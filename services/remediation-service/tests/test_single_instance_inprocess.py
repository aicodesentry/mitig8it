"""The two single-instance switches: an in-process worker loop and an in-process broker.

Together they let one container accept a repair request and drive it to a terminal state
with no separate worker process and no separate broker service. Both default to the
production arrangement, and the in-process broker still produces `development_unverified`
evidence that a policy without `allow_development_verification` refuses.
"""
from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src import main as main_module
from src import sandbox as sandbox_module
from src.agent import ProviderAction
from tests.conftest import whole_file_change
from src.digests import content_sha256
from src.fixtures import build_repair_request, fixture_regression_test, read_fixture, reference_replacements
from src.sandbox import (
    BrokerConfigurationError,
    HttpSandboxBroker,
    InProcessSandboxBroker,
    LocalSubprocessDriver,
    create_sandbox_broker,
    selected_broker_mode,
)
from src.verification import Verifier
from src.worker import inprocess_enabled

FIXTURE_DIR = Path(__file__).parents[3] / "benchmarks" / "remediation" / "fixtures" / "sql-parameterized"
TERMINAL_STATES = {"ready", "unsupported", "inconclusive", "failed", "cancelled"}


# --- SANDBOX_BROKER_MODE -----------------------------------------------------------


def test_broker_mode_defaults_to_the_attested_http_broker(monkeypatch):
    monkeypatch.delenv("SANDBOX_BROKER_MODE", raising=False)
    for name, value in {
        "SANDBOX_BROKER_URL": "https://sandbox-broker.internal",
        "SANDBOX_BROKER_TOKEN": "token",
        "SANDBOX_BROKER_ATTESTATION_SECRET": "secret",
        "SANDBOX_BROKER_ATTESTATION_KEY_ID": "key-1",
    }.items():
        monkeypatch.setenv(name, value)
    assert selected_broker_mode() == "http"
    assert isinstance(create_sandbox_broker(), HttpSandboxBroker)


def test_broker_mode_inprocess_selects_the_local_subprocess_driver(monkeypatch):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.delenv("SANDBOX_BROKER_URL", raising=False)
    broker = create_sandbox_broker()
    assert isinstance(broker, InProcessSandboxBroker)
    assert isinstance(broker.driver, LocalSubprocessDriver)
    assert broker.driver.verification_level == "development_unverified"


def test_an_unknown_broker_mode_fails_closed(monkeypatch):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "kubernetes")
    with pytest.raises(BrokerConfigurationError):
        create_sandbox_broker()


def test_inprocess_broker_warns_that_its_evidence_is_development_only(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    with caplog.at_level("WARNING", logger="mitig8it.remediation.sandbox"):
        create_sandbox_broker()
    assert sandbox_module.INPROCESS_BROKER_WARNING in caplog.text


@pytest.mark.asyncio
async def test_inprocess_broker_evidence_is_development_unverified_and_policy_gated(request_payload, source, monkeypatch):
    """The same evidence passes with `allow_development_verification` and is refused without it."""
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    import sys

    from src.models import RepairRequest
    from src.patches import build_patch_bundle
    from src.retrieval import Snapshot

    repaired = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"
    argv = {
        "exploit": [sys.executable, "-c", "import pathlib,sys; sys.exit(1 if '${id}' in pathlib.Path('src/db.ts').read_text() else 0)"],
        "behavior": [sys.executable, "-c", "import pathlib,sys; sys.exit(0 if 'loadUser' in pathlib.Path('src/db.ts').read_text() else 1)"],
    }
    checks = [{"check_id": kind, "kind": kind, "argv": command, "timeout_seconds": 60} for kind, command in argv.items()]

    def build(allow: bool):
        payload = dict(request_payload)
        # The snapshot is TypeScript, which node cannot load, so the fixture's policy checks are
        # the evidence here rather than a generated behavior test.
        payload["policy"] = {
            **request_payload["policy"],
            "sandbox_image_digest": None,
            "allow_development_verification": allow,
            "verification_checks": checks,
            "require_generated_regression_test": False,
        }
        parsed = RepairRequest.model_validate(payload)
        snapshot = Snapshot(parsed)
        from tests.conftest import whole_file_change

        bundle = build_patch_bundle(parsed, snapshot, [whole_file_change("src/db.ts", source, repaired)])
        return parsed, snapshot, bundle

    allowed = await Verifier(create_sandbox_broker()).verify(*build(True))
    assert allowed.status == "passed"
    assert allowed.verification_level == "development_unverified"

    refused = await Verifier(create_sandbox_broker()).verify(*build(False))
    assert refused.status != "passed"


# --- REMEDIATION_WORKER_INPROCESS --------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, False), ("", False), ("false", False), ("True", True), ("true", True)],
)
def test_worker_inprocess_switch_defaults_off(monkeypatch, value, expected):
    monkeypatch.delenv("REMEDIATION_WORKER_INPROCESS", raising=False)
    if value is not None:
        monkeypatch.setenv("REMEDIATION_WORKER_INPROCESS", value)
    assert inprocess_enabled() is expected


def _isolated_service(monkeypatch, tmp_path: Path, *, inprocess: bool) -> None:
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "dev-secret")
    monkeypatch.setenv("REMEDIATION_EXECUTION_BACKEND", "local")
    monkeypatch.setenv("REMEDIATION_LOCAL_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("REMEDIATION_WORKER_POLL_SECONDS", "0.1")
    monkeypatch.setenv("REMEDIATION_WORKER_INPROCESS", "true" if inprocess else "false")
    monkeypatch.setattr(main_module, "execution_backend", None, raising=False)


def test_lifespan_leaves_the_worker_loop_off_by_default(monkeypatch, tmp_path):
    _isolated_service(monkeypatch, tmp_path, inprocess=False)
    started: list[str] = []
    monkeypatch.setattr(main_module, "run_worker_loop", lambda backend: started.append("started") or asyncio.sleep(0))
    with TestClient(main_module.app) as client:
        assert client.get("/health").json()["status"] == "ok"
    assert started == []


def test_lifespan_starts_and_cancels_the_worker_loop_on_the_shared_backend(monkeypatch, tmp_path):
    _isolated_service(monkeypatch, tmp_path, inprocess=True)
    observed: dict[str, object] = {}

    async def fake_loop(backend):
        observed["backend"] = backend
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            observed["cancelled"] = True
            raise

    monkeypatch.setattr(main_module, "run_worker_loop", fake_loop)
    with TestClient(main_module.app) as client:
        client.get("/health")
        # The loop shares the process's backend instance, so the HTTP handlers and the
        # worker read and write one execution store.
        deadline = time.monotonic() + 5
        while "backend" not in observed and time.monotonic() < deadline:
            time.sleep(0.02)
        assert observed["backend"] is main_module.get_execution_backend()
    assert observed.get("cancelled") is True


# --- One container, end to end -----------------------------------------------------


class _ScriptedProvider:
    """The double used by tests/test_engine.py, scripted from the fixture's reviewed repair."""

    def __init__(self, actions):
        self.actions = list(actions)
        self.max_output_tokens = 4096
        self._index = 0

    async def next_action(self, messages, tools):
        if self._index >= len(self.actions):
            raise RuntimeError("scripted provider exhausted its script")
        action = self.actions[self._index]
        self._index += 1
        return action


class _ScriptedProviderFactory:
    """Stands in for `OpenAICompatibleProvider` so the engine builds its own default agent."""

    def __init__(self, actions):
        self.actions = actions

    def from_env(self, expected_model=None, **_kwargs):
        return _ScriptedProvider(self.actions)


@pytest.mark.skipif(shutil.which("node") is None, reason="the fixture's verification checks run under node")
def test_one_container_drives_a_posted_repair_to_a_terminal_state(monkeypatch, tmp_path):
    """No worker process, no broker service: intake, execution, and verification in one container."""
    _isolated_service(monkeypatch, tmp_path, inprocess=True)

    fixture = read_fixture(FIXTURE_DIR)
    request = build_repair_request(FIXTURE_DIR, fixture, versions={"repair_model": "scripted-double", "retriever": "v1", "verifier": "v1"})
    replacements = reference_replacements(FIXTURE_DIR, fixture)
    originals = {item.path: item.content for item in request.files}
    actions = [
        ProviderAction(
            "propose_patch",
            {
                "hypothesis": "Untrusted input is interpolated into a SQL string.",
                "intended_behavior": "Load the same rows for legitimate input.",
                "assumptions": ["the fixture's reference repair is the reviewed expected patch"],
                "citations": [{"path": path, "line_start": 1, "line_end": max(1, len(originals[path].splitlines()))} for path in replacements],
                "changes": [whole_file_change(path, originals[path], content) for path, content in replacements.items()],
                "regression_tests": [fixture_regression_test(fixture, finding.stable_id) for finding in request.findings],
            },
            input_tokens=8,
            output_tokens=8,
        ),
        ProviderAction("request_verification", {}, input_tokens=8, output_tokens=8),
    ]
    monkeypatch.setattr("src.engine.OpenAICompatibleProvider", _ScriptedProviderFactory(actions), raising=True)

    headers = {"x-internal-secret": "dev-secret", "Content-Type": "application/json"}
    with TestClient(main_module.app) as client:
        accepted = client.post("/v1/repair", json=request.model_dump(mode="json"), headers=headers)
        assert accepted.status_code == 202
        execution_id = accepted.json()["execution_id"]

        deadline = time.monotonic() + 120
        body = None
        while time.monotonic() < deadline:
            body = client.get(f"/v1/repair/{execution_id}", headers=headers).json()
            if body["state"] != "running":
                break
            time.sleep(0.25)

    assert body is not None and body["state"] in TERMINAL_STATES, body
    assert body["state"] == "ready", body
    candidate = body["result"]["candidates"][0]
    assert candidate["verification"]["status"] == "passed"
    # The in-process broker never claims the production isolation level.
    assert candidate["preview"]["evidence"]["verification_level"] == "development_unverified"
