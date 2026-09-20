#!/usr/bin/env python3
"""Run curated remediation fixtures without executing untrusted candidate code.

Only the checked-in original and reference-repaired fixture trees may be run by
the trusted Node assertions. Provider/HTTP candidates are never executed here;
they require the remediation service's signed sandbox evidence in a separate
environment before they can be called independently verified.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
SERVICE_ROOT = REPOSITORY_ROOT / "services" / "remediation-service"
FIXTURES = ROOT / "fixtures"
DEFAULT_BUDGET = {"max_tool_calls": 20, "max_attempts": 3, "max_input_tokens": 120000,
                  "max_output_tokens": 120000, "max_cost_usd": 2.0}
SUPPORTED_FAMILIES = {"sql_parameterization", "command_arguments", "path_containment"}
NEGATIVE_KINDS = {"negative", "adversarial"}


class FixtureError(ValueError):
    pass


@dataclass
class CaseResult:
    fixture_id: str
    repository_id: str
    split: str
    family: str
    kind: str
    expected_state: str
    observed_state: str
    outcome: str
    reason: str | None
    fixture_tests: dict[str, Any] | None
    usage: dict[str, Any]
    elapsed_ms: int
    verification_level: str | None = None
    limitations: list[str] | None = None


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resolve_fixture_path(fixture_dir: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise FixtureError("fixture path is unsafe")
    result = (fixture_dir / relative).resolve()
    if fixture_dir.resolve() not in result.parents:
        raise FixtureError("fixture path escapes its fixture")
    return result


def fixture_units(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Each affected file in the fixture with its own finding and reviewed repair.

    One unit is one finding in one file. A fixture with `additional_units` therefore carries
    several findings, which the engine groups into several connected components and repairs
    with one bounded agent loop each.
    """
    units = [{"source": fixture.get("source"), "reference_repair": fixture.get("reference_repair"), "finding": fixture.get("finding")}]
    for item in fixture.get("additional_units") or []:
        if not isinstance(item, dict):
            raise FixtureError(f"{fixture.get('id')}: additional unit is malformed")
        units.append({"source": item.get("source"), "reference_repair": item.get("reference_repair"), "finding": item.get("finding")})
    return units


def expected_patches(fixture_dir: Path, fixture: dict[str, Any]) -> dict[str, str]:
    """The complete reviewed repair the fixture expects, as a path to content mapping."""
    expected: dict[str, str] = {}
    for unit in fixture_units(fixture):
        if isinstance(unit["source"], str) and isinstance(unit["reference_repair"], str):
            expected[unit["source"]] = resolve_fixture_path(fixture_dir, unit["reference_repair"]).read_text(encoding="utf-8")
    return expected


def load_fixtures() -> list[tuple[Path, dict[str, Any]]]:
    fixtures: list[tuple[Path, dict[str, Any]]] = []
    for fixture_file in sorted(FIXTURES.glob("*/fixture.json")):
        try:
            metadata = json.loads(fixture_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise FixtureError(f"invalid JSON: {fixture_file}") from error
        validate_fixture(fixture_file.parent, metadata)
        fixtures.append((fixture_file.parent, metadata))
    if not fixtures:
        raise FixtureError("no remediation fixtures found")
    assert_no_repository_leakage(fixtures)
    return fixtures


def validate_fixture(fixture_dir: Path, fixture: dict[str, Any]) -> None:
    required = {"schema_version", "id", "repository_id", "split", "family", "kind", "expected_state", "budget"}
    missing = required - set(fixture)
    if fixture.get("schema_version") != "v1" or missing:
        raise FixtureError(f"{fixture_dir.name}: missing/unsupported fields: {sorted(missing)}")
    if fixture["split"] not in {"train", "validation", "holdout"}:
        raise FixtureError(f"{fixture['id']}: invalid split")
    if fixture["kind"] not in {"supported", *NEGATIVE_KINDS}:
        raise FixtureError(f"{fixture['id']}: invalid kind")
    if fixture["kind"] == "supported" and fixture["family"] not in SUPPORTED_FAMILIES:
        raise FixtureError(f"{fixture['id']}: unsupported seed family")
    if fixture["kind"] in NEGATIVE_KINDS and fixture["expected_state"] != "unsupported":
        raise FixtureError(f"{fixture['id']}: negative/adversarial cases must require abstention")
    validate_verification_checks(fixture)
    budget = fixture["budget"]
    if not isinstance(budget, dict) or any(not isinstance(budget.get(key), (int, float)) or budget[key] < 0 for key in DEFAULT_BUDGET):
        raise FixtureError(f"{fixture['id']}: fixed budget is invalid")
    if fixture["kind"] == "supported":
        seen: set[str] = set()
        for unit in fixture_units(fixture):
            source, expected = unit["source"], unit["reference_repair"]
            if not isinstance(source, str) or not isinstance(expected, str):
                raise FixtureError(f"{fixture['id']}: supported fixture requires source and reference_repair")
            if not resolve_fixture_path(fixture_dir, source).is_file() or not resolve_fixture_path(fixture_dir, expected).is_file():
                raise FixtureError(f"{fixture['id']}: source or reference repair is missing")
            if not isinstance(unit["finding"], dict):
                raise FixtureError(f"{fixture['id']}: every repair unit requires its own finding")
            if source in seen:
                raise FixtureError(f"{fixture['id']}: duplicate repair unit source: {source}")
            seen.add(source)
        test = fixture.get("trusted_fixture_test")
        if not isinstance(test, dict) or test.get("runtime") != "node" or not isinstance(test.get("path"), str):
            raise FixtureError(f"{fixture['id']}: trusted Node fixture test is required")
        if not resolve_fixture_path(fixture_dir, test["path"]).is_file():
            raise FixtureError(f"{fixture['id']}: trusted fixture test is missing")


def validate_verification_checks(fixture: dict[str, Any]) -> None:
    """Every fixture declares the fixed argv the sandbox runs and the outcome it expects."""
    checks = fixture.get("verification_checks")
    if not isinstance(checks, list) or len(checks) < 2:
        raise FixtureError(f"{fixture['id']}: verification_checks must declare at least an exploit and a behavior check")
    kinds: set[str] = set()
    identifiers: set[str] = set()
    for check in checks:
        required = {"check_id", "kind", "argv", "timeout_seconds", "expected_baseline", "expected_candidate"}
        if not isinstance(check, dict) or not required.issubset(check):
            raise FixtureError(f"{fixture['id']}: verification check is missing required fields")
        if check["kind"] not in {"existing_test", "typecheck", "build", "scanner", "exploit", "behavior"}:
            raise FixtureError(f"{fixture['id']}: unsupported verification check kind")
        if not isinstance(check["argv"], list) or not check["argv"] or any(not isinstance(part, str) or not part for part in check["argv"]):
            raise FixtureError(f"{fixture['id']}: verification check argv must be a non-empty string array")
        if check["expected_baseline"] not in {"passed", "failed", "inconclusive"} or check["expected_candidate"] not in {"passed", "failed", "inconclusive"}:
            raise FixtureError(f"{fixture['id']}: verification check expectations are invalid")
        if check["check_id"] in identifiers:
            raise FixtureError(f"{fixture['id']}: duplicate verification check id")
        identifiers.add(check["check_id"])
        kinds.add(check["kind"])
    if not {"exploit", "behavior"}.issubset(kinds):
        raise FixtureError(f"{fixture['id']}: an exploit and a behavior check are both required")
    if fixture["kind"] == "supported":
        exploit = next(check for check in checks if check["kind"] == "exploit")
        if exploit["expected_baseline"] != "failed":
            raise FixtureError(f"{fixture['id']}: a supported fixture's exploit check must fail on the baseline tree")


def assert_no_repository_leakage(fixtures: list[tuple[Path, dict[str, Any]]]) -> None:
    split_by_repository: dict[str, str] = {}
    ids: set[str] = set()
    for _, fixture in fixtures:
        if fixture["id"] in ids:
            raise FixtureError(f"duplicate fixture id: {fixture['id']}")
        ids.add(fixture["id"])
        previous = split_by_repository.setdefault(fixture["repository_id"], fixture["split"])
        if previous != fixture["split"]:
            raise FixtureError(f"repository leakage: {fixture['repository_id']} is in {previous} and {fixture['split']}")


def run_trusted_fixture_test(fixture_dir: Path, fixture: dict[str, Any]) -> dict[str, Any]:
    """Run only audited fixture source paths with a fixed Node argv, never shell."""
    test = fixture["trusted_fixture_test"]
    script = resolve_fixture_path(fixture_dir, test["path"])
    # One original/repaired pair per repair unit, in fixture order.
    pairs: list[str] = []
    for unit in fixture_units(fixture):
        pairs.append(str(resolve_fixture_path(fixture_dir, unit["source"])))
        pairs.append(str(resolve_fixture_path(fixture_dir, unit["reference_repair"])))
    try:
        completed = subprocess.run(
            ["node", str(script), *pairs],
            cwd=fixture_dir,
            env={"PATH": os.environ.get("PATH", ""), "NODE_OPTIONS": "--disable-proto=throw"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=int(test.get("timeout_seconds", 5)),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"passed": False, "reason": f"trusted_fixture_test_unavailable:{type(error).__name__}"}
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report = {"passed": False, "reason": "trusted_fixture_test_invalid_json"}
    report["exit_code"] = completed.returncode
    if completed.returncode != 0 or report.get("vulnerability_observed") is not True or report.get("behavior_preserved") is not True:
        report["passed"] = False
    else:
        report["passed"] = True
    return report


def reference_hunks(path: str, original: str, replacement: str) -> list[dict[str, Any]]:
    """The reviewed repair expressed as the line-range hunks `propose_patch` now takes.

    The reference repair is stored as a whole file, so the changed ranges are recovered with a
    diff. This replays exactly the reviewed patch while exercising the hunk path end to end.
    Each hunk quotes the lines it replaces, which is what the service checks: no caller, scripted
    or model, is asked to compute a digest.
    """
    original_lines = original.splitlines(keepends=True)
    replacement_lines = replacement.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=original_lines, b=replacement_lines, autojunk=False)
    hunks: list[dict[str, Any]] = []
    for tag, start_a, end_a, start_b, end_b in matcher.get_opcodes():
        if tag == "equal":
            continue
        # A pure insertion has no replaced lines, so it rewrites the line before it instead.
        start, end = (start_a, end_a) if end_a > start_a else (max(0, start_a - 1), start_a)
        replaced = "".join(original_lines[start:end])
        new_lines = original_lines[start:start_a] + replacement_lines[start_b:end_b]
        hunks.append(
            {
                "path": path,
                "start_line": start + 1,
                "end_line": end,
                "original_lines": replaced.splitlines(),
                "replacement_lines": "".join(new_lines).splitlines(),
            }
        )
    return hunks


def reference_adapter(fixture_dir: Path, fixture: dict[str, Any]) -> dict[str, Any]:
    """A zero-cost deterministic baseline, not a repair model or release result."""
    if fixture["expected_state"] == "unsupported":
        return {"state": "unsupported", "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}}
    return {
        "state": "ready",
        "candidates": [
            {"path": path, "replacement_content": content}
            for path, content in sorted(expected_patches(fixture_dir, fixture).items())
        ],
        "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        "evidence": {"kind": "trusted_fixture_reference_only"},
    }


class RemediationServiceClient:
    """Minimal authenticated client for the remediation service's repair contract.

    It is injectable so the adapter can be unit tested without a network listener.
    """

    def __init__(self, base_url: str, token: str, request_timeout_seconds: float = 30):
        if not base_url:
            raise FixtureError(
                "--adapter engine requires the service URL; set REMEDIATION_SERVICE_URL or pass --engine-url"
            )
        if not token:
            raise FixtureError("--adapter engine requires REMEDIATION_SERVICE_INTERNAL_SECRET")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.request_timeout_seconds = request_timeout_seconds

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=self.request_timeout_seconds) as response:
            return json.loads(response.read())

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/v1/repair", payload)

    def poll(self, execution_id: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/repair/{execution_id}")


def engine_request_payload(
    fixture_dir: Path,
    fixture: dict[str, Any],
    modules: dict[str, Any],
    *,
    allow_development_verification: bool,
    sandbox_image_digest: str | None,
) -> dict[str, Any]:
    """The same complete RepairRequest the in-process adapter builds, as JSON."""
    versions = {"benchmark": "fixture-development-v1", "retriever": "v1", "verifier": "v1"}
    model = os.environ.get("REPAIR_LLM_MODEL", "")
    if model:
        versions["repair_model"] = model
    request = modules["build_repair_request"](
        fixture_dir,
        fixture,
        job_id=f"benchmark-{fixture['id']}",
        versions=versions,
        allow_development_verification=allow_development_verification,
        sandbox_image_digest=sandbox_image_digest,
    )
    return request.model_dump(mode="json")


def engine_adapter(
    client: RemediationServiceClient,
    fixture_dir: Path,
    fixture: dict[str, Any],
    modules: dict[str, Any],
    *,
    poll_timeout_seconds: float = 300,
    poll_interval_seconds: float = 2,
    allow_development_verification: bool = False,
    sandbox_image_digest: str | None = None,
    sleep: Any = time.sleep,
) -> dict[str, Any]:
    """Submits the fixture to a deployed service and polls until the execution is terminal.

    Nothing the service returns is executed on this host. The returned evidence is graded
    exactly like the in-process adapters, at whatever verification level the service reports.
    """
    try:
        payload = engine_request_payload(
            fixture_dir,
            fixture,
            modules,
            allow_development_verification=allow_development_verification,
            sandbox_image_digest=sandbox_image_digest,
        )
    except Exception as error:  # noqa: BLE001 - a malformed fixture must not look like a repair.
        return {"state": "inconclusive", "reason": f"fixture_request_invalid:{type(error).__name__}", "usage": {}}
    try:
        accepted = client.submit(payload)
        execution_id = accepted.get("execution_id")
        if not isinstance(execution_id, str) or not execution_id:
            return {"state": "inconclusive", "reason": "engine_intake_returned_no_execution_id", "usage": {}}
        deadline = time.monotonic() + poll_timeout_seconds
        document: dict[str, Any] = {}
        while True:
            document = client.poll(execution_id)
            state = document.get("state")
            if state not in {"queued", "running"}:
                break
            if time.monotonic() >= deadline:
                return {"state": "inconclusive", "reason": "engine_poll_timeout", "usage": {}}
            sleep(poll_interval_seconds)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as error:
        return {"state": "inconclusive", "reason": f"engine_adapter_error:{type(error).__name__}", "usage": {}}
    return engine_result(document)


def engine_result(document: dict[str, Any]) -> dict[str, Any]:
    """Normalizes a terminal GET body into the shape the grader consumes."""
    state = document.get("state")
    if state in {"failed", "cancelled"}:
        return {"state": "inconclusive", "reason": f"engine_execution_{state}", "usage": {}}
    result = document.get("result")
    if not isinstance(result, dict):
        return {"state": "inconclusive", "reason": "engine_terminal_result_missing", "usage": {}}
    evidence = result.get("evidence") or {}
    usage = evidence.get("usage") or {}
    input_tokens = int(usage.get("input_tokens", 0) or 0)
    output_tokens = int(usage.get("output_tokens", 0) or 0)
    candidates = []
    for candidate in result.get("candidates") or []:
        for patch in candidate.get("patch") or []:
            candidates.append({"path": patch.get("path"), "replacement_content": patch.get("replacement_content")})
    return {
        "state": result.get("state", "inconclusive"),
        "candidates": candidates,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round((input_tokens + output_tokens) * 1.0 / 1_000_000, 8),
        },
        "verification_level": evidence.get("verification_level", "none"),
        "limitations": evidence.get("limitations", []),
        "evidence": {"kind": "remote_remediation_service", "manifest_digest": result.get("manifest_digest")},
        "reason": (result.get("reason") or {}).get("code"),
    }


LOCAL_ADAPTERS = {"engine-local", "engine-live"}
GRADED_ADAPTERS = LOCAL_ADAPTERS | {"engine"}
SCRIPTED_PROVIDER_KIND = "scripted-provider"
LIVE_PROVIDER_KIND = "live-provider"
REMOTE_PROVIDER_KIND = "unknown-remote-provider"
DEVELOPMENT_VERIFICATION_LEVEL = "development_unverified"
PRODUCTION_VERIFICATION_LEVEL = "independent_sandbox"
VERIFICATION_LEVELS = {DEVELOPMENT_VERIFICATION_LEVEL, PRODUCTION_VERIFICATION_LEVEL}
REMOTE_CONTRACT_NOTE = (
    "Results produced against a deployed service are graded at the verification level that "
    "service reported. This harness cannot observe which provider the service used, so "
    "repair quality is claimed only when --remote-provider live-provider is declared and the "
    "service returned the production verification level."
)
PIPELINE_INTEGRITY_NOTE = (
    "Results produced with the scripted provider and the local development sandbox measure "
    "pipeline integrity, not repair quality: the patch is replayed from the fixture and the "
    "verification level is development_unverified."
)
REPAIR_QUALITY_NOTE = (
    "Results produced with a live provider still ran in the local development sandbox, so the "
    "verification level is development_unverified and no production isolation claim is made."
)


def load_service_modules() -> dict[str, Any]:
    """Imports the remediation service in-process. No HTTP, no cloud services, no GitHub."""
    if str(SERVICE_ROOT) not in sys.path:
        sys.path.insert(0, str(SERVICE_ROOT))
    from src.agent import ProviderAction, RepairAgent  # noqa: PLC0415 - optional adapter import.
    from src.agent.provider import OpenAICompatibleProvider, ProviderError  # noqa: PLC0415
    from src.digests import content_sha256  # noqa: PLC0415
    from src.engine import RepairEngine  # noqa: PLC0415
    from src.executions import LocalExecutionBackend, create_checkpoint_store  # noqa: PLC0415
    from src.fixtures import (  # noqa: PLC0415
        build_repair_request,
        fixture_regression_test,
        reference_replacement,
        reference_replacements,
    )
    from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver  # noqa: PLC0415
    from src.verification import Verifier  # noqa: PLC0415

    return {
        "ProviderAction": ProviderAction,
        "RepairAgent": RepairAgent,
        "OpenAICompatibleProvider": OpenAICompatibleProvider,
        "ProviderError": ProviderError,
        "content_sha256": content_sha256,
        "RepairEngine": RepairEngine,
        "LocalExecutionBackend": LocalExecutionBackend,
        "create_checkpoint_store": create_checkpoint_store,
        "build_repair_request": build_repair_request,
        "fixture_regression_test": fixture_regression_test,
        "reference_replacement": reference_replacement,
        "reference_replacements": reference_replacements,
        "InProcessSandboxBroker": InProcessSandboxBroker,
        "LocalSubprocessDriver": LocalSubprocessDriver,
        "Verifier": Verifier,
    }


class ScriptedFixtureProvider:
    """A deterministic, free provider double. It is not a model and proves no repair quality.

    One instance drives one finding group's bounded agent loop. It reads each of the group's
    affected files once, replays their reviewed reference repairs as a single `propose_patch`
    carrying a generated regression test, and requests verification. A group with no reviewed
    repair abstains. Every graded outcome therefore reflects the service pipeline: intake,
    grouping, patch policy, generated-test policy, sandbox execution, evidence validation, and
    batch assembly.
    """

    def __init__(self, modules: dict[str, Any], fixture: dict[str, Any], units: list[dict[str, Any]]):
        action = modules["ProviderAction"]
        repairable = [unit for unit in units if isinstance(unit.get("replacement"), str)]
        if not repairable:
            self.actions = [
                action(
                    "abstain",
                    {"reason_code": "fixture_requires_abstention", "explanation": fixture.get("reason", "No reliable bounded repair is available.")},
                    input_tokens=8,
                    output_tokens=8,
                )
            ]
        else:
            self.actions = [
                action("read_file", {"path": unit["path"], "line_start": 1, "line_end": 200}, input_tokens=8, output_tokens=8)
                for unit in repairable
            ]
            self.actions.append(
                action(
                    "propose_patch",
                    {
                        "hypothesis": (
                            f"The {fixture['family']} finding is reachable from untrusted input in "
                            + ", ".join(unit["path"] for unit in repairable)
                            + "."
                        ),
                        "intended_behavior": "Preserve the documented behavior for legitimate input.",
                        "assumptions": ["the fixture's reference repair is the reviewed expected patch"],
                        "citations": [
                            {"path": unit["path"], "line_start": 1, "line_end": max(1, len(unit["original"].splitlines()))}
                            for unit in repairable
                        ],
                        "changes": [
                            hunk
                            for unit in repairable
                            for hunk in reference_hunks(unit["path"], unit["original"], unit["replacement"])
                        ],
                        # One reproducer per finding group, so a multi-group fixture proposes a
                        # distinct generated test per candidate and the combined tree runs both.
                        "regression_test": modules["fixture_regression_test"](
                            fixture, suffix=f"-{repairable[0]['path'].replace('/', '-')}"
                        ),
                    },
                    input_tokens=8,
                    output_tokens=8,
                )
            )
            self.actions.append(action("request_verification", {}, input_tokens=8, output_tokens=8))
        self._index = 0

    async def next_action(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any:
        if self._index >= len(self.actions):
            raise RuntimeError("scripted provider exhausted its script")
        action = self.actions[self._index]
        self._index += 1
        return action


def live_provider_settings() -> dict[str, str]:
    settings = {
        "base_url": os.environ.get("REPAIR_LLM_BASE_URL", ""),
        "api_key": os.environ.get("REPAIR_LLM_API_KEY", ""),
        "model": os.environ.get("REPAIR_LLM_MODEL", ""),
    }
    missing = sorted(f"REPAIR_LLM_{name.upper()}" for name, value in settings.items() if not value)
    if missing:
        raise FixtureError(
            "--adapter engine-live requires a configured real provider; set " + ", ".join(missing)
        )
    return settings


def engine_local_adapter(
    fixture_dir: Path,
    fixture: dict[str, Any],
    modules: dict[str, Any],
    state_dir: Path,
    provider_kind: str,
) -> dict[str, Any]:
    """Runs the real engine in-process against the local backend and local sandbox driver."""
    import asyncio  # noqa: PLC0415 - only the local adapters need an event loop.

    versions = {"benchmark": "fixture-development-v1", "retriever": "v1", "verifier": "v1"}
    if provider_kind == LIVE_PROVIDER_KIND:
        versions["repair_model"] = live_provider_settings()["model"]
    try:
        request = modules["build_repair_request"](fixture_dir, fixture, versions=versions)
        replacements = modules["reference_replacements"](fixture_dir, fixture)
    except Exception as error:  # noqa: BLE001 - a malformed fixture must not look like a repair.
        return {"state": "inconclusive", "reason": f"fixture_request_invalid:{type(error).__name__}", "usage": {}}

    originals = {item.path: item.content for item in request.files}

    def agent_factory(prepared: Any) -> Any:
        """One agent per connected finding group; the engine calls this once per group."""
        broker = modules["InProcessSandboxBroker"](modules["LocalSubprocessDriver"]())
        verifier = modules["Verifier"](broker)
        if provider_kind == LIVE_PROVIDER_KIND:
            settings = live_provider_settings()
            provider = modules["OpenAICompatibleProvider"](
                base_url=settings["base_url"], api_key=settings["api_key"], model=settings["model"]
            )
        else:
            paths: list[str] = []
            for finding in prepared.findings:
                if finding.affected_path and finding.affected_path not in paths:
                    paths.append(finding.affected_path)
            units = [
                {"path": path, "original": originals.get(path, ""), "replacement": replacements.get(path)}
                for path in paths
            ]
            provider = ScriptedFixtureProvider(modules, fixture, units)
        return modules["RepairAgent"](provider, verifier, None)

    backend = modules["LocalExecutionBackend"](state_dir / fixture["id"])
    worker_id = f"benchmark-{fixture['id']}"
    backend.enqueue(request)
    claimed = backend.claim(worker_id, lease_seconds=900)
    if claimed is None:
        return {"state": "inconclusive", "reason": "local_execution_not_claimable", "usage": {}}
    stored = backend.read_request(claimed)
    checkpoints = modules["create_checkpoint_store"](backend, claimed.execution_id, worker_id, stored)
    response = asyncio.run(modules["RepairEngine"](agent_factory).repair(stored, checkpoints))
    if not backend.complete(claimed.execution_id, worker_id, response):
        return {"state": "inconclusive", "reason": "local_execution_result_not_published", "usage": {}}
    record = backend.get(claimed.execution_id)
    persisted = backend.read_result(record)

    evidence = persisted.evidence or {}
    usage = evidence.get("usage") or {}
    tokens = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    return {
        "state": persisted.state,
        "candidates": [
            {"path": patch.path, "replacement_content": patch.replacement_content}
            for candidate in persisted.candidates
            for patch in candidate.patch
        ],
        "usage": {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
            "cost_usd": round(tokens * 1.0 / 1_000_000, 8),
        },
        "verification_level": evidence.get("verification_level", "none"),
        "limitations": evidence.get("limitations", []),
        "evidence": {"kind": "local_development_sandbox", "manifest_digest": persisted.manifest_digest},
        "reason": (persisted.reason or {}).get("code"),
    }


def remote_results_kind(levels: list[str], provider_kind: str) -> str:
    """Labels a deployed-service report by the verification level the service reported.

    The production level alone is not a repair-quality claim: the patch may still have been
    replayed by a scripted provider, which this harness cannot observe from outside.
    """
    observed = {level for level in levels if level in VERIFICATION_LEVELS}
    if not observed or observed == {DEVELOPMENT_VERIFICATION_LEVEL}:
        return "pipeline_integrity"
    if PRODUCTION_VERIFICATION_LEVEL in observed and provider_kind == LIVE_PROVIDER_KIND:
        return "repair_quality"
    return "unverified_contract_smoke"


def budget_ok(result: dict[str, Any], budget: dict[str, Any]) -> bool:
    usage = result.get("usage") or {}
    limits = {"input_tokens": "max_input_tokens", "output_tokens": "max_output_tokens", "cost_usd": "max_cost_usd"}
    return all(not isinstance(usage.get(actual), (int, float)) or usage[actual] <= budget[limit] for actual, limit in limits.items())


def matches_reference_patch(fixture_dir: Path, fixture: dict[str, Any], result: dict[str, Any]) -> bool:
    """True when the union of the returned patches is exactly the reviewed repair.

    A multi-file fixture produces one candidate per finding group, so the comparison is over
    the union of every candidate's patches rather than over a single candidate. A patch for a
    file the fixture did not expect fails the comparison instead of being ignored.
    """
    candidates = result.get("candidates")
    if not isinstance(candidates, list) or not candidates or any(not isinstance(item, dict) for item in candidates):
        return False
    produced: dict[str, str] = {}
    for candidate in candidates:
        path, replacement = candidate.get("path"), candidate.get("replacement_content")
        if not isinstance(path, str) or not isinstance(replacement, str) or path in produced:
            return False
        produced[path] = replacement
    return produced == expected_patches(fixture_dir, fixture)


def evaluate_fixture(
    fixture_dir: Path,
    fixture: dict[str, Any],
    adapter: str,
    engine: dict[str, Any] | None,
    local: dict[str, Any] | None = None,
) -> CaseResult:
    started = time.monotonic()
    fixture_tests = run_trusted_fixture_test(fixture_dir, fixture) if fixture["kind"] == "supported" else None
    if adapter == "reference":
        result = reference_adapter(fixture_dir, fixture)
    elif adapter in LOCAL_ADAPTERS:
        result = engine_local_adapter(fixture_dir, fixture, local["modules"], local["state_dir"], local["provider_kind"])
    else:
        result = engine_adapter(
            engine["client"],
            fixture_dir,
            fixture,
            engine["modules"],
            poll_timeout_seconds=engine["poll_timeout_seconds"],
            allow_development_verification=engine["allow_development_verification"],
            sandbox_image_digest=engine["sandbox_image_digest"],
        )
    state = result.get("state", "inconclusive")
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    reason = result.get("reason")
    level = result.get("verification_level")
    if not budget_ok(result, fixture["budget"]):
        outcome, reason = "failed", "fixed_budget_exceeded"
    elif fixture["kind"] in NEGATIVE_KINDS:
        outcome = "passed" if state == "unsupported" else "failed"
        reason = reason or (None if outcome == "passed" else "unsafe_or_missing_abstention")
    elif adapter in GRADED_ADAPTERS:
        # A local adapter always runs in the development sandbox, so anything other than
        # development_unverified would be a mislabelled result. A deployed service may report
        # either level, and the level it reports is what the report is labelled with.
        permitted = {DEVELOPMENT_VERIFICATION_LEVEL} if adapter in LOCAL_ADAPTERS else VERIFICATION_LEVELS
        if state != "ready":
            outcome, reason = "failed", reason or "no_verified_candidate"
        elif level not in permitted:
            outcome, reason = "failed", f"unexpected_verification_level:{level}"
        elif not (fixture_tests and fixture_tests.get("passed")):
            outcome, reason = "failed", "trusted_fixture_reference_check_failed"
        elif not matches_reference_patch(fixture_dir, fixture, result):
            outcome, reason = "failed", "candidate_does_not_match_reference_patch"
        else:
            outcome = "passed"
    elif fixture_tests and fixture_tests.get("passed") and state == "ready" and matches_reference_patch(fixture_dir, fixture, result):
        outcome = "passed"
    else:
        outcome, reason = "failed", reason or "fixture_reference_patch_or_verification_failed"
    return CaseResult(fixture["id"], fixture["repository_id"], fixture["split"], fixture["family"], fixture["kind"],
                      fixture["expected_state"], state, outcome, reason, fixture_tests, usage,
                      round((time.monotonic() - started) * 1000), level, list(result.get("limitations") or []))


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float | None]:
    if total == 0:
        return [None, None]
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total) / denominator
    return [round(max(0, centre - margin), 4), round(min(1, centre + margin), 4)]


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    positives = [result for result in results if result.kind == "supported"]
    negatives = [result for result in results if result.kind in NEGATIVE_KINDS]
    verified = [result for result in positives if result.observed_state == "ready"]
    correct = [result for result in positives if result.outcome == "passed"]
    abstentions = [result for result in negatives if result.outcome == "passed"]
    costs = sum(float(result.usage.get("cost_usd", 0) or 0) for result in results)
    precision = len(correct) / len(verified) if verified else None
    coverage = len(correct) / len(positives) if positives else None
    safe_abstention = len(abstentions) / len(negatives) if negatives else None
    return {
        "total_cases": len(results), "eligible_supported_cases": len(positives), "negative_adversarial_cases": len(negatives),
        "verified_repairs": len(verified), "independently_correct_repairs": len(correct), "abstentions": len(abstentions),
        "precision": precision, "precision_wilson_95": wilson_interval(len(correct), len(verified)),
        "coverage": coverage, "coverage_wilson_95": wilson_interval(len(correct), len(positives)),
        "safe_abstention": safe_abstention, "safe_abstention_wilson_95": wilson_interval(len(abstentions), len(negatives)),
        "failures": [result.fixture_id for result in results if result.outcome == "failed"],
        "inconclusive": [result.fixture_id for result in results if result.outcome == "inconclusive"],
        "total_cost_usd": round(costs, 6), "cost_per_attempt_usd": round(costs / len(results), 6) if results else 0,
    }


def release_gate(fixtures: list[tuple[Path, dict[str, Any]]], results: list[CaseResult]) -> dict[str, Any]:
    manifest = json.loads((ROOT / "release-manifest.json").read_text(encoding="utf-8"))
    reasons: list[str] = []
    if len(fixtures) < manifest["minimum_cases"]:
        reasons.append(f"minimum_cases_not_met:{len(fixtures)}/{manifest['minimum_cases']}")
    kinds = {kind: sum(1 for _, fixture in fixtures if fixture["kind"] == kind) for kind in ("supported", "negative", "adversarial")}
    if kinds["negative"] < manifest["minimum_negative_cases"] or kinds["adversarial"] < manifest["minimum_adversarial_cases"]:
        reasons.append("minimum_negative_and_adversarial_cases_not_met")
    for family in SUPPORTED_FAMILIES:
        if sum(1 for _, fixture in fixtures if fixture["family"] == family and fixture["kind"] == "supported") < manifest["minimum_supported_cases_per_family"]:
            reasons.append(f"minimum_family_cases_not_met:{family}")
    review_file = ROOT / manifest["review_signatures_file"]
    if not review_file.is_file():
        reasons.append("external_review_signatures_missing")
    else:
        try:
            reviews = json.loads(review_file.read_text(encoding="utf-8"))
            expected_ids = {fixture["id"] for _, fixture in fixtures}
            signed_ids = set()
            for review in reviews.get("reviews", []):
                if (review.get("algorithm") != manifest["required_signature_algorithm"]
                    or not isinstance(review.get("fixture_id"), str)
                    or not isinstance(review.get("reviewer_id"), str)
                    or not isinstance(review.get("key_id"), str)
                    or not isinstance(review.get("signature"), str)
                    or len(review["signature"]) < 32):
                    raise ValueError("invalid review record")
                signed_ids.add(review["fixture_id"])
            if not expected_ids.issubset(signed_ids):
                reasons.append("external_review_signatures_incomplete")
            # Parsing a signature is not authentication. This seed has no
            # configured trust root/Ed25519 verifier, so it stays non-promotable.
            reasons.append("external_review_signature_cryptographic_verifier_not_configured")
        except (OSError, ValueError, json.JSONDecodeError, AttributeError):
            reasons.append("external_review_signatures_invalid")
    if any(result.outcome != "passed" for result in results):
        reasons.append("fixture_results_not_all_passed")
    return {"passed": False, "reasons": reasons or ["release_signature_verification_not_configured"],
            "manifest_digest": canonical_digest(manifest), "manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline remediation evaluation harness")
    parser.add_argument("--suite", choices=["seed", "release"], default="seed")
    parser.add_argument("--split", choices=["train", "validation", "holdout"])
    parser.add_argument("--adapter", choices=["reference", "engine", "engine-local", "engine-live"], default="reference")
    parser.add_argument("--engine-url", help="Deployed remediation service base URL; defaults to REMEDIATION_SERVICE_URL")
    parser.add_argument("--allow-network", action="store_true", help="Required with --adapter engine")
    parser.add_argument("--engine-poll-timeout-seconds", type=float, default=300,
                        help="Bound on how long --adapter engine polls one execution before giving up")
    parser.add_argument("--engine-allow-development-verification", action="store_true",
                        help="Accept development_unverified evidence from the deployed service; needed for the local compose stack")
    parser.add_argument("--engine-sandbox-image-digest",
                        help="Digest-pinned runner image the deployed service must verify with (registry/image@sha256:...)")
    parser.add_argument("--remote-provider", choices=["unknown", "live-provider"], default="unknown",
                        help="Declare that the deployed service runs a real evaluated model. This harness cannot verify it.")
    parser.add_argument("--state-dir", type=Path, help="Local execution backend directory for the in-process adapters")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    engine_url = args.engine_url or os.environ.get("REMEDIATION_SERVICE_URL", "")
    if args.adapter == "engine" and not args.allow_network:
        parser.error("--adapter engine requires --allow-network; no network calls are implicit")
    if args.adapter == "engine" and not engine_url:
        parser.error("--adapter engine requires REMEDIATION_SERVICE_URL or --engine-url")
    fixtures = load_fixtures()
    if args.split:
        fixtures = [(directory, fixture) for directory, fixture in fixtures if fixture["split"] == args.split]
    engine: dict[str, Any] | None = None
    if args.adapter == "engine":
        try:
            client = RemediationServiceClient(engine_url, os.environ.get("REMEDIATION_SERVICE_INTERNAL_SECRET", ""))
        except FixtureError as error:
            parser.error(str(error))
        engine = {
            "client": client,
            "modules": load_service_modules(),
            "poll_timeout_seconds": args.engine_poll_timeout_seconds,
            "allow_development_verification": args.engine_allow_development_verification,
            "sandbox_image_digest": args.engine_sandbox_image_digest,
        }
    local: dict[str, Any] | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    provider_kind = "none"
    if args.adapter == "engine":
        provider_kind = LIVE_PROVIDER_KIND if args.remote_provider == "live-provider" else REMOTE_PROVIDER_KIND
    if args.adapter in LOCAL_ADAPTERS:
        provider_kind = LIVE_PROVIDER_KIND if args.adapter == "engine-live" else SCRIPTED_PROVIDER_KIND
        if args.adapter == "engine-live":
            try:
                live_provider_settings()
            except FixtureError as error:
                parser.error(str(error))
        if args.state_dir:
            state_dir = args.state_dir
        else:
            temporary = tempfile.TemporaryDirectory(prefix="mitig8it-remediation-local-")
            state_dir = Path(temporary.name)
        local = {"modules": load_service_modules(), "state_dir": state_dir, "provider_kind": provider_kind}
    try:
        results = [evaluate_fixture(directory, fixture, args.adapter, engine, local) for directory, fixture in fixtures]
    finally:
        if temporary is not None:
            temporary.cleanup()
    verification_levels = sorted({result.verification_level for result in results if result.verification_level})
    report: dict[str, Any] = {
        "schema_version": "v1",
        "suite": args.suite,
        "adapter": args.adapter,
        "provider_kind": provider_kind,
        "verification_levels": verification_levels or ["none"],
        "results_kind": "pipeline_integrity" if args.adapter in {"engine-local", "reference"} else "unverified_contract_smoke",
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }
    if args.adapter == "engine-local":
        report["note"] = PIPELINE_INTEGRITY_NOTE
    elif args.adapter == "engine-live":
        report["results_kind"] = "development_verified_repair_attempt"
        report["note"] = REPAIR_QUALITY_NOTE
    elif args.adapter == "engine":
        report["results_kind"] = remote_results_kind(verification_levels, provider_kind)
        report["note"] = REMOTE_CONTRACT_NOTE
    if args.suite == "release":
        report["release_gate"] = release_gate(fixtures, results)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if args.suite == "seed" or report["release_gate"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
