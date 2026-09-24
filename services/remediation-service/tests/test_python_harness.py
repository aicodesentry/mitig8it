"""The service-supplied Python sandbox harness and the Python patch policy.

The harness fakes flask, the database drivers, subprocess, os.environ, and open(), records every
call, and is materialized into both sandbox workspaces beside the Python tests. These tests cover
the unit spec under plain python3, the check derivation and materialization path, the manifest
boundary, and the Python-specific patch policy (dependencies, syntax, load check, notes).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import (
    PatchPolicyError,
    build_generated_tests,
    build_patch_bundle,
    environment_notes,
    python_declared_dependencies,
    python_module_specifiers,
    PYTHON_STDLIB_MODULES,
    _reject_missing_python_dependencies,
)
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.sandbox.harness import (
    HARNESS_PATH,
    MAX_PYTHON_HARNESS_BYTES,
    PYTHON_HARNESS_MODULES,
    PYTHON_HARNESS_OCCUPIED_LIMITATION,
    PYTHON_HARNESS_PATH,
    PYTHON_HARNESS_SOURCE_FILE,
    is_harness_path,
    python_harness_modules,
    python_harness_source,
)
from src.sandbox.runner import materialize_tree
from src.verification import Verifier
from src.verification.checks import build_effective_checks, generated_snapshot_entries
from tests.conftest import git_blob, whole_file_change

requires_python = pytest.mark.skipif(shutil.which("python3") is None, reason="the Python harness runs under python3")
TESTS_DIR = Path(__file__).parent

APP_PATH = "app/client.py"
TEST_PATH = ".mitig8it/regression/finding-secret.test.py"
APP_SOURCE = '"""Billing client."""\n\nAPI_KEY = "sk-live-aaaaaaaaaaaaaaaa"\n\n\ndef auth_headers():\n    return {"Authorization": "Bearer " + API_KEY}\n'
APP_REPAIRED = APP_SOURCE.replace('\nAPI_KEY = "sk-live-aaaaaaaaaaaaaaaa"', '\nimport os\n\nAPI_KEY = os.environ["API_KEY"]')
HARNESS_TEST = (
    "import harness as h\n"
    "\n"
    "\n"
    "def body():\n"
    f'    m = h.load("{APP_PATH}", env={{"API_KEY": "from-env"}})\n'
    '    h.assert_equal(m.API_KEY, "from-env")\n'
    '    h.assert_env_read("API_KEY")\n'
    '    h.assert_not_in_source(m, "sk-live-")\n'
    "\n"
    "\n"
    "h.run(body)\n"
)


def _payload(request_payload, *, extra_files=(), source=APP_SOURCE):
    files = [(APP_PATH, source), *extra_files]
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content)) for path, content in files]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": content, "sha": git_blob(content)} for path, content in files]
    payload["findings"] = [
        {"snapshot_id": "finding-secret", "rule_id": "secret.hardcoded.credential", "cwe_id": "CWE-798", "file_path": APP_PATH, "line_start": 3, "line_end": 3}
    ]
    payload["policy"] = {**request_payload["policy"], "sandbox_image_digest": None, "allow_development_verification": True, "verification_checks": []}
    return payload


def _spec(content=HARNESS_TEST, path=TEST_PATH, finding_id="finding-secret"):
    return {"finding_id": finding_id, "path": path, "content": content}


def _bundle(request, snapshot, test=None, replacement=APP_REPAIRED):
    return build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, replacement)], [test or _spec()])


@requires_python
def test_python_harness_unit_spec_passes_under_plain_python():
    completed = subprocess.run(
        [sys.executable, str(TESTS_DIR / "python_harness_spec.py")],
        cwd=TESTS_DIR.parent,
        env={"PATH": os.environ.get("PATH", ""), "MITIG8IT_PYTHON_HARNESS_SOURCE": str(PYTHON_HARNESS_SOURCE_FILE), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    assert "OK" in completed.stderr


def test_python_harness_source_is_bounded_and_standard_library_only():
    source = python_harness_source()
    assert len(source.encode("utf-8")) <= MAX_PYTHON_HARNESS_BYTES
    assert source == PYTHON_HARNESS_SOURCE_FILE.read_text(encoding="utf-8")
    for specifier in python_module_specifiers(source):
        assert specifier.split(".")[0] in PYTHON_STDLIB_MODULES, specifier
    assert is_harness_path(PYTHON_HARNESS_PATH) and is_harness_path(HARNESS_PATH)
    assert "python3 .mitig8it/harness.py" in source


class _CapturingDriver(LocalSubprocessDriver):
    def __init__(self, workspace_root):
        super().__init__(str(workspace_root))
        self.payloads = []

    def execute(self, payload, deadline_seconds):
        self.payloads.append(payload)
        return super().execute(payload, deadline_seconds)


@requires_python
@pytest.mark.asyncio
async def test_python_harness_is_materialized_in_both_trees_and_kept_out_of_the_manifest(tmp_path, request_payload):
    request = RepairRequest.model_validate(_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = _bundle(request, snapshot)
    driver = _CapturingDriver(tmp_path / "workspaces")
    result = await Verifier(InProcessSandboxBroker(driver)).verify(request, snapshot, bundle)

    assert result.status == "passed", (result.reason_code, result.limitations)
    assert result.proven_finding_ids == ["finding-secret"]
    [payload] = driver.payloads
    paths = [entry["path"] for entry in payload["snapshot"]]
    assert paths.count(PYTHON_HARNESS_PATH) == 1 and TEST_PATH in paths and HARNESS_PATH not in paths
    for variant in ("baseline", "candidate"):
        root = tmp_path / variant
        materialize_tree(root, payload, variant)
        assert (root / PYTHON_HARNESS_PATH).read_text(encoding="utf-8") == python_harness_source()
        assert (root / TEST_PATH).read_text(encoding="utf-8") == HARNESS_TEST
    assert (tmp_path / "baseline" / APP_PATH).read_text() == APP_SOURCE
    assert (tmp_path / "candidate" / APP_PATH).read_text() == APP_REPAIRED
    assert [patch["path"] for patch in payload["patches"]] == [APP_PATH]
    assert [entry["path"] for entry in bundle.file_manifest] == [APP_PATH]
    assert [entry["path"] for entry in bundle.generated_test_manifest] == [TEST_PATH]
    effective = build_effective_checks(request, snapshot, bundle)
    assert [check.argv for check in effective.checks] == [
        ["python3", PYTHON_HARNESS_PATH, TEST_PATH],
        ["python3", "-m", "py_compile", APP_PATH],
    ]
    assert [check.kind for check in effective.checks] == ["exploit", "typecheck"]
    assert [entry["path"] for entry in effective.harness_files] == [PYTHON_HARNESS_PATH]
    assert generated_snapshot_entries(snapshot, effective)[-1]["path"] == PYTHON_HARNESS_PATH
    checks = {item["check_id"]: item for item in result.evidence["checks"]}
    assert checks["generated_regression_test"]["baseline"]["status"] == "failed"
    assert checks["generated_regression_test"]["candidate"]["status"] == "passed"
    assert checks["generated_python_syntax"]["baseline"]["status"] == "passed"


def test_a_repository_that_occupies_the_python_harness_path_keeps_its_file_and_gets_a_limitation(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload, extra_files=[(PYTHON_HARNESS_PATH, "# theirs\n")]))
    snapshot = Snapshot(request)
    bundle = _bundle(request, snapshot)
    effective = build_effective_checks(request, snapshot, bundle)
    assert effective.harness_files == ()
    assert PYTHON_HARNESS_OCCUPIED_LIMITATION in effective.limitations
    entries = generated_snapshot_entries(snapshot, effective)
    assert [entry["content"] for entry in entries if entry["path"] == PYTHON_HARNESS_PATH] == ["# theirs\n"]


def test_patch_policy_rejects_a_proposal_that_writes_the_python_harness(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload, extra_files=[(PYTHON_HARNESS_PATH, "# theirs\n")]))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="harness_path_protected"):
        build_patch_bundle(request, snapshot, [whole_file_change(PYTHON_HARNESS_PATH, "# theirs\n", "# mine\n")])
    with pytest.raises(PatchPolicyError, match="harness_path_protected"):
        build_generated_tests(request, snapshot, [_spec(path=PYTHON_HARNESS_PATH)])


def test_patch_policy_rejects_a_python_test_that_imports_a_package_and_names_the_harness(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload, extra_files=[("requirements.txt", "requests==2.32.0\nFlask>=3\n")]))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError) as error:
        build_generated_tests(request, snapshot, [_spec("import requests\nrequests.get('http://x')\n")])
    assert error.value.code == "missing_dependency:requests"
    assert "import harness as h" in error.value.guidance and PYTHON_HARNESS_PATH in error.value.guidance
    # Standard library, the harness, and repository modules are always importable.
    tests, _ = build_generated_tests(request, snapshot, [_spec("import json\nimport harness as h\nfrom app import client\n")])
    assert [test.path for test in tests] == [TEST_PATH]
    # An application file may import what the requirements declare, and nothing else.
    assert python_declared_dependencies(snapshot) == {"requests", "flask"}
    build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, "import flask\n" + APP_SOURCE)], [])
    with pytest.raises(PatchPolicyError, match="missing_dependency:boto3"):
        build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, "import boto3\n" + APP_SOURCE)], [])


# The shape the service writes for a Python SQL finding whose repaired function takes a cursor:
# the driver is imported so the proof can hand that driver's own cursor to the function and
# assert on that driver's placeholder syntax. `psycopg` binds `%s`, `sqlite3` binds `?`, so the
# proof cannot state what it exercises without naming the driver.
SQL_APP_PATH = "app/tickets.py"
SQL_APP_SOURCE = (
    '"""Ticket search."""\n'
    "import psycopg\n"
    "\n"
    "\n"
    "def find_tickets(cursor, status):\n"
    "    cursor.execute(\"SELECT id FROM tickets WHERE status = '%s'\" % status)\n"
    "    return cursor.fetchall()\n"
)
PSYCOPG_PROOF = (
    "import harness as h\n"
    "\n"
    "\n"
    "def body():\n"
    f'    m = h.load("{SQL_APP_PATH}")\n'
    "    import psycopg\n"
    "    cursor = psycopg.connect('').cursor()\n"
    "    payload = \"1' OR '1'='1\"\n"
    "    h.call(m.find_tickets, cursor, payload)\n"
    "    h.assert_true(h.db.queries, 'expected one query to be executed')\n"
    "    h.assert_param(h.db.queries[0], payload)\n"
    "\n"
    "\n"
    "h.run(body)\n"
)


def test_the_harness_module_exemption_matches_the_harness_fake_table():
    """The exempted names are the ones the harness actually installs, read from its source."""
    assert PYTHON_HARNESS_MODULES == python_harness_modules()
    assert "psycopg" in PYTHON_HARNESS_MODULES and "requests" not in PYTHON_HARNESS_MODULES


def test_a_generated_python_test_may_import_a_driver_the_harness_fakes(request_payload):
    """The service used to reject the coverage proof it had just written for itself.

    The Python harness installs recorded fakes for its drivers into `sys.modules` before it
    loads the module under test, so `import psycopg` in a proof resolves in a sandbox where
    nothing is installed. The generated-test check did not know that: it ran with
    `allow_declared=False`, found no standard-library, snapshot, or harness module of that
    name, and raised `missing_dependency:psycopg`. The template pass and then every agent patch
    were refused, so no candidate was ever proposed for such a finding.
    """
    request = RepairRequest.model_validate(
        _payload(request_payload, extra_files=[(SQL_APP_PATH, SQL_APP_SOURCE), ("requirements.txt", "psycopg==3.2.10\n")])
    )
    snapshot = Snapshot(request)

    # The old behaviour, still reachable by asking for it: the proof is refused.
    with pytest.raises(PatchPolicyError) as rejected:
        _reject_missing_python_dependencies(
            TEST_PATH, "", PSYCOPG_PROOF, snapshot, allow_declared=False, allow_harness_modules=False
        )
    assert rejected.value.code == "missing_dependency:psycopg"

    # What generated tests get today: the drivers the harness supplies, and nothing else.
    tests, _ = build_generated_tests(request, snapshot, [_spec(PSYCOPG_PROOF)])
    assert [test.path for test in tests] == [TEST_PATH]
    with pytest.raises(PatchPolicyError, match="missing_dependency:requests"):
        build_generated_tests(request, snapshot, [_spec("import harness as h\nimport requests\n")])


def test_the_harness_exemption_does_not_reach_application_patches(request_payload):
    """A driver the sandbox fakes is still a dependency the deployment has to install.

    The widening is for generated tests only, so a patch that introduces an undeclared import
    of a faked driver is rejected exactly as before, and one the requirements declare is not.
    """
    undeclared = RepairRequest.model_validate(_payload(request_payload))
    with pytest.raises(PatchPolicyError, match="missing_dependency:psycopg"):
        build_patch_bundle(
            undeclared,
            Snapshot(undeclared),
            [whole_file_change(APP_PATH, APP_SOURCE, "import psycopg\n" + APP_SOURCE)],
            [],
        )
    declared = RepairRequest.model_validate(_payload(request_payload, extra_files=[("requirements.txt", "psycopg==3.2.10\n")]))
    build_patch_bundle(
        declared,
        Snapshot(declared),
        [whole_file_change(APP_PATH, APP_SOURCE, "import psycopg\n" + APP_SOURCE)],
        [],
    )


def test_a_python_test_that_only_reads_the_file_as_text_is_rejected(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload))
    snapshot = Snapshot(request)
    text_only = "import sys\nsys.exit(0 if 'environ' in open('app/client.py').read() else 1)\n"
    with pytest.raises(PatchPolicyError) as error:
        build_generated_tests(request, snapshot, [_spec(text_only)])
    assert error.value.code == f"regression_test_reads_source_as_text:{TEST_PATH}"
    # The same read beside a harness load is a behavior test.
    tests, _ = build_generated_tests(request, snapshot, [_spec(HARNESS_TEST.replace("def body():\n", "def body():\n    open(__file__).read()\n"))])
    assert len(tests) == 1


def test_a_python_test_name_must_end_in_test_py_inside_the_generated_directory(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="regression_test_name_invalid"):
        build_generated_tests(request, snapshot, [_spec(path=".mitig8it/regression/finding.py")])
    with pytest.raises(PatchPolicyError, match="regression_test_outside_generated_directory"):
        build_generated_tests(request, snapshot, [_spec(path="tests/finding.test.py")])
    with pytest.raises(PatchPolicyError) as error:
        build_generated_tests(request, snapshot, [_spec("def body(:\n    pass\n")])
    assert error.value.code == f"candidate_syntax_invalid:{TEST_PATH}"
    assert "py_compile" in error.value.guidance


def test_python_syntax_and_load_checks_reject_a_broken_candidate(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError) as error:
        build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, APP_SOURCE + "def broken(:\n")], [])
    assert error.value.code == f"candidate_syntax_invalid:{APP_PATH}"
    with pytest.raises(PatchPolicyError) as error:
        build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, APP_SOURCE.replace('"sk-live-aaaaaaaaaaaaaaaa"', "secrets.token_hex()"))], [])
    assert error.value.code == f"candidate_load_failed:{APP_PATH}"
    assert "NameError" in error.value.guidance and "Python reports" in error.value.guidance


def test_python_load_check_records_missing_dependencies_and_environment_reads_as_limitations(request_payload):
    request = RepairRequest.model_validate(_payload(request_payload, extra_files=[("requirements.txt", "flask\n")]))
    snapshot = Snapshot(request)
    bundle = _bundle(request, snapshot)
    assert f"{APP_PATH} now reads API_KEY from the environment; the deployment must provide it" in bundle.limitations
    # A literal name gets a placeholder during the load check, so the module loads past it and
    # a NameError further down is still caught; only a name the check cannot see is a limitation.
    assert not any(item.startswith("runtime load check") for item in bundle.limitations), bundle.limitations
    dynamic = APP_REPAIRED.replace('os.environ["API_KEY"]', 'os.environ["API_KEY_" + "SUFFIX"]')
    bundle = build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, dynamic)], [_spec()])
    assert any(item.startswith(f"runtime load check skipped for {APP_PATH}: environment variable 'API_KEY_SUFFIX' is not set") for item in bundle.limitations)
    with pytest.raises(PatchPolicyError) as error:
        build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, APP_REPAIRED + "\nVALUE = ast.literal_eval('1')\n")], [])
    assert error.value.code == f"candidate_load_failed:{APP_PATH}" and "NameError" in error.value.guidance
    bundle = build_patch_bundle(request, snapshot, [whole_file_change(APP_PATH, APP_SOURCE, "import flask\n" + APP_SOURCE)], [_spec()])
    assert any("No module named 'flask'" in item for item in bundle.limitations)
    assert environment_notes(APP_PATH, APP_SOURCE, APP_REPAIRED) == [f"{APP_PATH} now reads API_KEY from the environment; the deployment must provide it"]
    assert environment_notes(APP_PATH, APP_REPAIRED, APP_REPAIRED) == []
    assert environment_notes("src/db.js", "", "process.env.X") == []
