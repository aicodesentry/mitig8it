"""The checks one verification run actually executes.

The request policy supplies fixture-shaped checks chosen by the trusted control plane. Most
real repositories have no such fixture, so the engine also derives checks from the candidate
itself: the agent's generated regression test, and generic behavior checks that need nothing
installed. Policy-supplied checks always run as before; the derived checks are additive.

Every derived check is a fixed argv built here, never a model-supplied command string. The
generated test's *content* is untrusted, so it is materialized into the sandbox workspace and
executed only by the sandbox driver, exactly like repository code.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ..models import RepairRequest, VerificationCheck
from ..patches import PatchBundle
from ..retrieval import Snapshot
from ..sandbox.harness import HARNESS_OCCUPIED_LIMITATION, HARNESS_PATH, harness_snapshot_entry

REGRESSION_CHECK_PREFIX = "generated_regression_test"
SYNTAX_CHECK_PREFIX = "generated_node_syntax"
REPOSITORY_TEST_CHECK_ID = "generated_repository_test_script"

REGRESSION_TEST_TIMEOUT_SECONDS = 60
SYNTAX_CHECK_TIMEOUT_SECONDS = 30
REPOSITORY_TEST_TIMEOUT_SECONDS = 300

SYNTAX_CHECKED_SUFFIXES = {".js", ".cjs", ".mjs"}
MAX_SYNTAX_CHECKS = 20

NO_REGRESSION_TEST_LIMITATION = "no agent-generated regression test was run"
NO_REPOSITORY_TEST_SCRIPT_LIMITATION = (
    "the repository declares no package.json test script, so no repository behavior suite was run"
)
UNINSTALLED_DEPENDENCIES_LIMITATION = (
    "the repository test script was not run: the snapshot carries no installed dependencies and "
    "the sandbox has no network"
)
REPOSITORY_TESTS_DISABLED_LIMITATION = (
    "the repository test script was not run: policy run_repository_tests is false"
)


@dataclass(frozen=True)
class EffectiveChecks:
    """The full check set for one verification run, plus the files it needs on disk."""

    checks: tuple[VerificationCheck, ...]
    generated_files: tuple[dict[str, str], ...]
    regression_check_ids: frozenset[str]
    limitations: tuple[str, ...]
    # Which finding each generated regression check reproduces, by check id. A candidate
    # claims a finding only when its own check fails on the baseline and passes on the candidate.
    regression_findings: dict[str, str] = field(default_factory=dict)
    # Service-owned support files the generated tests load, materialized into both workspaces
    # exactly like the tests: never a patch, never a manifest entry, never applied to the tree.
    harness_files: tuple[dict[str, str], ...] = ()

    @property
    def kinds(self) -> set[str]:
        return {check.kind for check in self.checks}


def _unique(check_id: str, used: set[str]) -> str:
    candidate = check_id
    suffix = 1
    while candidate in used:
        suffix += 1
        candidate = f"{check_id}_{suffix}"
    used.add(candidate)
    return candidate


def _repository_test_script(snapshot: Snapshot) -> str | None:
    """The root package.json `scripts.test`, or None. Nested manifests are not the entry point."""
    if "package.json" not in snapshot.paths:
        return None
    try:
        manifest = json.loads(snapshot.full_content("package.json"))
    except (TypeError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return None
    script = scripts.get("test")
    return script if isinstance(script, str) and script.strip() else None


def dependencies_installed(snapshot: Snapshot) -> bool:
    return any(path == "node_modules" or path.startswith("node_modules/") for path in snapshot.paths)


def build_effective_checks(request: RepairRequest, snapshot: Snapshot, bundle: PatchBundle) -> EffectiveChecks:
    checks: list[VerificationCheck] = list(request.policy.verification_checks)
    used = {check.check_id for check in checks}
    generated_files: list[dict[str, str]] = []
    regression_ids: set[str] = set()
    regression_findings: dict[str, str] = {}
    limitations: list[str] = []

    # 1. The agent's reproducer. It runs on both trees, so the evidence distinguishes a repair
    #    from a candidate that merely removed the feature: baseline must fail, candidate pass.
    for test in bundle.generated_tests:
        check_id = _unique(REGRESSION_CHECK_PREFIX, used)
        regression_ids.add(check_id)
        regression_findings[check_id] = test.finding_id
        generated_files.append({"path": test.path, "content": test.content})
        checks.append(
            VerificationCheck(
                check_id=check_id,
                kind="exploit",
                argv=["node", test.path],
                timeout_seconds=REGRESSION_TEST_TIMEOUT_SECONDS,
            )
        )
    harness_files: list[dict[str, str]] = []
    if not bundle.generated_tests:
        limitations.append(NO_REGRESSION_TEST_LIMITATION)
    elif HARNESS_PATH in snapshot.paths:
        # The materializer refuses duplicate paths, so a repository that occupies the harness
        # path keeps its own file and the limitation says the harness was not supplied.
        limitations.append(HARNESS_OCCUPIED_LIMITATION)
    else:
        harness_files.append(harness_snapshot_entry())

    # 2. `node --check` on every changed JavaScript file. It needs no fixture and no installed
    #    dependency, so it is the one behavior check every Node repository can always run.
    for patch in bundle.patches[:MAX_SYNTAX_CHECKS]:
        if PurePosixPath(patch.path).suffix.lower() not in SYNTAX_CHECKED_SUFFIXES:
            continue
        checks.append(
            VerificationCheck(
                check_id=_unique(SYNTAX_CHECK_PREFIX, used),
                kind="typecheck",
                argv=["node", "--check", patch.path],
                timeout_seconds=SYNTAX_CHECK_TIMEOUT_SECONDS,
            )
        )

    # 3. The repository's own test script, when the snapshot proves one exists and can run.
    script = _repository_test_script(snapshot)
    if not request.policy.run_repository_tests:
        limitations.append(REPOSITORY_TESTS_DISABLED_LIMITATION)
    elif script is None:
        limitations.append(NO_REPOSITORY_TEST_SCRIPT_LIMITATION)
    elif not dependencies_installed(snapshot):
        limitations.append(UNINSTALLED_DEPENDENCIES_LIMITATION)
    else:
        checks.append(
            VerificationCheck(
                check_id=_unique(REPOSITORY_TEST_CHECK_ID, used),
                kind="existing_test",
                argv=["npm", "test", "--silent"],
                timeout_seconds=REPOSITORY_TEST_TIMEOUT_SECONDS,
            )
        )

    return EffectiveChecks(
        tuple(checks),
        tuple(generated_files),
        frozenset(regression_ids),
        tuple(limitations),
        regression_findings,
        harness_files=tuple(harness_files),
    )


def generated_snapshot_entries(snapshot: Snapshot, effective: EffectiveChecks) -> list[dict[str, Any]]:
    """The sandbox payload's file list: the exact snapshot, the generated tests, and the harness.

    The generated files are added to the tree both variants materialize, so the baseline runs
    the same reproducer against the original code. Both sandbox drivers write this list through
    the shared trusted materializer, so the harness reaches the Kubernetes runner and the local
    driver by the same path as the tests. None of it is part of the candidate patch set, so none
    of it reaches the tree the batch applies.
    """
    entries = [{"path": path, "content": snapshot.full_content(path)} for path in snapshot.paths]
    entries.extend({"path": item["path"], "content": item["content"]} for item in effective.generated_files)
    entries.extend({"path": item["path"], "content": item["content"]} for item in effective.harness_files)
    return entries
