"""The two `workflow_hardening` repairs added with the October 2026 supply-chain rules.

`cwe-829.gha-pwn-request-checkout` reports an `actions/checkout` of the pull request's revision
under `pull_request_target` or `workflow_run`. The repair points the checkout at the base revision
under the first trigger and removes the `ref:` under the second.

`cwe-732.gha-write-grant-on-pull-request-target` reports `write-all`, `contents: write` or
`id-token: write` under `pull_request_target`. The repair removes the write half of the grant.

Each repair is checked twice: as the hunks the template writes, and through the static assertion
over the real scanner, which is the only verification level this family has. The second half
skips, with the reason named, when this process cannot import the analysis service or has no
scanner, exactly as `test_static_assertion_engine.py` does.

The other two rules of that change, `cwe-829.gha-untrusted-artifact-executed` and
`cwe-494.gha-remote-script-piped-to-shell`, get no template, and the last class here says so.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from src.families import WORKFLOW, WORKFLOW_HARDENING, rule_family
from src.git_tree import compute_tree_oid
from src.models import FilePatch, GitTreeEntry, RepairRequest
from src.patches import LocatedHunk, PatchBundle, PatchPolicyError, build_patch_bundle, path_forbidden
from src.retrieval import Snapshot
from src.templates import BASE_REVISION, TemplateFallback, generate_template
from src.verification import Verifier
from src.verification.static_assertion import InProcessRuleOracle
from tests.conftest import git_blob

PATH = ".github/workflows/preview.yml"
PWN_RULE = "opengrep.cwe-829.gha-pwn-request-checkout"
WIDE_CHECKOUT_RULE = "opengrep.cwe-829.gha-untrusted-checkout-privileged-trigger"
GRANT_RULE = "opengrep.cwe-732.gha-write-grant-on-pull-request-target"

TARGET_CHECKOUT = """\
name: preview
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo done
"""

WORKFLOW_RUN_CHECKOUT = """\
name: report
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: echo done
"""

WORKFLOW_RUN_CHECKOUT_WITH_SIBLING = WORKFLOW_RUN_CHECKOUT.replace(
    "          ref: ${{ github.event.workflow_run.head_sha }}\n",
    "          ref: ${{ github.event.workflow_run.head_sha }}\n          fetch-depth: 0\n",
)

OTHER_ACTION_REF = """\
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Wait
        uses: tomchv/wait-my-workflow@v1.1.0
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
"""

TARGET_GRANTS = """\
name: label
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo hi
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: echo hi
"""

TARGET_WRITE_ALL = """\
name: label
on:
  pull_request_target:
permissions: write-all # everything
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


# `.github/` is a forbidden path prefix by default (`models.RepairPolicy`) and `.yml` is not an
# application suffix (`patches.APPLICATION_SUFFIXES`), so `build_patch_bundle` refuses every
# workflow patch: `protected_path` first, `unsupported_application_file` behind it. That is file
# policy, which decides who may edit CI, and nothing on this branch changes it.
# `test_patch_policy_still_refuses_to_bundle_a_workflow` pins both refusals. The static
# assertion tests below therefore build the bundle by hand from the template's own hunks, so they
# measure the repair and the level, not the policy.
def _snapshot(request_payload: dict, source: str, findings: list[dict]):
    entries = [GitTreeEntry(path=PATH, mode="100644", type="blob", sha=git_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": PATH, "content": source, "sha": git_blob(source)}]
    payload["findings"] = findings
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request


def _finding(rule_id: str, line: int, internal_type: str, cwe: str, merged: list[str] | None = None) -> dict:
    finding = {
        "snapshot_id": f"gha-{line}",
        "rule_id": rule_id,
        "cwe_id": cwe,
        "internal_type": internal_type,
        "category": "CI/CD",
        "file_path": PATH,
        "line_start": line,
        "line_end": line,
    }
    if merged is not None:
        finding["evidence_details"] = {"extra": {"merged_rule_ids": merged}}
    return finding


def _pwn(line: int, rule_id: str = PWN_RULE, merged: list[str] | None = None) -> dict:
    return _finding(rule_id, line, "untrusted_code_checkout", "CWE-829", merged)


def _grant(line: int) -> dict:
    return _finding(GRANT_RULE, line, "excessive_workflow_permissions", "CWE-732")


def _patch(request_payload, source, finding):
    snapshot, request = _snapshot(request_payload, source, [finding])
    assert rule_family(request.findings[0]) == WORKFLOW_HARDENING
    return generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)


def _apply(source: str, changes: list[dict]) -> str:
    lines = source.split("\n")
    for change in sorted(changes, key=lambda item: item["start_line"], reverse=True):
        start = change["start_line"] - 1
        assert lines[start : start + len(change["original_lines"])] == change["original_lines"]
        lines[start : start + len(change["original_lines"])] = change["replacement_lines"]
    return "\n".join(lines)


class TestThePwnRequestRepair:
    def test_under_pull_request_target_the_checkout_takes_the_base_revision(self, request_payload):
        patch = _patch(request_payload, TARGET_CHECKOUT, _pwn(12))
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        [change] = patch.changes
        assert change["start_line"] == 12
        assert change["replacement_lines"] == [f"          ref: {BASE_REVISION}"]

    def test_quotes_and_a_trailing_comment_survive(self, request_payload):
        source = TARGET_CHECKOUT.replace(
            "          ref: ${{ github.event.pull_request.head.sha }}",
            "          ref: '${{ github.head_ref }}' # the branch",
        )
        patch = _patch(request_payload, source, _pwn(12))
        assert patch.changes[0]["replacement_lines"] == [f"          ref: '{BASE_REVISION}' # the branch"]

    def test_under_workflow_run_the_ref_and_its_now_empty_with_block_go(self, request_payload):
        patch = _patch(request_payload, WORKFLOW_RUN_CHECKOUT, _pwn(12))
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        [change] = patch.changes
        assert change["start_line"] == 11
        assert change["original_lines"] == ["        with:", "          ref: ${{ github.event.workflow_run.head_sha }}"]
        assert change["replacement_lines"] == []
        repaired = _apply(WORKFLOW_RUN_CHECKOUT, patch.changes)
        assert "      - uses: actions/checkout@v4\n      - run: echo done" in repaired

    def test_under_workflow_run_a_sibling_input_keeps_the_with_block(self, request_payload):
        patch = _patch(request_payload, WORKFLOW_RUN_CHECKOUT_WITH_SIBLING, _pwn(12))
        [change] = patch.changes
        assert change["start_line"] == 12
        assert change["replacement_lines"] == []
        assert "          fetch-depth: 0" in _apply(WORKFLOW_RUN_CHECKOUT_WITH_SIBLING, patch.changes)

    def test_a_workflow_with_both_triggers_gets_the_removal(self, request_payload):
        """`base.sha` is empty under `workflow_run`, so it is not a repair for that half."""
        source = WORKFLOW_RUN_CHECKOUT_WITH_SIBLING.replace("on:\n", "on:\n  pull_request_target:\n", 1)
        patch = _patch(request_payload, source, _pwn(13))
        assert patch.changes[0]["replacement_lines"] == []

    def test_the_narrower_rule_merged_into_the_wider_one_still_gets_the_repair(self, request_payload):
        """The clusterer may keep either id as the survivor; the union decides."""
        finding = _pwn(12, rule_id=WIDE_CHECKOUT_RULE, merged=[WIDE_CHECKOUT_RULE, PWN_RULE])
        patch = _patch(request_payload, TARGET_CHECKOUT, finding)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert patch.changes[0]["replacement_lines"] == [f"          ref: {BASE_REVISION}"]

    def test_the_wider_rule_alone_is_still_not_an_edit(self, request_payload):
        """It also reports a `ref:` that is an input to some other action."""
        patch = _patch(request_payload, TARGET_CHECKOUT, _pwn(12, rule_id=WIDE_CHECKOUT_RULE))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "workflow_shape_not_templated"

    def test_a_ref_under_another_action_is_refused(self, request_payload):
        patch = _patch(request_payload, OTHER_ACTION_REF, _pwn(11))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "ref_not_under_checkout"

    def test_a_line_that_is_not_an_untrusted_ref_is_refused(self, request_payload):
        patch = _patch(request_payload, TARGET_CHECKOUT, _pwn(11))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "untrusted_ref_not_found"

    def test_no_privileged_trigger_is_refused(self, request_payload):
        source = TARGET_CHECKOUT.replace("  pull_request_target:\n    types: [opened, synchronize]\n", "  pull_request:\n")
        patch = _patch(request_payload, source, _pwn(11))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "privileged_trigger_not_found"


class TestTheWriteGrantRepair:
    def test_contents_write_becomes_read(self, request_payload):
        patch = _patch(request_payload, TARGET_GRANTS, _grant(6))
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        [change] = patch.changes
        assert change["replacement_lines"] == ["  contents: read"]
        assert "will now fail" in patch.description

    def test_a_lone_id_token_grant_leaves_an_empty_mapping_not_a_null(self, request_payload):
        patch = _patch(request_payload, TARGET_GRANTS, _grant(12))
        [change] = patch.changes
        assert change["start_line"] == 11
        assert change["original_lines"] == ["    permissions:", "      id-token: write"]
        assert change["replacement_lines"] == ["    permissions: {}"]

    def test_an_id_token_grant_with_a_sibling_is_deleted(self, request_payload):
        patch = _patch(request_payload, TARGET_GRANTS, _grant(18))
        [change] = patch.changes
        assert change["start_line"] == 18
        assert change["replacement_lines"] == []
        assert "      contents: read" in _apply(TARGET_GRANTS, patch.changes)

    def test_write_all_becomes_read_all_and_keeps_its_comment(self, request_payload):
        patch = _patch(request_payload, TARGET_WRITE_ALL, _grant(4))
        assert patch.changes[0]["replacement_lines"] == ["permissions: read-all # everything"]

    def test_a_grant_outside_a_permissions_block_is_refused(self, request_payload):
        source = TARGET_GRANTS.replace("permissions:\n  contents: write", "settings:\n  contents: write", 1)
        patch = _patch(request_payload, source, _grant(6))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "write_grant_not_under_permissions"

    def test_a_line_that_is_not_a_write_grant_is_refused(self, request_payload):
        patch = _patch(request_payload, TARGET_GRANTS, _grant(7))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "write_grant_not_found"


class TestTheShapesThatStayFindingsWithoutAFix:
    @pytest.mark.parametrize(
        "rule_id,internal_type,cwe",
        [
            ("opengrep.cwe-829.gha-untrusted-artifact-executed", "untrusted_artifact_execution", "CWE-829"),
            ("opengrep.cwe-494.gha-remote-script-piped-to-shell", "remote_script_execution", "CWE-494"),
        ],
    )
    def test_they_produce_no_patch_and_say_why(self, request_payload, rule_id, internal_type, cwe):
        patch = _patch(request_payload, TARGET_CHECKOUT, _finding(rule_id, 12, internal_type, cwe))
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "workflow_shape_not_templated"


# -- the static assertion over the real scanner ------------------------------------------------


@pytest.fixture(scope="module")
def oracle():
    unavailable = InProcessRuleOracle.unavailable_reason()
    if unavailable is not None:
        pytest.skip(unavailable)
    return InProcessRuleOracle.load()


def test_patch_policy_still_refuses_to_bundle_a_workflow(request_payload):
    """Nothing here changes who may edit CI: the template writes hunks, the policy decides."""
    snapshot, request = _snapshot(request_payload, TARGET_CHECKOUT, [_pwn(12)])
    assert path_forbidden(PATH, request)
    patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
    with pytest.raises(PatchPolicyError, match="protected_path"):
        build_patch_bundle(request, snapshot, patch.changes, None)
    request.policy.forbidden_path_prefixes = [p for p in request.policy.forbidden_path_prefixes if p != ".github/"]
    with pytest.raises(PatchPolicyError, match="unsupported_application_file"):
        build_patch_bundle(request, snapshot, patch.changes, None)


def _bundle(path: str, original: str, changes: list[dict]) -> PatchBundle:
    """The template's hunks as a bundle, built without the file policy `build_patch_bundle` applies."""
    patched = _apply(original, changes)
    hunks = tuple(
        LocatedHunk(
            path,
            change["start_line"],
            change["start_line"] + max(len(change["original_lines"]), 1) - 1,
            tuple(change["original_lines"]),
            tuple(change["replacement_lines"]),
            change.get("finding_id"),
        )
        for change in changes
    )
    digest = hashlib.sha256(patched.encode()).hexdigest()
    file_patch = FilePatch(
        path=path,
        base_sha256=hashlib.sha256(original.encode()).hexdigest(),
        replacement_content=patched,
        contents_base64=base64.b64encode(patched.encode()).decode(),
        new_sha256=digest,
        unified_diff="",
    )
    return PatchBundle((file_patch,), digest, sum(len(change["original_lines"]) for change in changes), hunks=hunks)


async def _assert(request_payload, oracle, source: str, finding: dict):
    snapshot, request = _snapshot(request_payload, source, [finding])
    patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
    assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
    bundle = _bundle(PATH, source, patch.changes)
    return await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:workflow"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,finding",
    [
        (TARGET_CHECKOUT, _pwn(12)),
        (WORKFLOW_RUN_CHECKOUT, _pwn(12)),
        (WORKFLOW_RUN_CHECKOUT_WITH_SIBLING, _pwn(12)),
    ],
    ids=["base-sha", "ref-and-with-removed", "ref-removed"],
)
async def test_the_pwn_request_repair_is_asserted(request_payload, oracle, source, finding):
    result = await _assert(request_payload, oracle, source, finding)
    assert result.status == "passed", result.reason_code
    assert result.proven_finding_ids == ["gha-12"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,line",
    [
        (TARGET_WRITE_ALL, 4),
        (TARGET_GRANTS.replace("    permissions:\n      id-token: write\n", "", 1).replace("      id-token: write\n", "", 1), 6),
        (TARGET_GRANTS.replace("permissions:\n  contents: write\n", "permissions:\n  contents: read\n", 1).replace("      id-token: write\n      contents: read\n", "      contents: read\n", 1), 12),
    ],
    ids=["write-all", "contents", "lone-id-token"],
)
async def test_the_write_grant_repair_is_asserted(request_payload, oracle, source, line):
    """One grant per file: the assertion is whole-file, so a second grant would keep the rule
    matching the patch and the candidate would be refused, as static-assertion-2026-09.md
    describes for every multi-site file."""
    result = await _assert(request_payload, oracle, source, _grant(line))
    assert result.status == "passed", result.reason_code
    assert result.proven_finding_ids == [f"gha-{line}"]


@pytest.mark.asyncio
async def test_a_second_grant_in_the_file_refuses_the_assertion(request_payload, oracle):
    result = await _assert(request_payload, oracle, TARGET_GRANTS, _grant(6))
    assert result.status == "failed"
    assert result.reason_code == "static_assertion_rule_still_matches_patch"
