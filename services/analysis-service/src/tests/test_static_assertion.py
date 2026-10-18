"""`POST /verify/static-assertion`: the four match sets, over the real rules of both tiers.

The remediation service decides the five clauses of a static assertion
(`services/remediation-service/contracts/repair-v1.md`); this side only answers which rules match
which file text. These tests hold that answer: the finding's own rule over each file, every rule
over each file, the file's own line numbers, and the two properties the assertion's claim rests
on, which are that nothing was executed and that the answer is the same every time.
"""
import main
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import static_assertion as sa
from security_rules import SECURITY_RULES

SECRET = "internal-secret-for-tests"
TIER1_RULE = "secret.hardcoded.credential"
TIER2_RULE = "opengrep.cwe-798.js-credential-constant"
PATH = "src/config.js"
LITERAL = "sk-live-7f3a91bc44de2210"
ORIGINAL = f"const region = 'eu-west-1';\nconst apiKey = '{LITERAL}';\nmodule.exports = {{ apiKey, region }};\n"
PATCHED = "const region = 'eu-west-1';\nconst apiKey = process.env.API_KEY;\nmodule.exports = { apiKey, region };\n"


@pytest.fixture(autouse=True)
def configured_secret(monkeypatch):
    monkeypatch.setenv("ANALYSIS_SERVICE_INTERNAL_SECRET", SECRET)
    monkeypatch.delenv("GITHUB_SERVICE_INTERNAL_SECRET", raising=False)


@pytest.fixture
def client():
    return TestClient(main.app)


def post(client, **overrides):
    body = {"rule_id": TIER1_RULE, "path": PATH, "original_content": ORIGINAL, "patched_content": PATCHED}
    body.update(overrides)
    return client.post("/verify/static-assertion", json=body, headers={"x-internal-secret": SECRET})


def lines(matches, rule_id=None):
    return sorted(item["line"] for item in matches if rule_id is None or item["rule_id"] == rule_id)


def rule_ids(matches):
    return sorted({item["rule_id"] for item in matches})


# -- the endpoint ------------------------------------------------------------------------------


def test_the_endpoint_requires_the_internal_secret(client):
    response = client.post("/verify/static-assertion", json={"rule_id": TIER1_RULE, "path": PATH})
    assert response.status_code == 401


def test_a_tier1_rule_is_answered_with_the_files_own_line_numbers(client):
    body = post(client).json()
    assert body["tier"] == sa.TIER1
    assert body["refusal"] is None
    assert lines(body["original"]["rule_matches"]) == [2]
    assert body["patched"]["rule_matches"] == []
    # Clause 5, asserted by the side that would have had to run something.
    assert body["executed"] is False
    assert body["nothing_executed"] == "No code was executed."


def test_a_tier2_rule_is_answered_through_the_opengrep_runner(client):
    body = post(client, rule_id=TIER2_RULE).json()
    assert body["tier"] == sa.TIER2
    assert lines(body["original"]["rule_matches"]) == [2]
    assert body["patched"]["rule_matches"] == []


def test_only_the_named_rule_is_reported_in_the_rule_match_set(client):
    """The single-rule config is what makes clauses 1 and 2 about this rule and no other."""
    body = post(client, rule_id=TIER2_RULE).json()
    assert rule_ids(body["original"]["rule_matches"]) == [TIER2_RULE]
    # While the all-rule set over the same file carries more than that one rule.
    assert len(rule_ids(body["original"]["all_matches"])) > 1


def test_the_all_rule_match_sets_cover_both_tiers(client):
    """Clause 4's input. A patch written for a tier 2 finding can introduce a tier 1 shape."""
    body = post(client).json()
    ids = rule_ids(body["original"]["all_matches"])
    assert any(not item.startswith("opengrep.") for item in ids), ids
    assert any(item.startswith("opengrep.") for item in ids), ids
    assert TIER1_RULE in ids


def test_a_patch_that_trades_one_vulnerability_for_another_shows_the_new_rule(client):
    """What clause 4 is decided from: a rule matching the patch that did not match the original."""
    traded = ORIGINAL.replace(
        f"const apiKey = '{LITERAL}';",
        "const apiKey = process.env.API_KEY;\nrequire('child_process').exec(`ls ${process.argv[2]}`);",
    )
    body = post(client, patched_content=traded).json()
    introduced = set(rule_ids(body["patched"]["all_matches"])) - set(rule_ids(body["original"]["all_matches"]))
    assert introduced, "the command sink should match a rule the original did not"


def test_an_unknown_rule_is_refused_rather_than_reported_as_no_match(client):
    """A rule that cannot be run must never look like a rule that found nothing."""
    body = post(client, rule_id="no.such.rule").json()
    assert body["refusal"] == sa.RULE_UNKNOWN
    assert "original" not in body and "patched" not in body


def test_a_tier2_rule_on_a_path_tier2_does_not_scan_is_refused(client):
    body = post(client, rule_id=TIER2_RULE, path="docs/config.rst").json()
    assert body["refusal"] == sa.RULE_NOT_APPLICABLE


WORKFLOW_PATH = ".github/workflows/preview.yml"
PWN_RULE = "opengrep.cwe-829.gha-pwn-request-checkout"
PWN_ORIGINAL = (
    "on:\n"
    "  pull_request_target:\n"
    "jobs:\n"
    "  preview:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "        with:\n"
    "          ref: ${{ github.event.pull_request.head.sha }}\n"
)
PWN_PATCHED = PWN_ORIGINAL.replace("head.sha", "base.sha")


def test_a_workflow_rule_on_a_workflow_path_is_answered(client):
    """Tier 2 reads `.github/workflows/*.yml` by path, not by extension, and so must this.

    Before this was asserted the endpoint refused every workflow rule as not applicable, so the
    one family that declares the static assertion could never have a repair asserted.
    """
    body = post(client, rule_id=PWN_RULE, path=WORKFLOW_PATH, original_content=PWN_ORIGINAL, patched_content=PWN_PATCHED).json()
    assert body["refusal"] is None
    assert body["tier"] == sa.TIER2
    assert lines(body["original"]["rule_matches"]) == [9]
    assert body["patched"]["rule_matches"] == []


def test_a_workflow_rule_on_ordinary_yaml_is_still_refused(client):
    body = post(client, rule_id=PWN_RULE, path="deploy/preview.yml", original_content=PWN_ORIGINAL, patched_content=PWN_PATCHED).json()
    assert body["refusal"] == sa.RULE_NOT_APPLICABLE


def test_an_oversized_file_is_refused(client):
    response = post(client, original_content="x" * (sa.MAX_ASSERTION_FILE_BYTES + 1))
    assert response.status_code == 413


def test_a_path_that_would_escape_the_scan_directory_is_refused(client):
    response = post(client, rule_id=TIER2_RULE, path="../../etc/passwd.js")
    assert response.status_code == 400


# -- the module ---------------------------------------------------------------------------------


def test_the_answer_is_deterministic():
    first = sa.match_sets(TIER1_RULE, PATH, ORIGINAL, PATCHED)
    second = sa.match_sets(TIER1_RULE, PATH, ORIGINAL, PATCHED)
    assert first == second


def test_every_line_a_tier1_rule_matches_is_reported_not_just_the_first():
    """Tier 1 emits one finding per rule per file; an assertion has to see all of them.

    Without this, clause 2 could not tell a file with one secret removed from a file with two
    secrets and one removed.
    """
    two = f"const apiKey = '{LITERAL}';\nconst password = 'hunter2-hunter2-hunter2';\n"
    matches = sa.rule_matches(TIER1_RULE, sa.TIER1, PATH, two)
    assert lines(matches) == [1, 2]


def test_a_tier1_rule_declaring_quarantine_is_still_asserted_against():
    """A quarantine decides whether a finding may be posted, not whether a patch may be checked."""
    from main import QUARANTINED_RULE_IDS

    quarantined = sorted(rule.rule_id for rule in SECURITY_RULES if rule.rule_id in QUARANTINED_RULE_IDS)
    assert quarantined, "the quarantine list is expected to be non-empty"
    assert sa.rule_tier(quarantined[0]) == sa.TIER1


def test_the_tier2_single_rule_document_is_the_rule_file_s_own():
    document = sa.tier2_rule_document(TIER2_RULE)
    assert document is not None
    [rule] = document["rules"]
    assert rule["id"] == "cwe-798.js-credential-constant"
    assert "languages" in rule and ("pattern" in rule or "patterns" in rule or "pattern-either" in rule)


def test_whole_file_patch_keeps_a_body_line_that_starts_with_a_diff_marker():
    from finding_quality import parse_patch_entries, whole_file_patch

    content = "-not-a-deletion\n+not-an-addition\nplain\n"
    entries = parse_patch_entries(whole_file_patch(content), PATH)
    assert [entry["content"] for entry in entries][:3] == ["-not-a-deletion", "+not-an-addition", "plain"]
    assert [entry["line_number"] for entry in entries][:3] == [1, 2, 3]


def test_the_scanner_is_run_with_the_network_switched_off(monkeypatch, tmp_path):
    """Clause 5 claims nothing ran; the assertion also claims nothing was fetched."""
    import subprocess

    import opengrep_runner

    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError):
        opengrep_runner._run_semgrep(str(tmp_path / "nowhere"))
    assert "--metrics=off" in seen["argv"]
    assert "--disable-version-check" in seen["argv"]


def test_a_scanner_that_cannot_run_is_an_error_and_never_an_empty_match_set(client, monkeypatch):
    import opengrep_runner

    def fake_run(target_dir, config=None):
        raise RuntimeError("OpenGrep executable is unavailable")

    monkeypatch.setattr(opengrep_runner, "_run_semgrep", fake_run)
    monkeypatch.setattr(sa, "_run_semgrep", fake_run)
    response = post(client, rule_id=TIER2_RULE)
    assert response.status_code == 503
