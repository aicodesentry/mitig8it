"""The tier 3 sweep: the model as a detector, with every answer checked against the patch.

What is asserted here is the contract around the model rather than the model: a valid answer
becomes a finding in the shape the rest of the pipeline reads; an answer that names a class
off the menu, quotes text that is not on the line, or points at a line the pull request did
not change is rejected with a reason; a sweep finding on a rule finding's line folds into it
as a supporting detection; and with the flag off, no provider is called.
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

import llm_sweep
import main
from finding_quality import cluster_findings, make_fingerprint
from llm_client import LLMResponse
from llm_sweep import (
    POSTING_POST,
    POSTING_QUARANTINE,
    RULE_ID_PREFIX,
    FileBlock,
    build_sweep_prompt,
    load_sweep_posting_policy,
    quarantined_sweep_rule_ids,
    rule_id_for,
    sweep_posting_for,
    sweep_with_summary,
    validate_item,
)
from main import TriageRequest, triage_findings_payload
from taxonomy import CANONICAL_INTERNAL_TYPES

PATH = "app/db.py"
SINK = """    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")"""
PATCH = (
    "@@ -1,3 +1,5 @@\n"
    " import sqlite3\n"
    "+def find(user_id):\n"
    f"+{SINK}\n"
    "+    return cursor.fetchall()\n"
    ' print("done")\n'
)
# New-file line numbers in PATCH: 1 context, 2 to 4 added, 5 context.
SINK_LINE = 3

ENABLED_ENV = {"LLM_SWEEP_ENABLED": "true", "LLM_PROVIDER": "openai", "LLM_API_KEY": "key"}


def _item(**overrides):
    base = {
        "internal_type": "sql_injection",
        "file_path": PATH,
        "line": SINK_LINE,
        "quote": "cursor.execute(",
        "severity": "high",
        "confidence": 0.85,
        "rationale": "user_id is concatenated into the query text.",
        "exploit_payload": "GET /user?id=' OR '1'='1",
    }
    base.update(overrides)
    return base


def _response(items) -> LLMResponse:
    return LLMResponse(text=json.dumps(items), input_tokens=120, output_tokens=40, provider="fake", model="fake")


def _run(items, file_patches=None, repo_profile=None):
    """The sweep over PATCH with a fake provider that answers `items`."""
    with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
        "llm_sweep._call_sweep_llm", return_value=_response(items)
    ) as fake:
        findings, summary = sweep_with_summary(file_patches or {PATH: PATCH}, repo_profile)
    return findings, summary, fake


def _rule_finding(line=SINK_LINE, severity="high"):
    return {
        "rule_id": "sql.injection.raw_query",
        "internal_type": "sql_injection",
        "title": "Potential SQL injection",
        "description": "d",
        "category": "SQL injection",
        "cwe_id": "CWE-89",
        "severity": severity,
        "confidence": 0.8,
        "file_path": PATH,
        "line_start": line,
        "line_end": line,
        "code_snippet": SINK,
        "evidence": "Matched deterministic rule `sql.injection.raw_query`.",
        "fingerprint": make_fingerprint("sql.injection.raw_query", PATH, line, SINK),
        "taxonomy_mappings": {"cwe": ["CWE-89"], "owasp": [], "attack": [], "capec": []},
    }


class TestFlagOff:
    def test_off_by_default_and_no_provider_is_called(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "openai", "LLM_API_KEY": "key"}, clear=True), patch(
            "llm_sweep._call_sweep_llm"
        ) as fake:
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert findings == []
        assert summary["enabled"] is False and summary["status"] == "disabled"
        fake.assert_not_called()

    def test_explicit_false_is_off(self):
        with patch.dict(os.environ, {**ENABLED_ENV, "LLM_SWEEP_ENABLED": "false"}, clear=True), patch(
            "llm_sweep._call_sweep_llm"
        ) as fake:
            findings, _ = sweep_with_summary({PATH: PATCH})
        assert findings == []
        fake.assert_not_called()

    def test_on_without_credentials_is_off(self):
        with patch.dict(os.environ, {"LLM_SWEEP_ENABLED": "true"}, clear=True), patch(
            "llm_sweep._call_sweep_llm"
        ) as fake:
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert findings == [] and summary["enabled"] is False
        fake.assert_not_called()

    def test_the_triage_flag_does_not_switch_the_sweep_on(self):
        """The two halves of tier 3 have their own flags; a triage key alone runs no sweep."""
        with patch.dict(
            os.environ, {"LLM_TRIAGE_ENABLED": "true", "LLM_PROVIDER": "openai", "LLM_API_KEY": "key"}, clear=True
        ), patch("llm_sweep._call_sweep_llm") as fake:
            findings, _ = sweep_with_summary({PATH: PATCH})
        assert findings == []
        fake.assert_not_called()


class TestValidOutputBecomesFindings:
    def test_one_valid_item_is_one_finding_in_the_pipeline_shape(self):
        findings, summary, fake = _run([_item()])
        fake.assert_called_once()
        assert len(findings) == 1
        finding = findings[0]
        assert finding["rule_id"] == "llm.sweep.sql_injection"
        assert finding["internal_type"] == "sql_injection"
        assert finding["cwe_id"] == "CWE-89"
        assert finding["file_path"] == PATH
        assert finding["line_start"] == finding["line_end"] == SINK_LINE
        assert finding["code_snippet"] == SINK
        assert finding["severity"] == "high"
        assert finding["confidence"] == 0.85
        assert finding["evidence_strength"] == "model"
        assert finding["is_taint_based"] is False
        assert finding["detector_tier"] == "tier3-sweep"
        assert finding["analysis_scope"] == "model-sweep"
        assert finding["evidence_details"]["is_taint_based"] is False
        assert finding["evidence_details"]["evidence_strength"] == "model"
        assert finding["exploit_scenario"] == "GET /user?id=' OR '1'='1"
        assert "cursor.execute(" in finding["evidence"]
        assert finding["fingerprint"] == make_fingerprint("llm.sweep.sql_injection", PATH, SINK_LINE, SINK)
        assert summary["accepted"] == 1 and summary["candidates"] == 1 and summary["rejected"] == {}
        assert summary["calls"] == 1 and summary["input_tokens"] == 120

    def test_the_tier_label_is_neither_tier_1_nor_tier_2(self):
        from finding_quality import detector_kind

        findings, _, _ = _run([_item()])
        assert detector_kind(findings[0]) == "model"
        assert not findings[0]["rule_id"].startswith("opengrep.")
        assert findings[0]["rule_id"].startswith(RULE_ID_PREFIX)

    def test_a_fenced_response_is_read(self):
        fenced = "```json\n" + json.dumps([_item()]) + "\n```"
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm",
            return_value=LLMResponse(text=fenced, input_tokens=1, output_tokens=1, provider="f", model="f"),
        ):
            findings, _ = sweep_with_summary({PATH: PATCH})
        assert len(findings) == 1

    def test_an_empty_array_is_no_findings_and_no_error(self):
        findings, summary, _ = _run([])
        assert findings == [] and summary["status"] == "ok" and summary["calls"] == 1


class TestRejections:
    @pytest.mark.parametrize(
        "override, reason",
        [
            ({"internal_type": "sql_injection_maybe"}, "off_menu_class"),
            ({"internal_type": "CWE-89"}, "off_menu_class"),
            ({"internal_type": ""}, "off_menu_class"),
            ({"quote": "cursor.exec("}, "quote_mismatch"),
            ({"quote": "SELECT * FROM accounts"}, "quote_mismatch"),
            ({"quote": ""}, "quote_missing"),
            ({"line": 1}, "line_not_changed"),  # a context line of the hunk
            ({"line": 5}, "line_not_changed"),  # the other context line
            ({"line": 40}, "line_not_changed"),  # not in the patch at all
            ({"line": "three"}, "line_not_an_integer"),
            ({"file_path": "app/other.py"}, "unknown_file"),
            ({"severity": "urgent"}, "invalid_severity"),
            ({"confidence": 1.5}, "invalid_confidence"),
            ({"confidence": "high"}, "invalid_confidence"),
            ({"exploit_payload": ""}, "no_exploit_payload"),
            ({"rationale": "   "}, "no_rationale"),
        ],
    )
    def test_an_invalid_item_is_rejected_with_its_reason(self, override, reason):
        findings, summary, _ = _run([_item(**override)])
        assert findings == []
        assert summary["rejected"] == {reason: 1}
        assert summary["candidates"] == 1 and summary["accepted"] == 0

    def test_a_quote_that_is_on_a_different_changed_line_is_rejected(self):
        """The quote has to be on the reported line, not merely somewhere in the file."""
        findings, summary, _ = _run([_item(line=2, quote="cursor.execute(")])
        assert findings == [] and summary["rejected"] == {"quote_mismatch": 1}

    def test_rejections_are_logged_with_the_reason(self, caplog):
        with caplog.at_level("INFO", logger="mitig8it.analysis.sweep"):
            _run([_item(internal_type="not_a_class")])
        assert any("off_menu_class" in record.getMessage() for record in caplog.records)

    def test_a_non_object_item_is_rejected(self):
        findings, summary, _ = _run(["sql_injection"])
        assert findings == [] and summary["rejected"] == {"not_an_object": 1}

    def test_valid_and_invalid_items_in_one_response_are_separated(self):
        findings, summary, _ = _run([_item(), _item(internal_type="nope"), _item(quote="zzz")])
        assert [f["rule_id"] for f in findings] == ["llm.sweep.sql_injection"]
        assert summary["rejected"] == {"off_menu_class": 1, "quote_mismatch": 1}

    def test_the_same_site_reported_twice_is_one_finding(self):
        findings, summary, _ = _run([_item(), _item(quote="user_id")])
        assert len(findings) == 1 and summary["rejected"] == {"duplicate": 1}

    def test_a_response_that_is_not_json_costs_the_call_and_nothing_else(self):
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm",
            return_value=LLMResponse(text="I think line 3 is bad", input_tokens=1, output_tokens=1, provider="f", model="f"),
        ):
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert findings == []
        assert summary["status"] == "failed"
        assert any(item["kind"] == "provider" for item in summary["limitations"])

    def test_a_provider_error_is_non_blocking(self):
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm", side_effect=RuntimeError("boom key=sk-abcdefghijklmnop")
        ):
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert findings == [] and summary["status"] == "failed"
        assert "sk-abcdefghijklmnop" not in json.dumps(summary)

    def test_validate_item_direct(self):
        block = FileBlock(path=PATH, rendered="", added_lines={SINK_LINE: SINK})
        finding, reason = validate_item(_item(), {PATH: block})
        assert reason is None and finding["rule_id"] == "llm.sweep.sql_injection"
        finding, reason = validate_item(_item(line=9), {PATH: block})
        assert finding is None and reason == "line_not_changed"


class TestFolding:
    def test_a_sweep_finding_on_a_rule_findings_line_folds_into_it(self):
        sweep, _, _ = _run([_item()])
        clustered = cluster_findings([_rule_finding(), *sweep])
        assert len(clustered) == 1
        survivor = clustered[0]
        assert survivor["rule_id"] == "sql.injection.raw_query"
        assert "llm.sweep.sql_injection" in survivor["merged_rule_ids"]
        assert "Supporting detections: llm.sweep.sql_injection" in survivor["evidence"]
        assert "Corroborated by: model" in survivor["evidence"]
        assert survivor["evidence_details"]["extra"]["merged_rule_ids"] == [
            "sql.injection.raw_query", "llm.sweep.sql_injection",
        ]

    def test_the_rule_survives_even_when_the_model_chose_a_higher_severity(self):
        sweep, _, _ = _run([_item(severity="critical", confidence=0.99)])
        clustered = cluster_findings([_rule_finding(severity="medium"), *sweep])
        assert len(clustered) == 1
        assert clustered[0]["rule_id"] == "sql.injection.raw_query"
        assert clustered[0]["severity"] == "medium"
        assert clustered[0]["line_start"] == SINK_LINE

    def test_the_fold_is_order_independent(self):
        sweep, _, _ = _run([_item()])
        clustered = cluster_findings([*sweep, _rule_finding()])
        assert len(clustered) == 1 and clustered[0]["rule_id"] == "sql.injection.raw_query"

    def test_a_sweep_finding_of_another_class_on_the_same_line_is_left_alone(self):
        sweep, _, _ = _run([_item(internal_type="command_injection", exploit_payload="x; id")])
        clustered = cluster_findings([_rule_finding(), *sweep])
        assert len(clustered) == 2

    def test_a_sweep_finding_far_from_the_rule_finding_is_left_alone(self):
        sweep, _, _ = _run([_item()])
        clustered = cluster_findings([_rule_finding(line=40), *sweep])
        assert len(clustered) == 2


class TestPostingPolicyIsData:
    def test_every_canonical_class_has_a_posting_entry(self):
        policy = load_sweep_posting_policy()
        missing = set(CANONICAL_INTERNAL_TYPES) - set(policy)
        assert not missing, f"classes with no posting decision in llm_sweep_posting.yml: {sorted(missing)}"

    def test_every_entry_names_a_canonical_class(self):
        unknown = set(load_sweep_posting_policy()) - set(CANONICAL_INTERNAL_TYPES)
        assert not unknown, f"llm_sweep_posting.yml names classes the taxonomy does not: {sorted(unknown)}"

    def test_every_class_starts_quarantined(self):
        """Nothing the sweep says is posted until the class has a measurement behind it."""
        policy = load_sweep_posting_policy()
        for name in CANONICAL_INTERNAL_TYPES:
            assert sweep_posting_for(name, policy) == POSTING_QUARANTINE, name
        assert quarantined_sweep_rule_ids() == frozenset(rule_id_for(name) for name in CANONICAL_INTERNAL_TYPES)

    def test_post_without_evidence_is_still_quarantine(self):
        policy = {"sql_injection": {"posting": "post", "precision": "measured", "precision_evidence": ""}}
        assert sweep_posting_for("sql_injection", policy) == POSTING_QUARANTINE

    def test_post_with_evidence_posts(self):
        policy = {"sql_injection": {"posting": "post", "precision": "measured", "precision_evidence": "docs/validation/x.md"}}
        assert sweep_posting_for("sql_injection", policy) == POSTING_POST

    def test_a_class_missing_from_the_file_is_quarantined(self):
        assert sweep_posting_for("sql_injection", {}) == POSTING_QUARANTINE

    def test_an_unreadable_file_quarantines_everything(self, tmp_path):
        assert load_sweep_posting_policy(tmp_path / "missing.json") == {}

    def test_the_service_unions_the_sweep_ids_into_the_one_quarantine_set(self):
        assert quarantined_sweep_rule_ids() <= main.QUARANTINED_RULE_IDS

    def test_a_posting_entry_is_data_not_code(self, tmp_path, monkeypatch):
        """Clearing a class is an edit to the JSON file, and the set follows it."""
        document = {"classes": {
            "sql_injection": {"posting": "post", "precision": "measured", "precision_evidence": "measured in doc X"},
        }}
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        monkeypatch.setattr(llm_sweep, "POSTING_POLICY_PATH", path)
        assert "llm.sweep.sql_injection" not in quarantined_sweep_rule_ids()
        assert "llm.sweep.command_injection" in quarantined_sweep_rule_ids()


class TestTier3Handler:
    def _payload(self, findings=None):
        return TriageRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            findings=findings or [],
            file_patches={PATH: PATCH},
            repo_profile={},
        )

    def test_with_the_flag_off_the_handler_calls_nothing_and_answers_as_before(self):
        with patch.dict(os.environ, {}, clear=True), patch("llm_sweep._call_sweep_llm") as fake:
            result = triage_findings_payload(self._payload())
        fake.assert_not_called()
        assert result["findings"] == [] and result["filtered_count"] == 0
        assert result["quarantined_findings"] == {}
        assert result["sweep"]["enabled"] is False

    def test_the_sweep_runs_when_the_rules_found_nothing(self):
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response([_item()])
        ) as fake:
            result = triage_findings_payload(self._payload())
        fake.assert_called_once()
        # Every class is quarantined today, so the finding is counted and not returned.
        assert result["findings"] == []
        assert result["quarantined_findings"] == {"llm.sweep.sql_injection": 1}
        assert result["sweep"]["accepted"] == 1 and result["sweep"]["quarantined"] == 1

    def test_a_cleared_class_reaches_the_response(self, monkeypatch):
        monkeypatch.setattr(main, "QUARANTINED_RULE_IDS", frozenset())
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response([_item()])
        ):
            result = triage_findings_payload(self._payload())
        assert [f["rule_id"] for f in result["findings"]] == ["llm.sweep.sql_injection"]
        assert result["quarantined_findings"] == {}

    def test_a_cleared_sweep_finding_folds_into_the_rule_finding_on_its_line(self, monkeypatch):
        monkeypatch.setattr(main, "QUARANTINED_RULE_IDS", frozenset())
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response([_item()])
        ):
            result = triage_findings_payload(self._payload([_rule_finding()]))
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "sql.injection.raw_query"
        assert "llm.sweep.sql_injection" in result["findings"][0]["merged_rule_ids"]
        assert result["filtered_count"] == 0

    def test_the_sweep_is_not_triaged(self):
        """One model call per hunk group and none to re-judge the sweep's own answers."""
        with patch.dict(os.environ, {**ENABLED_ENV, "LLM_TRIAGE_ENABLED": "true"}, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response([_item()])
        ), patch("llm_triage._call_triage_llm") as triage:
            triage_findings_payload(self._payload())
        triage.assert_not_called()


class TestCostControl:
    def test_only_code_templates_and_workflows_are_sent(self):
        findings, summary, fake = _run([], file_patches={
            "README.md": "@@ -1,1 +1,2 @@\n+password = 'hunter2'\n",
            "opengrep_rules/x.yml": "@@ -1,1 +1,2 @@\n+pattern: eval(...)\n",
            "package-lock.json": "@@ -1,1 +1,2 @@\n+\"lodash\": \"4.17.0\"\n",
            "deploy/k8s.yml": "@@ -1,1 +1,2 @@\n+run: echo ${{ github.event.issue.title }}\n",
            ".github/workflows/ci.yml": "@@ -1,1 +1,2 @@\n+run: echo ${{ github.event.issue.title }}\n",
            "views/page.ejs": "@@ -1,1 +1,2 @@\n+<%- user.name %>\n",
            PATH: PATCH,
        })
        prompt = fake.call_args.args[0]
        for sent in (PATH, ".github/workflows/ci.yml", "views/page.ejs"):
            assert f"### {sent}" in prompt
        for skipped in ("README.md", "opengrep_rules", "package-lock.json", "deploy/k8s.yml"):
            assert skipped not in prompt
        assert summary["files_considered"] == 7 and summary["files_swept"] == 3 and summary["files_skipped"] == 4

    def test_a_patch_ending_in_a_newline_has_no_phantom_line(self):
        block = llm_sweep._render_file(PATH, PATCH)
        assert block.rendered.rstrip().endswith('print("done")')
        assert "     6" not in block.rendered

    def test_a_patch_with_no_added_lines_is_not_sent(self):
        with patch.dict(os.environ, ENABLED_ENV, clear=True), patch("llm_sweep._call_sweep_llm") as fake:
            findings, summary = sweep_with_summary({PATH: "@@ -1,2 +1,1 @@\n import os\n-import sys\n"})
        fake.assert_not_called()
        assert findings == [] and summary["calls"] == 0

    def test_files_are_packed_into_calls_by_the_token_budget(self):
        patches = {f"app/m{i}.py": PATCH for i in range(6)}
        one_file_tokens = llm_sweep.estimate_tokens(llm_sweep._render_file(PATH, PATCH).rendered)
        with patch.dict(
            os.environ,
            {**ENABLED_ENV, "LLM_SWEEP_CALL_TOKEN_BUDGET": str(one_file_tokens * 2 + 1), "LLM_SWEEP_MAX_CALLS": "10"},
            clear=True,
        ), patch("llm_sweep._call_sweep_llm", return_value=_response([])) as fake:
            _, summary = sweep_with_summary(patches)
        assert fake.call_count == 3 and summary["calls"] == 3 and summary["files_swept"] == 6

    def test_the_request_budget_stops_further_calls_and_says_so(self):
        patches = {f"app/m{i}.py": PATCH for i in range(6)}
        one_file_tokens = llm_sweep.estimate_tokens(llm_sweep._render_file(PATH, PATCH).rendered)
        with patch.dict(
            os.environ,
            {
                **ENABLED_ENV,
                "LLM_SWEEP_CALL_TOKEN_BUDGET": str(one_file_tokens + 1),
                "LLM_SWEEP_TOKEN_BUDGET": str(one_file_tokens * 2 + 1),
                "LLM_SWEEP_MAX_CALLS": "10",
            },
            clear=True,
        ), patch("llm_sweep._call_sweep_llm", return_value=_response([])) as fake:
            _, summary = sweep_with_summary(patches)
        assert fake.call_count == 2
        assert summary["files_swept"] == 2 and summary["files_skipped"] == 4
        assert any(item["kind"] == "budget" and "stopped after 2 of 6" in item["message"] for item in summary["limitations"])

    def test_a_file_over_the_per_call_budget_is_skipped_and_reported(self):
        with patch.dict(
            os.environ, {**ENABLED_ENV, "LLM_SWEEP_CALL_TOKEN_BUDGET": "5"}, clear=True
        ), patch("llm_sweep._call_sweep_llm") as fake:
            _, summary = sweep_with_summary({PATH: PATCH})
        fake.assert_not_called()
        assert summary["limitations"][0]["path"] == PATH and summary["limitations"][0]["kind"] == "budget"

    def test_the_findings_cap_holds_over_one_response(self):
        items = [_item(line=2, quote="def find"), _item(), _item(line=4, quote="return")]
        with patch.dict(os.environ, {**ENABLED_ENV, "LLM_SWEEP_MAX_FINDINGS": "2"}, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response(items)
        ):
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert len(findings) == 2 and summary["rejected"] == {"request_cap": 1}

    def test_the_per_file_cap_holds(self):
        items = [_item(line=2, quote="def find"), _item(), _item(line=4, quote="return")]
        with patch.dict(os.environ, {**ENABLED_ENV, "LLM_SWEEP_MAX_FINDINGS_PER_FILE": "1"}, clear=True), patch(
            "llm_sweep._call_sweep_llm", return_value=_response(items)
        ):
            findings, summary = sweep_with_summary({PATH: PATCH})
        assert len(findings) == 1 and summary["rejected"] == {"file_cap": 2}


class TestPrompt:
    def test_added_lines_are_marked_and_context_lines_are_not(self):
        block = llm_sweep._render_file(PATH, PATCH)
        prompt = build_sweep_prompt([block])
        assert f"### {PATH}" in prompt
        assert "     1   import sqlite3" in prompt
        assert f"     3 + {SINK}" in prompt
        assert '     5   print("done")' in prompt
        assert block.added_lines == {2: "def find(user_id):", 3: SINK, 4: "    return cursor.fetchall()"}

    def test_the_menu_is_the_canonical_vocabulary_and_nothing_else(self):
        menu_lines = [line[2:] for line in llm_sweep.SYSTEM_PROMPT.split("Menu of classes:")[1].strip().split("\n")]
        assert set(menu_lines) == set(CANONICAL_INTERNAL_TYPES)

    def test_the_repository_profile_is_included_when_given(self):
        block = llm_sweep._render_file(PATH, PATCH)
        prompt = build_sweep_prompt([block], {"deterministic": {"framework": "flask", "languages": ["python"]}})
        assert "Framework: flask" in prompt and "Languages: python" in prompt
