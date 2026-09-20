"""Tests for LLM triage (Tier 3)."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from llm_triage import (
    LLM_TRIAGE_MAX_FINDINGS,
    _apply_verdicts,
    _build_finding_context,
    _build_triage_prompt,
    _evidence_strength,
    _normalize_fixed_code,
    _parse_triage_response,
    _sanitizer_status,
    _select_findings_for_triage,
    _trace_features,
    is_llm_triage_enabled,
    triage_findings,
)


def _make_finding(**overrides):
    base = {
        "rule_id": "sql.injection.raw_query",
        "title": "Potential SQL Injection",
        "category": "SQL injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "confidence": 0.7,
        "file_path": "app.py",
        "line_start": 10,
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "evidence": "Matched deterministic rule",
        "fingerprint": "abc123",
        "description": "SQL query built with f-string",
        "exploitability": "high",
        "owasp_category": "A03:2021",
        "line_end": 10,
        "remediation": "Use parameterized queries",
        "remediation_patch": "",
        "exploit_scenario": "",
        "evidence_details": {},
    }
    base.update(overrides)
    return base


def _moderate_trace_steps():
    return [
        {"kind": "source", "expr": "req.query.input", "line": 10},
        {"kind": "sink", "expr": "dangerousCall(req.query.input)", "line": 11},
    ]


def _strong_trace_steps():
    return [
        {"kind": "source", "expr": "req.query.input", "line": 10},
        {"kind": "assignment", "expr": "const value = req.query.input", "line": 10},
        {"kind": "sink", "expr": "dangerousCall(value)", "line": 11},
    ]


class TestIsEnabled:
    def test_disabled_when_no_key(self):
        with patch.dict(os.environ, {}, clear=True):
            assert not is_llm_triage_enabled()

    def test_enabled_when_key_set(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            assert is_llm_triage_enabled()

    def test_enabled_when_generic_gemini_key_set(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "test-key"}, clear=True):
            assert is_llm_triage_enabled()


class TestSelectFindings:
    def test_limits_to_max(self):
        findings = [_make_finding(fingerprint=f"fp-{i}") for i in range(30)]
        selected = _select_findings_for_triage(findings)
        assert len(selected) == min(30, LLM_TRIAGE_MAX_FINDINGS)

    def test_prioritizes_high_severity_low_confidence(self):
        low_value = _make_finding(severity="low", confidence=0.95, fingerprint="low")
        high_value = _make_finding(severity="critical", confidence=0.5, fingerprint="high")
        selected = _select_findings_for_triage([low_value, high_value])
        assert selected[0]["fingerprint"] == "high"

    def test_prioritizes_patchable_findings(self):
        generic = _make_finding(
            fingerprint="generic",
            severity="low",
            confidence=0.7,
            rule_id="generic.security.issue",
            category="security issue",
            cwe_id="CWE-200",
            code_snippet="doThing(userInput)",
        )
        patchable = _make_finding(
            fingerprint="patchable",
            severity="high",
            confidence=0.7,
            file_path="app.js",
            category="cross-site scripting (xss)",
            cwe_id="CWE-79",
            code_snippet="element.innerHTML = req.query.name;",
        )
        selected = _select_findings_for_triage([generic, patchable])
        assert selected[0]["fingerprint"] == "patchable"


class TestBuildFindingContext:
    def test_includes_required_fields(self):
        finding = _make_finding()
        ctx = _build_finding_context(finding, {"app.py": "+some code"})
        assert ctx["fingerprint"] == "abc123"
        assert ctx["rule_id"] == "sql.injection.raw_query"
        assert ctx["surrounding_code"] == "+some code"

    def test_truncates_long_patches(self):
        long_patch = "\n".join([f"+line {i}" for i in range(200)])
        ctx = _build_finding_context(_make_finding(), {"app.py": long_patch})
        lines = ctx["surrounding_code"].split("\n")
        assert len(lines) <= 60

    def test_includes_fix_generation_fields(self):
        ctx = _build_finding_context(_make_finding(description="desc", exploit_scenario="boom"), {"app.py": "+some code"})
        assert ctx["category"] == "SQL injection"
        assert ctx["description"] == "desc"
        assert ctx["remediation_hint"] == "Use parameterized queries"
        assert ctx["exploit_scenario"] == "boom"

    def test_includes_structured_analysis_evidence_when_present(self):
        ctx = _build_finding_context(
            _make_finding(
                analysis_scope="taint-intraprocedural",
                source="request-controlled file path",
                sink="filesystem access",
                sanitizers_seen=["path.basename"],
                trace_summary="Taint-tracked flow from request input into fs.readFile.",
                evidence_details={
                    "fix_scope": "line",
                    "fix_target_line": 18,
                    "fix_target_expr": "fs.readFile(file)",
                    "missing_control_type": "base_dir_validation",
                    "auto_fix_eligible": True,
                    "trace_steps": [
                        {"kind": "source", "expr": "req.query.file", "line": 12},
                        {"kind": "assignment", "expr": "const file = req.query.file", "line": 12},
                        {"kind": "sink", "expr": "fs.readFile(file)", "line": 18},
                    ]
                },
            ),
            {"app.py": "+some code"},
        )
        assert ctx["analysis_scope"] == "taint-intraprocedural"
        assert ctx["source"] == "request-controlled file path"
        assert ctx["sink"] == "filesystem access"
        assert ctx["sanitizers_seen"] == ["path.basename"]
        assert "fs.readFile" in ctx["trace_summary"]
        assert ctx["inline_fix_eligible"] is True
        assert ctx["sanitizer_status"] == "present"
        assert ctx["trace_length"] == 3
        assert ctx["trace_quality"] == "strong"
        assert ctx["has_meaningful_trace"] is True
        assert ctx["fix_scope"] == "line"
        assert ctx["fix_target_line"] == 18
        assert ctx["fix_target_expr"] == "fs.readFile(file)"
        assert ctx["missing_control_type"] == "base_dir_validation"
        assert ctx["auto_fix_eligible"] is True

    def test_uses_nested_evidence_details_when_top_level_fields_are_missing(self):
        ctx = _build_finding_context(
            _make_finding(
                analysis_scope=None,
                source=None,
                sink=None,
                sanitizers_seen=None,
                trace_summary=None,
                evidence_details={
                    "analysis_scope": "taint-intraprocedural",
                    "source_type": "request-controlled redirect target",
                    "sink_type": "HTTP redirect",
                    "sanitizer_exprs": ["ensureRelativeRedirect"],
                    "trace_summary": "Taint flow into redirect.",
                    "is_taint_based": True,
                },
            ),
            {"app.py": "+code"},
        )
        assert ctx["analysis_scope"] == "taint-intraprocedural"
        assert ctx["source"] == "request-controlled redirect target"
        assert ctx["sink"] == "HTTP redirect"
        assert ctx["sanitizers_seen"] == ["ensureRelativeRedirect"]
        assert ctx["is_taint_based"] is True
        assert ctx["evidence_strength"] == "strong"
        assert ctx["sanitizer_status"] == "present"

    def test_marks_context_only_findings_as_not_inline_fix_eligible(self):
        ctx = _build_finding_context(
            _make_finding(
                analysis_scope="taint-intraprocedural",
                evidence_details={"reviewability": "context-only"},
            ),
            {"app.py": "+code"},
        )
        assert ctx["reviewability"] == "context-only"
        assert ctx["inline_fix_eligible"] is False


class TestBuildTriagePrompt:
    def test_includes_structured_evidence_and_repo_profile(self):
        prompt = _build_triage_prompt(
            [
                _make_finding(
                    rule_id="opengrep.cwe-22.path-traversal-fs",
                    analysis_scope="taint-intraprocedural",
                    source="request-controlled file path",
                    sink="filesystem access",
                    sanitizers_seen=["path.basename"],
                    trace_summary="Taint-tracked flow from request input into fs.readFile.",
                )
            ],
            {"app.py": "+const file = req.query.file\n+fs.readFile(file)\n"},
            {
                "deterministic": {"framework": "express", "languages": ["javascript"]},
                "interpreted": {"auth_strategy": "middleware", "risk_areas": ["file handling"]},
            },
        )
        assert "Repository Profile" in prompt
        assert "taint-intraprocedural" in prompt
        assert "request-controlled file path" in prompt
        assert "filesystem access" in prompt
        assert "path.basename" in prompt
        assert "inline_fix_eligible" in prompt
        assert "auto_fix_eligible" in prompt
        assert "missing_control_type" in prompt
        assert "fix_scope=line" in prompt
        assert "If reviewability is context-only" in prompt
        assert "trace_quality=strong" in prompt


class TestEvidenceStrength:
    def test_marks_taint_findings_as_strong(self):
        assert _evidence_strength(_make_finding(analysis_scope="taint-intraprocedural")) == "strong"

    def test_marks_ast_pattern_findings_as_medium(self):
        assert _evidence_strength(_make_finding(analysis_scope="ast-pattern")) == "medium"

    def test_marks_pattern_findings_as_light(self):
        assert _evidence_strength(_make_finding(analysis_scope="pattern")) == "light"


class TestTraceFeatures:
    def test_marks_source_assignment_sink_trace_as_strong(self):
        finding = _make_finding(evidence_details={
            "trace_steps": [
                {"kind": "source", "expr": "req.query.file"},
                {"kind": "assignment", "expr": "const file = req.query.file"},
                {"kind": "sink", "expr": "fs.readFile(file)"},
            ]
        })
        features = _trace_features(finding)
        assert features["trace_quality"] == "strong"
        assert features["trace_length"] == 3
        assert features["has_meaningful_trace"] is True

    def test_marks_source_sink_only_trace_as_moderate(self):
        finding = _make_finding(evidence_details={
            "trace_steps": [
                {"kind": "source", "expr": "req.query.url"},
                {"kind": "sink", "expr": "fetch(req.query.url)"},
            ]
        })
        features = _trace_features(finding)
        assert features["trace_quality"] == "moderate"
        assert features["has_only_source_and_sink"] is True

    def test_marks_missing_sink_trace_as_weak(self):
        finding = _make_finding(evidence_details={
            "trace_steps": [
                {"kind": "source", "expr": "req.query.name"},
            ]
        })
        features = _trace_features(finding)
        assert features["trace_quality"] == "weak"

    def test_marks_empty_trace_as_none(self):
        features = _trace_features(_make_finding(analysis_scope="pattern", evidence_details={"trace_steps": []}))
        assert features["trace_quality"] == "none"


class TestSanitizerStatus:
    def test_defaults_to_none_without_sanitizers(self):
        assert _sanitizer_status(_make_finding()) == "none"

    def test_uses_explicit_validated_status(self):
        assert _sanitizer_status(_make_finding(evidence_details={"sanitizer_status": "validated"})) == "validated"

    def test_falls_back_to_present_when_signal_exists_without_status(self):
        assert _sanitizer_status(_make_finding(evidence_details={"sanitizer_exprs": ["path.basename(file)"]})) == "present"


class TestNormalizeFixedCode:
    def test_accepts_small_inline_patch(self):
        fixed = _normalize_fixed_code("cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))", 'query = f"SELECT * FROM users WHERE id = {user_id}"')
        assert fixed == 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'

    def test_strips_markdown_fences(self):
        fixed = _normalize_fixed_code("```python\ncursor.execute(\"SELECT 1\")\n```", "query = 'SELECT 1'")
        assert fixed == 'cursor.execute("SELECT 1")'

    def test_rejects_large_patches(self):
        fixed = _normalize_fixed_code("\n".join([f"line {i}" for i in range(9)]), "eval(user_input)")
        assert fixed is None

    def test_preserves_original_indent_when_llm_returns_flush_left(self):
        original = "    query = f\"SELECT * FROM users WHERE id = {user_id}\""
        fixed = _normalize_fixed_code("cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))", original)
        assert fixed == "    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"

    def test_preserves_relative_indent_across_multiline_patch(self):
        original = "    if user:\n        process(user)"
        llm_output = "if user is not None:\n    process(user)"
        fixed = _normalize_fixed_code(llm_output, original)
        assert fixed == "    if user is not None:\n        process(user)"

    def test_does_not_double_indent_when_llm_already_matches(self):
        original = "    query = f\"SELECT 1\""
        fixed = _normalize_fixed_code("    cursor.execute(\"SELECT 1\")", original)
        assert fixed == "    cursor.execute(\"SELECT 1\")"

    def test_rejects_blank_only_input(self):
        assert _normalize_fixed_code("   \n\t\n", "eval(x)") is None


class TestParseTriageResponse:
    def test_parses_valid_json(self):
        response = json.dumps([{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "Input is user-controlled",
            "adjusted_severity": None,
            "adjusted_confidence": None,
        }])
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "true_positive"

    def test_parses_markdown_fenced_json(self):
        response = '```json\n[{"fingerprint": "abc123", "verdict": "false_positive", "reasoning": "test"}]\n```'
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "false_positive"

    def test_rejects_unknown_fingerprints(self):
        response = json.dumps([{
            "fingerprint": "unknown",
            "verdict": "true_positive",
            "reasoning": "test",
        }])
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 0

    def test_rejects_invalid_verdicts(self):
        response = json.dumps([{
            "fingerprint": "abc123",
            "verdict": "maybe_vulnerable",
            "reasoning": "test",
        }])
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 0

    def test_preserves_fixed_code_until_finding_context_is_available(self):
        response = json.dumps([{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": "\n".join([
                "const text = String(req.query.id)",
                "if (!/^\\d+$/.test(text)) throw new Error('invalid id')",
                "const userId = Number(text)",
                "db.query(\"SELECT * FROM users WHERE id = ?\", [userId]);",
            ]),
        }])
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 1
        assert verdicts[0]["fixed_code"].startswith("const text = String")

    def test_accepts_alias_fields_from_model_response(self):
        response = json.dumps([{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploitScenario": "Attacker-controlled input reaches query construction.",
            "recommendation": "Use a parameterized query.",
            "remediationPatch": 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        }])
        verdicts = _parse_triage_response(response, {"abc123"})
        assert len(verdicts) == 1
        assert verdicts[0]["exploit_scenario"] == "Attacker-controlled input reaches query construction."
        assert verdicts[0]["remediation"] == "Use a parameterized query."
        assert verdicts[0]["fixed_code"] == 'db.query("SELECT * FROM users WHERE id = ?", [userId]);'

    def test_raises_on_invalid_json(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_triage_response("not json at all", {"abc123"})


class TestApplyVerdicts:
    def test_removes_false_positives(self):
        findings = [_make_finding()]
        verdicts = [{"fingerprint": "abc123", "verdict": "false_positive", "reasoning": "safe", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 0

    def test_boosts_true_positive_confidence(self):
        findings = [_make_finding(confidence=0.7, analysis_scope="taint-intraprocedural", evidence_details={"trace_steps": _strong_trace_steps()})]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.8

    def test_uses_smaller_confidence_boost_for_lightweight_evidence(self):
        findings = [_make_finding(confidence=0.7, analysis_scope="pattern", evidence_details={"trace_steps": _moderate_trace_steps()})]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.75

    def test_caps_confidence_boost_when_sanitizer_signal_exists(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={"sanitizer_exprs": ["path.basename"], "trace_steps": _strong_trace_steps()},
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.75

    def test_uses_smaller_boost_for_present_but_insufficient_sanitizer(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "sanitizer_exprs": ["path.basename(file)"],
                "sanitizer_status": "present-but-insufficient",
                "trace_steps": _strong_trace_steps(),
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.73

    def test_removes_boost_for_validated_sanitizer(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "sanitizer_exprs": ["ensureRelativeRedirect(nextUrl)"],
                "sanitizer_status": "validated",
                "trace_steps": _strong_trace_steps(),
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.7

    def test_adjusts_severity(self):
        findings = [_make_finding(severity="high")]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "worse than thought", "adjusted_severity": "critical", "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert result[0]["severity"] == "critical"

    def test_applies_adjusted_confidence(self):
        findings = [_make_finding(confidence=0.7)]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": 0.95}]
        result = _apply_verdicts(findings, verdicts)
        assert result[0]["confidence"] == 0.95

    def test_leaves_uncertain_unchanged(self):
        findings = [_make_finding(confidence=0.7, severity="high", analysis_scope="taint-intraprocedural", evidence_details={"trace_steps": _strong_trace_steps()})]
        verdicts = [{"fingerprint": "abc123", "verdict": "uncertain", "reasoning": "unclear", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.7
        assert result[0]["severity"] == "high"

    def test_untriaged_findings_pass_through(self):
        findings = [
            _make_finding(fingerprint="triaged"),
            _make_finding(fingerprint="not_triaged"),
        ]
        verdicts = [{"fingerprint": "triaged", "verdict": "false_positive", "reasoning": "safe", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["fingerprint"] == "not_triaged"

    def test_adds_llm_triage_metadata(self):
        findings = [_make_finding(evidence_details={
            "trace_steps": _moderate_trace_steps(),
            "fix_scope": "line",
            "missing_control_type": "output_encoding",
            "auto_fix_eligible": True,
        })]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "user input flows to query", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert "llm_triage" in result[0]
        assert result[0]["llm_triage"]["verdict"] == "true_positive"
        assert "user input" in result[0]["llm_triage"]["reasoning"]
        assert result[0]["llm_triage"]["evidence_strength"] == "light"
        assert result[0]["llm_triage"]["reviewability"] == "changed-lines-only"
        assert result[0]["llm_triage"]["has_sanitizer_signal"] is False
        assert result[0]["llm_triage"]["fix_scope"] == "line"
        assert result[0]["llm_triage"]["missing_control_type"] == "output_encoding"
        assert result[0]["llm_triage"]["auto_fix_eligible"] is True

    def test_dampens_confidence_boost_for_context_only_findings(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "reviewability": "context-only",
                "trace_steps": [
                    {"kind": "source", "expr": "req.query.file"},
                    {"kind": "assignment", "expr": "const file = req.query.file"},
                    {"kind": "sink", "expr": "fs.readFile(file)"},
                ],
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed by trace", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.72

    def test_removes_confidence_boost_for_context_only_findings_with_sanitizer_signal(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "reviewability": "context-only",
                "sanitizer_exprs": ["path.basename"],
                "trace_steps": [
                    {"kind": "source", "expr": "req.query.file"},
                    {"kind": "assignment", "expr": "const file = req.query.file"},
                    {"kind": "sanitizer", "expr": "path.basename(file)", "status": "present-but-insufficient"},
                    {"kind": "sink", "expr": "fs.readFile(file)"},
                ],
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed by trace", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.7

    def test_uses_moderate_trace_to_limit_confidence_boost(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "trace_steps": [
                    {"kind": "source", "expr": "req.query.url"},
                    {"kind": "sink", "expr": "res.redirect(req.query.url)"},
                ]
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.75

    def test_uses_weak_trace_to_prevent_automatic_confidence_boost(self):
        findings = [_make_finding(
            confidence=0.7,
            analysis_scope="taint-intraprocedural",
            evidence_details={
                "trace_steps": [
                    {"kind": "source", "expr": "req.query.name"},
                ]
            },
        )]
        verdicts = [{"fingerprint": "abc123", "verdict": "true_positive", "reasoning": "confirmed", "adjusted_severity": None, "adjusted_confidence": None}]
        result = _apply_verdicts(findings, verdicts)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.7

    def test_applies_inline_fix_patch_for_true_positive(self):
        findings = [_make_finding(evidence_details={
            "trace_steps": _moderate_trace_steps(),
            "auto_fix_eligible": True,
            "fix_scope": "line",
            "missing_control_type": "output_encoding",
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        }]
        result = _apply_verdicts(findings, verdicts)
        assert result[0]["remediation_patch"] == 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'

    def test_skips_inline_fix_patch_when_auto_fix_is_not_eligible(self):
        findings = [_make_finding(evidence_details={
            "trace_steps": _strong_trace_steps(),
            "auto_fix_eligible": False,
            "fix_scope": "line",
            "missing_control_type": "base_dir_validation",
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": 'safeOpen(resolveWithinBaseDir(req.query.file))',
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "remediation_patch" not in result[0]

    def test_skips_inline_fix_patch_for_context_only_true_positive(self):
        findings = [_make_finding(evidence_details={
            "reviewability": "context-only",
            "auto_fix_eligible": True,
            "trace_steps": [
                {"kind": "source", "expr": "req.query.file"},
                {"kind": "assignment", "expr": "const file = req.query.file"},
                {"kind": "sink", "expr": "fs.readFile(file)"},
            ],
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "remediation_patch" not in result[0]

    def test_skips_inline_fix_patch_for_weak_trace_true_positive(self):
        findings = [_make_finding(evidence_details={
            "auto_fix_eligible": True,
            "trace_steps": [
                {"kind": "source", "expr": "req.query.url"},
            ],
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": 'res.redirect(ensureRelativeRedirect(req.query.url))',
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "remediation_patch" not in result[0]

    def test_skips_inline_fix_patch_for_validated_sanitizer(self):
        findings = [_make_finding(evidence_details={
            "auto_fix_eligible": True,
            "sanitizer_exprs": ["ensureRelativeRedirect(nextUrl)"],
            "sanitizer_status": "validated",
            "trace_steps": _strong_trace_steps(),
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": 'res.redirect(ensureRelativeRedirect(req.query.next))',
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "remediation_patch" not in result[0]

    def test_normalizes_fixed_code_using_real_snippet_context(self):
        findings = [_make_finding(code_snippet="\n".join([
            'const text = String(req.query.id)',
            'const userId = Number(text)',
            'db.query("SELECT * FROM users WHERE id = " + userId);',
        ]), evidence_details={
            "trace_steps": _strong_trace_steps(),
            "auto_fix_eligible": True,
            "fix_scope": "block",
            "missing_control_type": "output_encoding",
        })]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": "\n".join([
                'const text = String(req.query.id)',
                "if (!/^\\d+$/.test(text)) throw new Error('invalid id')",
                'const userId = Number(text)',
                'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
            ]),
        }]
        result = _apply_verdicts(findings, verdicts)
        assert result[0]["remediation_patch"].endswith('[userId]);')

    def test_skips_fallback_fix_when_sanitizer_signal_exists(self):
        findings = [_make_finding(
            file_path="app.js",
            code_snippet='db.query("SELECT * FROM users WHERE id = " + userId);',
            evidence_details={"sanitizer_exprs": ["validateUserId"], "auto_fix_eligible": True},
        )]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "fixed_code": None,
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "remediation_patch" not in result[0]

    def test_uses_missing_control_specific_fallback_remediation(self):
        findings = [_make_finding(
            remediation="",
            category="path traversal",
            cwe_id="CWE-22",
            evidence_details={
                "missing_control_type": "base_dir_validation",
                "auto_fix_eligible": False,
            },
        )]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "remediation": None,
            "fixed_code": None,
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "fixed base directory" in result[0]["remediation"]

    def test_backfills_exploit_scenario_when_missing(self):
        findings = [_make_finding(exploit_scenario="", remediation="")]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploit_scenario": None,
            "remediation": None,
            "fixed_code": None,
        }]
        result = _apply_verdicts(findings, verdicts)
        assert "alter the SQL query" in result[0]["exploit_scenario"]
        assert "parameterized queries" in result[0]["remediation"]

    def test_applies_model_exploit_scenario_and_remediation(self):
        findings = [_make_finding(exploit_scenario="", remediation="")]
        verdicts = [{
            "fingerprint": "abc123",
            "verdict": "true_positive",
            "reasoning": "confirmed",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploit_scenario": "An attacker can tamper with the query to access unauthorized rows.",
            "remediation": "Bind the identifier as a query parameter.",
            "fixed_code": None,
        }]
        result = _apply_verdicts(findings, verdicts)
        assert result[0]["exploit_scenario"] == "An attacker can tamper with the query to access unauthorized rows."
        assert result[0]["remediation"] == "Bind the identifier as a query parameter."


class TestTriageFindings:
    def test_returns_unchanged_when_disabled(self):
        findings = [_make_finding()]
        with patch.dict(os.environ, {}, clear=True):
            result = triage_findings(findings, {})
        assert result == findings

    def test_returns_empty_for_empty_findings(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings([], {})
        assert result == []

    @patch("llm_triage._call_triage_llm")
    def test_returns_original_on_api_error(self, mock_call):
        mock_call.side_effect = Exception("API down")
        findings = [_make_finding()]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {})
        assert result == findings

    @patch("llm_triage._call_triage_llm")
    def test_returns_original_on_bad_json(self, mock_call):
        mock_call.return_value = ("not valid json", 100, 50)
        findings = [_make_finding()]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {})
        assert result == findings

    @patch("llm_triage._call_triage_llm")
    def test_filters_false_positives_end_to_end(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "false_positive",
                "reasoning": "Input is from trusted internal service",
                "adjusted_severity": None,
                "adjusted_confidence": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding()]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.py": "+code here"})
        assert len(result) == 0

    @patch("llm_triage._call_triage_llm")
    def test_keeps_true_positives_with_boost(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "User input directly concatenated",
                "adjusted_severity": "critical",
                "adjusted_confidence": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            confidence=0.7,
            severity="high",
            analysis_scope="taint-intraprocedural",
            evidence_details={"trace_steps": _strong_trace_steps()},
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.py": "+code"})
        assert len(result) == 1
        assert result[0]["confidence"] == 0.8
        assert result[0]["severity"] == "critical"
        assert result[0]["llm_triage"]["verdict"] == "true_positive"

    @patch("llm_triage._call_triage_llm")
    def test_keeps_llm_generated_fix_patch_end_to_end(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "User input directly concatenated",
                "adjusted_severity": None,
                "adjusted_confidence": 0.91,
                "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            }]),
            500,
            200,
        )
        findings = [_make_finding(evidence_details={
            "trace_steps": _moderate_trace_steps(),
            "auto_fix_eligible": True,
            "fix_scope": "line",
            "missing_control_type": "output_encoding",
        })]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.py": "+cursor.execute(query)\n"})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'

    @patch("llm_triage._call_triage_llm")
    def test_generates_fallback_sql_fix_when_model_omits_fixed_code(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "User input directly concatenated",
                "adjusted_severity": None,
                "adjusted_confidence": 0.91,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            file_path="app.js",
            code_snippet='db.query("SELECT * FROM users WHERE id = " + userId);',
            evidence_details={
                "trace_steps": _moderate_trace_steps(),
                "auto_fix_eligible": True,
                "fix_scope": "line",
                "missing_control_type": "output_encoding",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.js": '+db.query("SELECT * FROM users WHERE id = " + userId);\n'})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == 'db.query("SELECT * FROM users WHERE id = ?", [userId]);'

    @patch("llm_triage._call_triage_llm")
    def test_generates_fallback_secret_fix_when_model_omits_fixed_code(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "Hardcoded secret confirmed",
                "adjusted_severity": None,
                "adjusted_confidence": None,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            rule_id="secret.hardcoded.credential",
            title="Hardcoded secret or credential",
            category="hardcoded secrets",
            cwe_id="CWE-798",
            file_path="config.js",
            code_snippet='const apiKey = "sk_live_1234567890abcdef";',
            evidence_details={
                "trace_steps": _moderate_trace_steps(),
                "auto_fix_eligible": True,
                "fix_scope": "line",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"config.js": '+const apiKey = "sk_live_1234567890abcdef";\n'})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == "const apiKey = process.env.API_KEY;"

    @patch("llm_triage._call_triage_llm")
    def test_generates_fallback_eval_fix_when_model_omits_fixed_code(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "eval executes attacker input",
                "adjusted_severity": None,
                "adjusted_confidence": None,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            rule_id="code.injection.eval",
            title="Code injection via eval",
            category="code injection",
            cwe_id="CWE-94",
            file_path="app.js",
            code_snippet="eval(req.body.code);",
            evidence_details={
                "trace_steps": _moderate_trace_steps(),
                "auto_fix_eligible": True,
                "fix_scope": "line",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.js": "+eval(req.body.code);\n"})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == "JSON.parse(req.body.code);"

    @patch("llm_triage._call_triage_llm")
    def test_generates_fallback_exec_fix_when_model_omits_fixed_code(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "command execution from request input",
                "adjusted_severity": None,
                "adjusted_confidence": None,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            rule_id="code.injection.exec",
            title="Command injection via exec",
            category="code injection",
            cwe_id="CWE-78",
            file_path="app.js",
            code_snippet="exec(req.query.cmd);",
            evidence_details={
                "trace_steps": _moderate_trace_steps(),
                "auto_fix_eligible": True,
                "fix_scope": "line",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.js": "+exec(req.query.cmd);\n"})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == 'return res.status(400).json({ error: "Refusing to execute user-controlled commands" });'

    @patch("llm_triage._call_triage_llm")
    def test_generates_fallback_xss_fix_when_model_omits_fixed_code(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "unsafe HTML rendering",
                "adjusted_severity": None,
                "adjusted_confidence": None,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            rule_id="xss.unsafe_html_render",
            title="Potential XSS through unsafe HTML rendering",
            category="cross-site scripting (xss)",
            cwe_id="CWE-79",
            file_path="app.js",
            code_snippet="element.innerHTML = req.query.name;",
            evidence_details={
                "trace_steps": _moderate_trace_steps(),
                "auto_fix_eligible": True,
                "fix_scope": "line",
                "missing_control_type": "html_sanitization_or_safe_text_rendering",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"app.js": "+element.innerHTML = req.query.name;\n"})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == "element.textContent = req.query.name;"

    @patch("llm_triage._call_triage_llm")
    def test_keeps_safe_deterministic_secret_fix_patch_without_trace_metadata(self, mock_call):
        mock_call.return_value = (
            json.dumps([{
                "fingerprint": "abc123",
                "verdict": "true_positive",
                "reasoning": "The credential is hardcoded and should be externalized.",
                "adjusted_severity": None,
                "adjusted_confidence": 0.93,
                "fixed_code": None,
            }]),
            500,
            200,
        )
        findings = [_make_finding(
            rule_id="secret.hardcoded.credential",
            title="Hardcoded secret or credential",
            category="hardcoded secrets",
            cwe_id="CWE-798",
            file_path="config.js",
            code_snippet='const apiKey = "sk_live_1234567890abcdef";',
            remediation_patch="const apiKey = process.env.API_KEY;",
            evidence_details={
                "analysis_scope": "pattern",
                "reviewability": "changed-lines-only",
                "auto_fix_eligible": True,
                "fix_scope": "line",
                "fix_target_line": 1,
                "fix_target_expr": 'const apiKey = "sk_live_1234567890abcdef";',
                "missing_control_type": "secret_manager_or_environment_variable",
            },
        )]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            result = triage_findings(findings, {"config.js": '+const apiKey = "sk_live_1234567890abcdef";\n'})
        assert len(result) == 1
        assert result[0]["remediation_patch"] == "const apiKey = process.env.API_KEY;"


def test_triage_failure_log_redacts_key_in_url(capsys):
    leaky = (
        "Client error '404 Not Found' for url "
        "'https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:generateContent?key=AIzaSyFAKEKEYVALUE123456'"
    )
    findings = [_make_finding()]

    with patch.dict("os.environ", {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "AIzaSyFAKEKEYVALUE123456"}, clear=True):
        with patch("llm_triage._call_triage_llm", side_effect=RuntimeError(leaky)):
            result = triage_findings(findings, {}, None)

    assert result == findings
    captured = capsys.readouterr().out
    assert "LLM triage failed (non-blocking)" in captured
    assert "AIzaSyFAKEKEYVALUE123456" not in captured
    assert "key=[REDACTED]" in captured
