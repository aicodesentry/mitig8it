"""Tests for OpenGrep runner integration."""

import subprocess
import shutil
import pytest
from pathlib import Path
from opengrep_runner import (
    _classify_sanitizer_status,
    _enrich_metadata_from_match,
    _infer_local_propagation_kind,
    _is_runtime_scannable_path,
    _normalize_trace_step,
    run_opengrep,
    _build_trace_steps,
    _extract_exact_lines,
    _extract_file_content,
    _extract_scan_content,
    make_fingerprint,
    RULES_DIR,
)


def _can_run_opengrep() -> bool:
    opengrep_path = shutil.which("semgrep")
    if not opengrep_path:
        return False
    try:
        result = subprocess.run(
            [opengrep_path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return result.returncode == 0


HAS_OPENGREP = _can_run_opengrep()
skip_no_opengrep = pytest.mark.skipif(
    not HAS_OPENGREP,
    reason="OpenGrep not available or TLS trust anchors missing",
)


def _find(rule_id):
    from security_rules import SECURITY_RULES

    return next(r for r in SECURITY_RULES if r.rule_id == rule_id)


class TestExtractFileContent:
    def test_extracts_added_lines(self):
        patch = "@@ -0,0 +1,3 @@\n+line1\n+line2\n+line3"
        assert _extract_file_content(patch) == "line1\nline2\nline3"

    def test_skips_removed_lines(self):
        patch = "@@ -1,2 +1,2 @@\n-old\n+new"
        assert "old" not in _extract_file_content(patch)
        assert "new" in _extract_file_content(patch)

    def test_empty_patch(self):
        assert _extract_file_content("") == ""

    def test_skips_transcript_artifact_lines(self):
        patch = "\n".join(
            [
                "@@ -1,2 +1,3 @@",
                '+    218 +        patch = "+API_KEY = \'sk_live_1234567890abcdef\'"',
                '+api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"',
            ]
        )
        assert _extract_file_content(patch) == 'api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'

    def test_prefers_full_file_content_when_available(self):
        file_info = {
            "path": "handler.js",
            "patch": "@@ -0,0 +1 @@\n+eval(req.body.code)",
            "content": "const value = req.body.code;\neval(value);\n",
        }
        assert _extract_scan_content(file_info) == "const value = req.body.code;\neval(value);\n"

    def test_wraps_patch_only_go_fragments_into_parseable_file(self):
        file_info = {
            "path": "download.go",
            "patch": '+data, _ := os.ReadFile(filepath.Join(baseDir, r.URL.Query().Get("file")))',
        }
        content = _extract_scan_content(file_info)
        assert content.startswith("package main")
        assert 'func _generated(r *http.Request)' in content
        assert 'os.ReadFile(filepath.Join(baseDir, r.URL.Query().Get("file")))' in content

    def test_extract_exact_lines_returns_only_target_range(self):
        content = "\n".join([
            "const a = 1;",
            "exec(req.query.cmd);",
            "document.innerHTML = req.query.name;",
        ])
        assert _extract_exact_lines(content, 2, 2) == "exec(req.query.cmd);"


class TestMakeFingerprint:
    def test_deterministic(self):
        fp1 = make_fingerprint("rule1", "file.py", 10, "code")
        fp2 = make_fingerprint("rule1", "file.py", 10, "code")
        assert fp1 == fp2

    def test_different_inputs(self):
        fp1 = make_fingerprint("rule1", "file.py", 10, "code")
        fp2 = make_fingerprint("rule2", "file.py", 10, "code")
        assert fp1 != fp2


class TestRuntimeScannablePaths:
    def test_accepts_runtime_source_files(self):
        assert _is_runtime_scannable_path("src/routes/download.js") is True

    def test_rejects_test_fixture_paths(self):
        assert _is_runtime_scannable_path("services/analysis-service/src/tests/test_llm_triage.py") is False
        assert _is_runtime_scannable_path("services/api-service/tests/orchestrator.test.js") is False
        assert _is_runtime_scannable_path("frontend/src/pages/__tests__/RepositoriesPage.test.jsx") is False
        assert _is_runtime_scannable_path("test_vuln.js") is False
        assert _is_runtime_scannable_path("fixtures/test_vuln.tsx") is False

    def test_rejects_rule_definition_paths(self):
        assert _is_runtime_scannable_path("services/analysis-service/src/opengrep_rules/javascript.yml") is False


class TestTraceSteps:
    def test_normalizes_trace_step_to_language_agnostic_shape(self):
        step = _normalize_trace_step(
            {"kind": "Assignment", "expr": "const file = req.query.file", "line": "12"},
            "download.js",
        )
        assert step == {
            "kind": "assignment",
            "label": "assignment",
            "expr": "const file = req.query.file",
            "file": "download.js",
            "line": 12,
        }

    def test_rejects_language_specific_trace_step_kind(self):
        step = _normalize_trace_step(
            {"kind": "member_expression", "expr": "req.query.file", "line": 12},
            "download.js",
        )
        assert step is None

    def test_builds_taint_trace_steps_from_metadata(self):
        steps = _build_trace_steps(
            {
                "analysis_scope": "taint-intraprocedural",
                "source_description": "request-controlled file path",
                "source_expr": "req.query.file",
                "sink_description": "filesystem access",
                "sink_expr": "fs.readFile(file)",
                "sanitizers_seen": ["path.basename(file)"],
                "sanitizer_status": "present-but-insufficient",
                "propagation_steps": [
                    {"kind": "assignment", "expr": "const file = req.query.file", "line": 12},
                ],
                "source_line": 12,
                "sink_line": 18,
            },
            file_path="download.js",
            line_start=18,
            line_end=18,
            code_snippet="fs.readFile(file)",
        )
        assert [step["kind"] for step in steps] == ["source", "assignment", "sanitizer", "sink"]
        assert steps[0]["expr"] == "req.query.file"
        assert steps[0]["line"] == 12
        assert steps[1]["expr"] == "const file = req.query.file"
        assert steps[2]["status"] == "present-but-insufficient"
        assert steps[3]["expr"] == "fs.readFile(file)"
        assert steps[3]["line"] == 18

    def test_returns_empty_trace_steps_for_pattern_findings(self):
        steps = _build_trace_steps(
            {"analysis_scope": "pattern"},
            file_path="app.js",
            line_start=10,
            line_end=10,
            code_snippet="eval(input)",
        )
        assert steps == []

    def test_preserves_prebuilt_trace_steps_when_present(self):
        prebuilt = [{"kind": "source", "expr": "req.query.url", "file": "handler.js", "line": 4}]
        steps = _build_trace_steps(
            {"analysis_scope": "taint-intraprocedural", "trace_steps": prebuilt},
            file_path="handler.js",
            line_start=10,
            line_end=10,
            code_snippet="fetch(url)",
        )
        assert steps == [{"kind": "source", "label": "source", "expr": "req.query.url", "file": "handler.js", "line": 4}]

    def test_filters_invalid_prebuilt_trace_steps(self):
        steps = _build_trace_steps(
            {
                "analysis_scope": "taint-intraprocedural",
                "trace_steps": [
                    {"kind": "source", "expr": "req.query.url", "file": "handler.js", "line": 4},
                    {"kind": "identifier_reference", "expr": "url", "file": "handler.js", "line": 5},
                ],
            },
            file_path="handler.js",
            line_start=10,
            line_end=10,
            code_snippet="fetch(url)",
        )
        assert steps == [{"kind": "source", "expr": "req.query.url", "file": "handler.js", "line": 4, "label": "source"}]


class TestMatchMetadataEnrichment:
    def test_classifies_path_traversal_basename_as_present_but_insufficient(self):
        assert _classify_sanitizer_status({
            "category": "path traversal",
            "sanitizers_seen": ["path.basename(file)"],
        }) == "present-but-insufficient"

    def test_classifies_open_redirect_relative_helper_as_validated(self):
        assert _classify_sanitizer_status({
            "category": "open redirect",
            "sanitizers_seen": ["ensureRelativeRedirect(nextUrl)"],
        }) == "validated"

    def test_classifies_ssrf_allowlist_helper_as_validated(self):
        assert _classify_sanitizer_status({
            "category": "SSRF",
            "sanitizers_seen": ["allowlistedUrl(target)"],
        }) == "validated"

    def test_classifies_xss_dompurify_as_validated(self):
        assert _classify_sanitizer_status({
            "category": "XSS",
            "sanitizers_seen": ["DOMPurify.sanitize(name)"],
        }) == "validated"

    def test_classifies_unknown_sanitizer_as_present(self):
        assert _classify_sanitizer_status({
            "category": "path traversal",
            "sanitizers_seen": ["safeWrapper(file)"],
        }) == "present"

    def test_enriches_fix_metadata_for_path_traversal(self):
        metadata = {
            "analysis_scope": "taint-intraprocedural",
            "category": "path traversal",
            "source_description": "request-controlled file path",
            "sink_description": "filesystem access",
            "source_var": "$INPUT",
            "sink_var": "$PATH",
        }
        match = {
            "extra": {
                "metavars": {
                    "$INPUT": {
                        "abstract_content": "req.query.file",
                        "start": {"line": 2},
                    },
                    "$PATH": {
                        "abstract_content": "file",
                        "start": {"line": 3},
                    },
                }
            }
        }
        content = "\n".join([
            "const path = require('path')",
            "const file = req.query.file",
            "fs.readFile(file, () => {})",
        ])
        enriched = _enrich_metadata_from_match(
            metadata,
            match,
            file_path="download.js",
            file_content=content,
            line_start=3,
            code_snippet="fs.readFile(file, () => {})",
        )
        assert enriched["missing_control_type"] == "base_dir_validation"
        assert enriched["fix_target_line"] == 3
        assert enriched["fix_target_expr"] == "fs.readFile(file, () => {})"
        assert enriched["fix_scope"] == "line"
        assert enriched["auto_fix_eligible"] is True

    def test_marks_validated_sanitizer_as_not_auto_fix_eligible(self):
        metadata = {
            "analysis_scope": "taint-intraprocedural",
            "category": "open redirect",
            "source_description": "request-controlled redirect target",
            "sink_description": "HTTP redirect",
            "source_var": "$URL",
            "sink_var": "$URL",
            "sanitizers_seen": ["ensureRelativeRedirect(nextUrl)"],
        }
        match = {
            "extra": {
                "metavars": {
                    "$URL": {
                        "abstract_content": "nextUrl",
                        "start": {"line": 5},
                    },
                }
            }
        }
        enriched = _enrich_metadata_from_match(
            metadata,
            match,
            file_path="handler.js",
            file_content="res.redirect(nextUrl)\n",
            line_start=5,
            code_snippet="res.redirect(nextUrl)",
        )
        assert enriched["sanitizer_status"] == "validated"
        assert enriched["missing_control_type"] == "relative_or_allowlisted_redirect_validation"
        assert enriched["auto_fix_eligible"] is False

    def test_infers_call_propagation_for_wrapper_assignment(self):
        assert _infer_local_propagation_kind(
            "const file = path.basename(req.query.file)",
            "req.query.file",
        ) == "call"

    def test_infers_assignment_propagation_for_direct_copy(self):
        assert _infer_local_propagation_kind(
            "const file = req.query.file",
            "req.query.file",
        ) == "assignment"

    def test_enriches_metadata_from_metavars(self):
        metadata = {
            "analysis_scope": "taint-intraprocedural",
            "source_description": "request-controlled file path",
            "sink_description": "filesystem access",
            "source_var": "$INPUT",
            "sink_var": "$PATH",
        }
        match = {
            "extra": {
                "metavars": {
                    "$INPUT": {
                        "abstract_content": "req.query.file",
                        "start": {"line": 2},
                    },
                    "$PATH": {
                        "abstract_content": "file",
                        "start": {"line": 3},
                    },
                }
            }
        }
        content = "\n".join([
            "const child_process = require('child_process')",
            "const file = req.query.file",
            "fs.readFile(file, () => {})",
        ])
        enriched = _enrich_metadata_from_match(
            metadata,
            match,
            file_path="download.js",
            file_content=content,
            line_start=3,
            code_snippet="fs.readFile(file, () => {})",
        )
        assert enriched["source_expr"] == "req.query.file"
        assert enriched["source_line"] == 2
        assert enriched["sink_expr"] == "fs.readFile(file, () => {})"
        assert enriched["sink_line"] == 3
        assert enriched["sink_arg_expr"] == "file"
        assert enriched["propagation_steps"][0]["kind"] == "assignment"
        assert enriched["propagation_steps"][0]["expr"] == "const file = req.query.file"

    def test_marks_wrapper_assignment_as_call_propagation(self):
        metadata = {
            "analysis_scope": "taint-intraprocedural",
            "source_description": "request-controlled file path",
            "sink_description": "filesystem access",
            "source_var": "$INPUT",
            "sink_var": "$PATH",
        }
        match = {
            "extra": {
                "metavars": {
                    "$INPUT": {
                        "abstract_content": "req.query.file",
                        "start": {"line": 2},
                    },
                    "$PATH": {
                        "abstract_content": "file",
                        "start": {"line": 3},
                    },
                }
            }
        }
        content = "\n".join([
            "const path = require('path')",
            "const file = path.basename(req.query.file)",
            "fs.readFile(file, () => {})",
        ])
        enriched = _enrich_metadata_from_match(
            metadata,
            match,
            file_path="download.js",
            file_content=content,
            line_start=3,
            code_snippet="fs.readFile(file, () => {})",
        )
        assert enriched["propagation_steps"][0]["kind"] == "call"
        assert enriched["propagation_steps"][0]["expr"] == "const file = path.basename(req.query.file)"

    def test_does_not_add_propagation_step_when_source_is_on_sink_line(self):
        metadata = {
            "analysis_scope": "taint-intraprocedural",
            "source_var": "$URL",
            "sink_var": "$URL",
        }
        match = {
            "extra": {
                "metavars": {
                    "$URL": {
                        "abstract_content": "req.query.url",
                        "start": {"line": 5},
                    },
                }
            }
        }
        enriched = _enrich_metadata_from_match(
            metadata,
            match,
            file_path="handler.js",
            file_content="axios.get(req.query.url)\n",
            line_start=5,
            code_snippet="axios.get(req.query.url)",
        )
        assert enriched["source_expr"] == "req.query.url"
        assert "propagation_steps" not in enriched


class TestRunOpenGrep:
    def test_returns_list(self):
        result = run_opengrep([])
        assert isinstance(result, list)

    def test_skips_unsupported_extensions(self):
        files = [{"path": "readme.md", "patch": "+# Hello"}]
        assert run_opengrep(files) == []

    def test_scans_test_files_as_informational_and_skips_rule_files(self):
        files = [
            {"path": "services/analysis-service/src/tests/test_llm_triage.py", "patch": "+eval(req.body.code)\n"},
            {"path": "services/api-service/tests/orchestrator.test.js", "patch": '+db.query("SELECT * FROM users WHERE id = " + userId);\n'},
            {"path": "test_vuln.js", "patch": "+eval(req.body.code)\n"},
            {"path": "services/analysis-service/src/opengrep_rules/javascript.yml", "patch": "+- pattern: $EL.innerHTML = $INPUT\n"},
        ]
        result = run_opengrep(files)

        assert result, "test-code findings must be reported, not dropped"
        assert all(finding["in_test_code"] is True for finding in result)
        assert all(finding["severity"] == "info" for finding in result)
        assert all(finding["original_severity"] != "info" for finding in result)
        # Scanner rule assets are still never analyzed.
        assert all("opengrep_rules/" not in finding["file_path"] for finding in result)

    def test_handles_no_findings_gracefully(self):
        files = [{"path": "clean.py", "patch": "+x = 1\n+y = 2"}]
        assert isinstance(run_opengrep(files), list)

    @skip_no_opengrep
    def test_detects_pickle_loads(self):
        files = [{"path": "app.py", "patch": "+import pickle\n+data = pickle.loads(user_input)"}]
        result = run_opengrep(files)
        assert any("pickle" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_eval_with_user_input(self):
        files = [{"path": "handler.js", "patch": "+const result = eval(req.body.code)"}]
        result = run_opengrep(files)
        assert any("eval" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_path_traversal_via_sendfile_join(self):
        files = [{
            "path": "download.js",
            "patch": "+res.sendFile(path.join(baseDir, req.query.file))"
        }]
        result = run_opengrep(files)
        assert any("path-traversal" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_path_traversal_when_request_value_is_assigned_first(self):
        files = [{
            "path": "download.js",
            "patch": "\n".join([
                "+const file = req.query.file",
                "+fs.readFile(file, () => {})",
            ]),
        }]
        result = run_opengrep(files)
        assert any("path-traversal" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_command_injection_when_request_value_is_assigned_first(self):
        files = [{
            "path": "handler.js",
            "content": "\n".join([
                "const child_process = require('child_process')",
                "const cmd = req.query.cmd",
                "child_process.exec(cmd)",
            ]),
            "patch": "@@ -0,0 +1,3 @@\n+const child_process = require('child_process')\n+const cmd = req.query.cmd\n+child_process.exec(cmd)",
        }]
        result = run_opengrep(files)
        assert any("child-process-exec" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_ssrf_when_request_value_is_assigned_first(self):
        files = [{
            "path": "handler.js",
            "content": "\n".join([
                "const axios = require('axios')",
                "const target = req.query.url",
                "axios.get(target)",
            ]),
            "patch": "@@ -0,0 +1,3 @@\n+const axios = require('axios')\n+const target = req.query.url\n+axios.get(target)",
        }]
        result = run_opengrep(files)
        assert any("ssrf-axios" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_open_redirect_when_request_value_is_assigned_first(self):
        files = [{
            "path": "handler.js",
            "content": "\n".join([
                "const nextUrl = req.query.next",
                "res.redirect(nextUrl)",
            ]),
            "patch": "@@ -0,0 +1,2 @@\n+const nextUrl = req.query.next\n+res.redirect(nextUrl)",
        }]
        result = run_opengrep(files)
        assert any("open-redirect" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_javascript_xss_when_request_value_is_assigned_first(self):
        files = [{
            "path": "handler.js",
            "content": "\n".join([
                "const name = req.query.name",
                "el.innerHTML = name",
            ]),
            "patch": "@@ -0,0 +1,2 @@\n+const name = req.query.name\n+el.innerHTML = name",
        }]
        result = run_opengrep(files)
        assert any("xss-innerhtml" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_go_path_traversal_via_readfile_join(self):
        files = [{
            "path": "download.go",
            "patch": "+data, _ := os.ReadFile(filepath.Join(baseDir, r.URL.Query().Get(\"file\")))"
        }]
        result = run_opengrep(files)
        assert any("go-path-traversal" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_go_path_traversal_when_query_value_is_assigned_first(self):
        files = [{
            "path": "download.go",
            "patch": "\n".join([
                "+name := r.URL.Query().Get(\"file\")",
                "+data, _ := os.ReadFile(name)",
            ]),
        }]
        result = run_opengrep(files)
        assert any("go-path-traversal" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_go_command_injection_when_request_value_is_assigned_first(self):
        files = [{
            "path": "run.go",
            "content": "\n".join([
                "package main",
                "import \"os/exec\"",
                "func run(r *Request) {",
                "  cmd := r.URL.Query().Get(\"cmd\")",
                "  exec.Command(\"sh\", \"-c\", cmd)",
                "}",
            ]),
            "patch": "\n".join([
                "@@ -0,0 +1,6 @@",
                "+package main",
                "+import \"os/exec\"",
                "+func run(r *Request) {",
                "+  cmd := r.URL.Query().Get(\"cmd\")",
                "+  exec.Command(\"sh\", \"-c\", cmd)",
                "+}",
            ]),
        }]
        result = run_opengrep(files)
        assert any("go-exec-command" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_detects_go_xss_when_request_value_is_assigned_first(self):
        files = [{
            "path": "render.go",
            "content": "\n".join([
                "package main",
                "import \"fmt\"",
                "func render(w Writer, r *Request) {",
                "  name := r.URL.Query().Get(\"name\")",
                "  fmt.Fprintf(w, \"%s\", name)",
                "}",
            ]),
            "patch": "\n".join([
                "@@ -0,0 +1,6 @@",
                "+package main",
                "+import \"fmt\"",
                "+func render(w Writer, r *Request) {",
                "+  name := r.URL.Query().Get(\"name\")",
                "+  fmt.Fprintf(w, \"%s\", name)",
                "+}",
            ]),
        }]
        result = run_opengrep(files)
        assert any("go-template-html" in f["rule_id"] for f in result)

    @skip_no_opengrep
    def test_finding_has_required_fields(self):
        files = [{"path": "vuln.py", "patch": "+import pickle\n+obj = pickle.loads(raw_data)"}]
        result = run_opengrep(files)
        assert len(result) > 0
        f = result[0]
        for key in ("rule_id", "fingerprint", "severity", "file_path", "line_start",
                     "title", "category", "cwe_id", "confidence"):
            assert key in f, f"Missing key: {key}"
        assert f["rule_id"].startswith("opengrep.")
        assert f["severity"] in ("critical", "high", "medium", "low")

    @skip_no_opengrep
    def test_detects_csharp_binary_formatter(self):
        files = [{
            "path": "app.cs",
            "patch": "+var secret = new BinaryFormatter().Deserialize(stream);"
        }]
        result = run_opengrep(files)
        assert any("csharp-deserialization" in f["rule_id"] for f in result), "C# BinaryFormatter pattern should trigger"

    def test_tier1_catches_generic_deserialize(self):
        """Generic Deserialize<T> can't be parsed by OpenGrep C# — Tier 1 regex covers it."""
        rule = _find("deserialize.untrusted_data")
        assert rule.pattern.search("new JavaScriptSerializer().Deserialize<object>(input)")


# ── Rule YAML validation ────────────────────────────────────────────────

class TestRuleYAMLValidity:
    """Verify all OpenGrep rule files have valid structure."""

    @pytest.fixture
    def rule_files(self):
        return list(RULES_DIR.glob("*.yml"))

    def test_rules_directory_exists(self):
        assert RULES_DIR.exists()

    def test_rule_files_exist(self, rule_files):
        assert len(rule_files) > 0, "No OpenGrep rule files found"

    def test_rule_files_contain_rules_key(self, rule_files):
        for f in rule_files:
            text = f.read_text()
            assert "rules:" in text, f"{f.name} missing 'rules:' key"

    def test_rule_files_have_ids(self, rule_files):
        import re
        for f in rule_files:
            text = f.read_text()
            ids = re.findall(r"^\s+- id:\s+(.+)$", text, re.MULTILINE)
            assert len(ids) > 0, f"{f.name} has no rule IDs"

    def test_rule_ids_unique_across_files(self, rule_files):
        import re
        all_ids = []
        for f in rule_files:
            text = f.read_text()
            all_ids.extend(re.findall(r"^\s+- id:\s+(.+)$", text, re.MULTILINE))
        assert len(all_ids) == len(set(all_ids)), \
            f"Duplicate rule IDs: {[x for x in all_ids if all_ids.count(x) > 1]}"

    def test_all_rules_have_cwe_metadata(self, rule_files):
        import re
        for f in rule_files:
            text = f.read_text()
            ids = re.findall(r"^\s+- id:\s+(.+)$", text, re.MULTILINE)
            cwes = re.findall(r"cwe:\s+\"(CWE-\d+)\"", text)
            assert len(cwes) == len(ids), \
                f"{f.name} has {len(ids)} rules but {len(cwes)} CWE entries"

    def test_all_rules_have_severity(self, rule_files):
        import re
        for f in rule_files:
            text = f.read_text()
            ids = re.findall(r"^\s+- id:\s+(.+)$", text, re.MULTILINE)
            severities = re.findall(r"severity:\s+(ERROR|WARNING|INFO)", text)
            assert len(severities) == len(ids), \
                f"{f.name} has {len(ids)} rules but {len(severities)} severity entries"

    @skip_no_opengrep
    def test_opengrep_validates_rules(self, rule_files):
        for f in rule_files:
            result = subprocess.run(
                ["semgrep", "--validate", "--config", str(f)],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, \
                f"OpenGrep validation failed for {f.name}: {result.stderr[:300]}"


# ── Combined pipeline test ───────────────────────────────────────────────

class TestCombinedPipeline:
    """Test Tier 1 + Tier 2 clustering and evidence quality."""

    def test_clusters_duplicate_detectors(self):
        """OpenGrep and deterministic detections for the same issue should collapse."""
        from security_rules import SECURITY_RULES
        from main import generate_finding
        from finding_quality import cluster_findings

        patch = "+import pickle\n+data = pickle.loads(user_input)"
        tier1_findings = []
        for rule in SECURITY_RULES:
            if rule.pattern.search(patch):
                tier1_findings.append(generate_finding(rule, "app.py", patch))
        assert tier1_findings

        # Tier 2: OpenGrep match (simulated)
        tier2_findings = [{
            "rule_id": "opengrep.cwe-502.pickle-loads",
            "internal_type": tier1_findings[0]["internal_type"],
            "title": "pickle.loads() deserializes arbitrary Python objects",
            "category": "insecure deserialization",
            "cwe_id": "CWE-502",
            "severity": "critical",
            "confidence": 0.95,
            "file_path": "app.py",
            "line_start": 2,
            "fingerprint": "unique_opengrep_fingerprint_123",
            "description": "test",
            "exploitability": "high",
            "owasp_category": "A08:2021",
            "line_end": 2,
            "code_snippet": "pickle.loads(user_input)",
            "evidence": "OpenGrep AST match",
            "exploit_scenario": "",
            "remediation": "Use safe alternatives",
            "remediation_patch": "",
        }]

        merged = cluster_findings(tier1_findings + tier2_findings)

        assert len(merged) == 1
        assert merged[0]["rule_id"].startswith("opengrep.")
        assert "Supporting detections:" in merged[0]["evidence"]

    def test_tier1_findings_present(self):
        """Verify Tier 1 catches pickle.loads via regex."""
        from security_rules import SECURITY_RULES
        from main import generate_finding

        patch = "+import pickle\n+data = pickle.loads(user_input)"
        findings = []
        for rule in SECURITY_RULES:
            if rule.pattern.search(patch):
                findings.append(generate_finding(rule, "app.py", patch))

        cwe_ids = [f["cwe_id"] for f in findings]
        assert "CWE-502" in cwe_ids, "Tier 1 should catch pickle.loads as CWE-502"

    def test_adjacent_secrets_do_not_cluster(self):
        from security_rules import SECURITY_RULES
        from main import generate_finding
        from finding_quality import cluster_findings

        rule = _find("secret.hardcoded.credential")
        patches = [
            "+password = \"FirstSecret123\"",
            "+api_key = \"sk_live_abcdef\"",
        ]
        findings = [generate_finding(rule, "app.py", patch) for patch in patches]
        merged = cluster_findings(findings)
        assert len(merged) == 2, "Adjacent hardcoded secrets should remain separate findings"

    def test_opengrep_primary_keeps_deterministic_review_anchor(self):
        from security_rules import SECURITY_RULES
        from main import generate_finding
        from finding_quality import cluster_findings

        patch = "\n".join(
            [
                "@@ -10,3 +10,6 @@",
                " def find_user(user_id)",
                '+  logger.info("querying")',
                '+  query = "SELECT * FROM users WHERE id=" + user_id',
                '+  DB.execute(query)',
                " end",
            ]
        )
        rule = next(rule for rule in SECURITY_RULES if rule.rule_id == "sql.injection.raw_query")
        tier1 = generate_finding(rule, "user_service.rb", patch)

        tier2 = {
            "rule_id": "opengrep.ruby-sql-injection",
            "internal_type": tier1["internal_type"],
            "title": "Potential SQL injection",
            "description": "OpenGrep AST match",
            "category": tier1["category"],
            "cwe_id": tier1["cwe_id"],
            "severity": "critical",
            "confidence": 0.95,
            "file_path": "user_service.rb",
            "line_start": 13,
            "line_end": 13,
            "fingerprint": "opengrep-fingerprint",
            "exploitability": "high",
            "owasp_category": tier1["owasp_category"],
            "code_snippet": 'query = "SELECT * FROM users WHERE id=" + user_id',
            "evidence": "OpenGrep AST match",
            "exploit_scenario": "",
            "remediation": "Use parameterized queries",
            "remediation_patch": "",
        }

        merged = cluster_findings([tier1, tier2])

        assert len(merged) == 1
        assert merged[0]["rule_id"].startswith("opengrep.")
        assert merged[0]["line_start"] == 12
        assert 'query = "SELECT * FROM users WHERE id=" + user_id' in merged[0]["code_snippet"]

    def test_findings_have_consistent_format(self):
        """Both tiers should produce findings with the same keys."""
        required_keys = {
            "rule_id", "title", "description", "category", "cwe_id",
            "severity", "confidence", "file_path", "line_start",
            "fingerprint", "remediation",
        }

        from security_rules import SECURITY_RULES
        from main import generate_finding

        patch = "+API_KEY = 'sk_live_1234567890abcdef'"
        for rule in SECURITY_RULES:
            if rule.pattern.search(patch):
                finding = generate_finding(rule, "config.py", patch)
                missing = required_keys - set(finding.keys())
                assert not missing, f"Tier 1 finding missing keys: {missing}"
                break

    def test_extracts_snippet_from_matching_hunk(self):
        from security_rules import SECURITY_RULES
        from main import generate_finding

        rule = next(rule for rule in SECURITY_RULES if rule.rule_id == "sql.injection.raw_query")
        patch = "\n".join(
            [
                "@@ -10,3 +10,6 @@",
                " def find_user(user_id)",
                '+  logger.info("querying")',
                '+  query = "SELECT * FROM users WHERE id=" + user_id',
                '+  DB.execute(query)',
                " end",
            ]
        )

        finding = generate_finding(rule, "user_service.rb", patch)

        assert finding["line_start"] == 12
        assert finding["code_snippet"] == '  query = "SELECT * FROM users WHERE id=" + user_id'
        assert "Matched deterministic rule" in finding["evidence"]
