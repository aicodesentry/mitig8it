"""Tier 1 must not read a comment as code.

The cases at the bottom are the ones the September 2026 real-repository replay read by
hand and found to be comments: `docs/validation/real-repo-replay-2026-09.md`,
observation 3.
"""

import pytest

from comment_stripper import language_for_path, strip_lines
from finding_quality import parse_patch_entries
from main import AnalyzePRRequest, analyze_tier1_payload


def stripped(lines, path, *, blank_strings=False):
    return strip_lines(lines, path, blank_strings=blank_strings)


class TestLanguageDetection:
    @pytest.mark.parametrize("path", [
        "src/index.js", "src/a.jsx", "src/a.mjs", "src/a.cjs",
        "src/a.ts", "src/a.tsx", "pkg/a.go", "src/A.java",
        "src/A.cs", "src/a.php", "lib/a.rb", "src/a.py",
    ])
    def test_modelled_languages(self, path):
        assert language_for_path(path) is not None

    @pytest.mark.parametrize("path", [
        "README.md", "History.md", "licenses.txt", "package.json",
        "Dockerfile", "src/main.rs", "a.yml", "",
    ])
    def test_unmodelled_paths_are_left_alone(self, path):
        assert language_for_path(path) is None
        assert stripped(["// looks like a comment"], path) == ["// looks like a comment"]


class TestLineNumbersAndColumns:
    def test_line_count_and_length_are_preserved(self):
        lines = ["const a = 1; // note", "// whole line", "const b = 2;"]
        out = stripped(lines, "a.ts")
        assert len(out) == len(lines)
        assert [len(line) for line in out] == [len(line) for line in lines]

    def test_patch_entries_keep_the_original_text_and_line_number(self):
        patch = "@@ -10,2 +10,2 @@\n+// a comment\n+const x = 1;"
        entries = parse_patch_entries(patch, "a.ts")
        assert [entry["line_number"] for entry in entries] == [10, 11]
        assert entries[0]["content"] == "// a comment"
        assert entries[0]["scan_text"].strip() == ""
        assert entries[1]["scan_text"] == "const x = 1;"


class TestPerLanguage:
    def test_javascript_line_block_and_jsdoc(self):
        lines = [
            "const x = 1; // trailing",
            "/* block start",
            "still block */ const y = 2;",
            "/**",
            " * jsdoc pool.destroy()",
            " */",
            "run();",
        ]
        out = stripped(lines, "src/a.js")
        assert out[0].rstrip() == "const x = 1;"
        assert out[1].strip() == ""
        assert out[2].strip() == "const y = 2;"
        assert out[4].strip() == ""
        assert out[6] == "run();"

    def test_typescript_template_literal_spans_lines(self):
        lines = ["const q = `select // not a comment", "from t`;", "// real"]
        out = stripped(lines, "src/a.ts")
        assert "// not a comment" in out[0]
        assert out[2].strip() == ""

    def test_go_raw_string_and_comments(self):
        lines = ["s := `raw // keep", "more`", "// gone", "x := 1 /* gone */"]
        out = stripped(lines, "pkg/a.go")
        assert "// keep" in out[0]
        assert out[2].strip() == ""
        assert out[3].rstrip() == "x := 1"

    def test_java_and_csharp(self):
        assert stripped(["int x = 1; // note"], "A.java")[0].rstrip() == "int x = 1;"
        assert stripped(["var x = 1; // note"], "A.cs")[0].rstrip() == "var x = 1;"

    def test_php_hash_and_slash_comments(self):
        out = stripped(["# hash", "// slash", "$p = 'keep';"], "a.php")
        assert out[0].strip() == ""
        assert out[1].strip() == ""
        assert out[2] == "$p = 'keep';"

    def test_ruby_hash_and_begin_end_block(self):
        out = stripped(["=begin", "int(1)", "=end", "puts '# not a comment'", "x = 1 # note"], "a.rb")
        assert out[1].strip() == ""
        assert out[3] == "puts '# not a comment'"
        assert out[4].rstrip() == "x = 1"

    def test_python_hash_and_docstring(self):
        out = stripped(['"""Module docstring', 'int(x) in prose', '"""', "z = int(w)  # note"], "a.py")
        assert out[0].strip() == ""
        assert out[1].strip() == ""
        assert out[3].rstrip() == "z = int(w)"

    def test_python_triple_quoted_value_is_not_a_docstring(self):
        line = 'sql = """SELECT * FROM t WHERE id = """ + uid'
        assert stripped([line], "a.py")[0] == line


class TestConservativeBehaviour:
    def test_a_comment_token_inside_a_string_is_not_stripped(self):
        line = 'const url = "http://example.test//path"; // gone'
        out = stripped([line], "a.ts")[0]
        assert 'const url = "http://example.test//path";' == out.rstrip()

    def test_a_hash_inside_a_python_string_is_not_stripped(self):
        line = "frag = '#section'  # gone"
        assert stripped([line], "a.py")[0].rstrip() == "frag = '#section'"

    def test_state_does_not_leak_across_hunks(self):
        # The second hunk opens with code, not with the first hunk's unterminated block.
        patch = (
            "@@ -1,1 +1,1 @@\n+/* opened here\n"
            "@@ -50,1 +50,1 @@\n+const x = eval(payload);\n"
        )
        entries = parse_patch_entries(patch, "a.ts")
        assert entries[0]["scan_text"].strip() == ""
        assert entries[1]["scan_text"] == "const x = eval(payload);"


class TestStringBlanking:
    def test_string_bodies_are_blanked_only_on_request(self):
        line = "const route = '/login';"
        assert stripped([line], "a.ts")[0] == line
        assert stripped([line], "a.ts", blank_strings=True)[0] == "const route = '      ';"

    def test_quotes_survive_blanking_so_the_line_still_parses_by_eye(self):
        out = stripped(['password = "hunter2"'], "a.py", blank_strings=True)[0]
        assert out.startswith('password = "') and out.endswith('"')


def _tier1(path, patch_lines):
    payload = AnalyzePRRequest(
        repository_full_name="acme/app",
        pull_request_number=1,
        commit_sha="a" * 40,
        files=[{"path": path, "patch": "@@ -1,%d +1,%d @@\n" % (len(patch_lines), len(patch_lines))
                + "".join(f"+{line}\n" for line in patch_lines)}],
    )
    return analyze_tier1_payload(payload)


class TestReplayCommentCases:
    """The lines the replay read by hand and found to be comments, not code."""

    def test_jsdoc_explaining_pool_destroy_is_not_a_finding(self):
        # sequelize packages/core/src/abstract-dialect/connection-manager.ts:74, severity high.
        result = _tier1("packages/core/src/abstract-dialect/connection-manager.ts", [
            "/**",
            " * Calling `pool.destroy()` on the connection from here does not throw, but it does not",
            " * release it either.",
            " */",
        ])
        assert result["findings"] == []

    def test_jsdoc_usage_example_of_res_location_is_not_a_finding(self):
        # express lib/response.js:787, rate_limit.missing on a JSDoc example.
        result = _tier1("lib/response.js", [
            " *    res.location('../login');",
        ])
        assert result["findings"] == []

    def test_sequelize_global_option_comment_is_not_a_finding(self):
        # sequelize packages/mariadb/src/connection-manager.ts:30.
        result = _tier1("packages/mariadb/src/connection-manager.ts", [
            "// Replaced by Sequelize's global option",
        ])
        assert result["findings"] == []

    def test_global_agent_comment_is_not_a_finding(self):
        # got, concurrency.shared_state on an English sentence in a comment.
        result = _tier1("source/core/index.ts", [
            "// If agent.http2 is unset, use the global agent for connection pooling.",
        ])
        assert result["findings"] == []

    def test_a_python_docstring_example_is_not_a_finding(self):
        result = _tier1("app/service.py", [
            '"""Helper.',
            "",
            "    Example: subprocess.run(cmd, shell=True)",
            '"""',
        ])
        assert result["findings"] == []

    def test_the_same_lines_as_code_are_still_found(self):
        # The stripper must not hide the real thing: the same call outside a comment.
        result = _tier1("app/service.py", [
            "subprocess.run(cmd, shell=True)",
        ])
        assert [f["rule_id"] for f in result["findings"]] == ["cmd.injection.shell_true"]
