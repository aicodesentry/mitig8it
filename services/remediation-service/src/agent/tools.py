from __future__ import annotations

from typing import Any


JAVASCRIPT = "javascript"
PYTHON = "python"

# Per-language wording for the parts of a tool description that name a toolchain. The
# JavaScript text is byte-for-byte what it was before Python support, so the JavaScript prompt
# budget is unchanged.
_LANGUAGE_TEXT = {
    JAVASCRIPT: {
        "references": "Find lexical references to a JS/TS identifier.",
        "regression_tests": (
            "One harness test (require('../harness')) per finding you fix, per the "
            "system prompt; a test requiring supertest, express, pg, or jest, or only "
            "reading the file as text, is rejected."
        ),
        "test_path": "'.mitig8it/regression/<finding-id>.test.js'.",
    },
    PYTHON: {
        "references": "Find lexical references to a Python identifier.",
        "regression_tests": (
            "One harness test (import harness as h) per finding you fix, per the "
            "system prompt; a test importing pytest, flask, requests, or a database driver, "
            "or only reading the file as text, is rejected."
        ),
        "test_path": "'.mitig8it/regression/<finding-id>.test.py'.",
    },
}


def tool_definitions(language: str = JAVASCRIPT) -> list[dict[str, Any]]:
    text = _LANGUAGE_TEXT.get(language, _LANGUAGE_TEXT[JAVASCRIPT])

    def tool(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
            },
        }

    return [
        tool("search_code", "Literal search of the exact-head snapshot.", {"query": {"type": "string", "maxLength": 200}}, ["query"]),
        tool(
            "read_file",
            (
                "Read a line range of one snapshot file (null bounds: around the finding lines). "
                "Returns lines as [line_number, text] pairs; text is what original_lines expects."
            ),
            {
                "path": {"type": "string"},
                "line_start": {"type": ["integer", "null"], "minimum": 1},
                "line_end": {"type": ["integer", "null"], "minimum": 1},
            },
            ["path", "line_start", "line_end"],
        ),
        tool("find_references", text["references"], {"symbol": {"type": "string"}}, ["symbol"]),
        tool("read_dependency", "Read an authorized dependency manifest by path.", {"path": {"type": "string"}}, ["path"]),
        tool("read_tests", "Find tests nearest to an application source path.", {"source_path": {"type": "string"}}, ["source_path"]),
        tool(
            "propose_patch",
            (
                "Propose the smallest line-range replacements, each quoting the exact lines it "
                "replaces, plus one regression test per finding you fix; the result names "
                "findings still lacking a test. Does not verify."
            ),
            {
                "hypothesis": {"type": "string", "maxLength": 4000},
                "intended_behavior": {"type": "string", "maxLength": 4000},
                "assumptions": {"type": "array", "items": {"type": "string", "maxLength": 1000}, "maxItems": 20},
                "citations": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "line_start": {"type": "integer"}, "line_end": {"type": "integer"}},
                        "required": ["path", "line_start", "line_end"],
                        "additionalProperties": False,
                    },
                },
                "changes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "description": (
                        "Hunks: original_lines verbatim from read_file; start_line disambiguates "
                        "repeats; replacement_lines replace them (empty deletes); no newlines in items."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "start_line": {"type": "integer", "minimum": 1},
                            "original_lines": {"type": "array", "items": {"type": "string", "maxLength": 4000}, "maxItems": 400},
                            "replacement_lines": {"type": "array", "items": {"type": "string", "maxLength": 4000}, "maxItems": 400},
                        },
                        "required": ["path", "start_line", "original_lines", "replacement_lines"],
                        "additionalProperties": False,
                    },
                },
                "regression_tests": {
                    "type": "array",
                    "maxItems": 10,
                    "description": text["regression_tests"],
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "string", "maxLength": 200, "description": "The finding id this test reproduces."},
                            "path": {"type": "string", "maxLength": 512, "description": text["test_path"]},
                            "content": {"type": "string", "maxLength": 64000},
                        },
                        "required": ["finding_id", "path", "content"],
                        "additionalProperties": False,
                    },
                },
            },
            ["hypothesis", "intended_behavior", "assumptions", "citations", "changes", "regression_tests"],
        ),
        tool("request_verification", "Verify the current proposal independently.", {}, []),
        tool("inspect_failure", "Read bounded evidence from the last verification failure.", {}, []),
        tool("abstain", "Stop safely when a reliable bounded repair is not possible.", {"reason_code": {"type": "string"}, "explanation": {"type": "string", "maxLength": 4000}}, ["reason_code", "explanation"]),
    ]
