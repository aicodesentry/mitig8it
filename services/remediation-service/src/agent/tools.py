from __future__ import annotations

from typing import Any


def tool_definitions() -> list[dict[str, Any]]:
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
        tool("search_code", "Literal search of the authorized exact-head snapshot.", {"query": {"type": "string", "maxLength": 200}}, ["query"]),
        tool(
            "read_file",
            (
                "Read a bounded line range from one snapshot file; null line_start and line_end "
                "read a window around the finding lines. Results are capped, so keep ranges "
                "narrow. Returns `lines`: `[line_number, text]` pairs whose text is what "
                "original_lines expects."
            ),
            {
                "path": {"type": "string"},
                "line_start": {"type": ["integer", "null"], "minimum": 1},
                "line_end": {"type": ["integer", "null"], "minimum": 1},
            },
            ["path", "line_start", "line_end"],
        ),
        tool("find_references", "Find lexical references to a JS/TS identifier.", {"symbol": {"type": "string"}}, ["symbol"]),
        tool("read_dependency", "Read an authorized dependency manifest by path.", {"path": {"type": "string"}}, ["path"]),
        tool("read_tests", "Find tests nearest to an application source path.", {"source_path": {"type": "string"}}, ["source_path"]),
        tool(
            "propose_patch",
            (
                "Propose the smallest line-range replacements, each quoting the exact lines it "
                "replaces, plus one regression test per repaired finding. Does not verify."
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
                        "Line-range hunks. original_lines: the replaced lines, verbatim from "
                        "read_file; the service locates them, so send no end_line or digest. "
                        "start_line: 1-based hint used only between repeats. replacement_lines: "
                        "the new lines; empty deletes the range. No newlines in either list."
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
                    "description": (
                        "One behavior test per finding this patch repairs; a finding whose test "
                        "does not fail on the original and pass on the patch is dropped and "
                        "reported not repaired. Require the changed module by relative path, "
                        "invoke the affected function or handler with fake req and res, stub "
                        "collaborators (child_process, pg, fs) via Module.prototype.require before "
                        "the require, and exit non-zero only on the vulnerable behavior. A test "
                        "that only reads the file as text is rejected."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "string", "maxLength": 200, "description": "The task finding id this test reproduces."},
                            "path": {"type": "string", "maxLength": 512, "description": "'.mitig8it/regression/<finding-id>.test.js'."},
                            "content": {"type": "string", "maxLength": 64000},
                        },
                        "required": ["finding_id", "path", "content"],
                        "additionalProperties": False,
                    },
                },
            },
            ["hypothesis", "intended_behavior", "assumptions", "citations", "changes", "regression_tests"],
        ),
        tool("request_verification", "Request independent broker verification of the current proposal.", {}, []),
        tool("inspect_failure", "Read bounded structured evidence from the last verification failure.", {}, []),
        tool("abstain", "Stop safely when a reliable bounded repair is not possible.", {"reason_code": {"type": "string"}, "explanation": {"type": "string", "maxLength": 4000}}, ["reason_code", "explanation"]),
    ]
