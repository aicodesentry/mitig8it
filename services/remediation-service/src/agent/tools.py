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
                "Read a bounded line range from one snapshot file. Leave line_start and line_end "
                "null to read a window around the reported finding lines. Results are capped, so "
                "request the narrowest range that answers the question. Returns `lines`: "
                "`[line_number, text]` pairs whose text is what original_lines expects."
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
                "replaces, with the regression test that reproduces the finding. This does not "
                "verify a patch."
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
                        "Line-range hunks against the exact snapshot. original_lines are the "
                        "lines this hunk replaces, copied verbatim from read_file; the service "
                        "locates them and derives the range, so send no end_line and no digest. "
                        "start_line is the 1-based line you believe they start at, used only to "
                        "pick between repeats. replacement_lines are the new lines. Neither list "
                        "contains newlines; an empty replacement_lines deletes the range."
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
                    "minItems": 1,
                    "maxItems": 10,
                    "description": (
                        "One behavior test per finding this patch actually repairs, and none for "
                        "a finding it does not. A candidate claims exactly the findings whose test "
                        "fails on the original code and passes on the patched code; every other "
                        "finding is dropped and reported as not repaired, so do not send a test "
                        "you cannot make reproduce. Each test must require the changed module by "
                        "relative path and invoke the affected function or route handler with fake "
                        "req and res objects, stubbing collaborators such as child_process, pg and "
                        "fs by patching Module.prototype.require or Module._load before the "
                        "require, so no package needs to be installed. Exit non-zero when the "
                        "vulnerable behavior is observed and zero when it is not. A test that only "
                        "reads the changed file as text with fs.readFileSync and never requires it "
                        "proves nothing about behavior and is rejected."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding_id": {
                                "type": "string",
                                "maxLength": 200,
                                "description": "The exact finding id from the task this test reproduces.",
                            },
                            "path": {
                                "type": "string",
                                "maxLength": 512,
                                "description": "'.mitig8it/regression/<finding-id>.test.js', not an existing repository path.",
                            },
                            "content": {"type": "string", "maxLength": 64000},
                        },
                        "required": ["finding_id", "path", "content"],
                        "additionalProperties": False,
                    },
                },
            ["hypothesis", "intended_behavior", "assumptions", "citations", "changes", "regression_tests"],
        ),
        tool("request_verification", "Request independent broker verification of the current proposal.", {}, []),
        tool("inspect_failure", "Read bounded structured evidence from the last verification failure.", {}, []),
        tool("abstain", "Stop safely when a reliable bounded repair is not possible.", {"reason_code": {"type": "string"}, "explanation": {"type": "string", "maxLength": 4000}}, ["reason_code", "explanation"]),
    ]
