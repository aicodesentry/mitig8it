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
            "Read a bounded line range from one snapshot file.",
            {"path": {"type": "string"}, "line_start": {"type": "integer", "minimum": 1}, "line_end": {"type": "integer", "minimum": 1}},
            ["path", "line_start", "line_end"],
        ),
        tool("find_references", "Find lexical references to a JS/TS identifier.", {"symbol": {"type": "string"}}, ["symbol"]),
        tool("read_dependency", "Read an authorized dependency manifest by path.", {"path": {"type": "string"}}, ["path"]),
        tool("read_tests", "Find tests nearest to an application source path.", {"source_path": {"type": "string"}}, ["source_path"]),
        tool(
            "propose_patch",
            (
                "Propose exact whole-file replacements bound to source digests, together with the "
                "regression test that reproduces the finding. This does not verify a patch."
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
                    "items": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "base_sha256": {"type": "string"}, "replacement_content": {"type": "string"}},
                        "required": ["path", "base_sha256", "replacement_content"],
                        "additionalProperties": False,
                    },
                },
                "regression_test": {
                    "type": "object",
                    "description": (
                        "A self-contained Node regression test that exits non-zero on the original "
                        "code and zero on the patched code. Its path must be "
                        "'.mitig8it/regression/<finding-id>.test.js' and must not already exist in "
                        "the repository. Use only Node built-ins and the repository's declared "
                        "dependencies, and import the changed module by relative path."
                    ),
                    "properties": {
                        "path": {"type": "string", "maxLength": 512},
                        "content": {"type": "string", "maxLength": 64000},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            },
            ["hypothesis", "intended_behavior", "assumptions", "citations", "changes", "regression_test"],
        ),
        tool("request_verification", "Request independent broker verification of the current proposal.", {}, []),
        tool("inspect_failure", "Read bounded structured evidence from the last verification failure.", {}, []),
        tool("abstain", "Stop safely when a reliable bounded repair is not possible.", {"reason_code": {"type": "string"}, "explanation": {"type": "string", "maxLength": 4000}}, ["reason_code", "explanation"]),
    ]
