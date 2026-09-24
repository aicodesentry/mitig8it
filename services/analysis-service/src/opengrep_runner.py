"""
Tier 2: OpenGrep-based AST analysis runner.

Writes PR diff files to a temp directory, runs OpenGrep with custom rules,
and returns findings in the same format as Tier 1 (security_rules.py).
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from finding_quality import is_transcript_artifact_line
from remediation_patches import build_remediation_patch
from taxonomy import build_taxonomy_metadata
from test_code_scope import (
    classify_findings,
    is_analyzable_path,
    is_runtime_scannable_path as _is_runtime_scannable_path,
)

RULES_DIR = Path(__file__).parent / "opengrep_rules"

# A large pull request must never be handed to one scanner process in a single
# call. Files are scanned in bounded batches and the results are merged.
DEFAULT_BATCH_MAX_FILES = 25
DEFAULT_BATCH_MAX_BYTES = 1024 * 1024

# Map OpenGrep severity to our severity levels
SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
}

TRACE_STEP_KINDS = {"source", "assignment", "call", "sanitizer", "sink"}

VALIDATED_SANITIZERS = {
    "path traversal": {"ensurewithbasedir", "validatesafepath", "allowlistedpath", "ensurewithinbasedir"},
    "open redirect": {"ensurerelativeredirect", "allowlistedredirect"},
    "ssrf": {"allowlistedurl", "validateinternalurl"},
    "xss": {"dompurify.sanitize", "escapehtml", "html.escapestring", "template.htmlescapestring"},
}

INSUFFICIENT_SANITIZERS = {
    "path traversal": {"path.basename", "path.posix.basename", "path.win32.basename", "filepath.base", "path.base", "filepath.clean", "path.clean"},
    "ssrf": {"new url", "url.parse"},
    "open redirect": set(),
    "xss": set(),
}

VALIDATED_SANITIZERS = {
    re.sub(r"[^a-z0-9]+", "", category.lower()): {re.sub(r"[^a-z0-9]+", "", value.lower()) for value in values}
    for category, values in VALIDATED_SANITIZERS.items()
}
INSUFFICIENT_SANITIZERS = {
    re.sub(r"[^a-z0-9]+", "", category.lower()): {re.sub(r"[^a-z0-9]+", "", value.lower()) for value in values}
    for category, values in INSUFFICIENT_SANITIZERS.items()
}


def make_fingerprint(rule_id: str, path: str, line: int, snippet: str) -> str:
    raw = f"{rule_id}|{path}|{line}|{snippet.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _extract_file_content(patch: str) -> str:
    """Rebuild the new side of a file from its unified diff, at the file's own line numbers.

    Every added and context line is placed at the line number the hunk header gives it and
    the gaps between hunks are left blank, so a line the scanner reports is the line the
    file really has. Concatenating the hunks instead reported a finding at line 3 of a
    reconstruction when the code was at line 501 of the file, and the inline review comment
    went to the wrong line.

    A context line also keeps its text without the diff's one-character marker. Leaving the
    marker in shifted every context line one column right while added lines kept their own
    indentation, which by itself makes a patch-only Python file unparseable.
    """
    if not patch:
        return ""

    lines: List[str] = []
    new_line = 1

    def place(text: str) -> None:
        nonlocal new_line
        while len(lines) < new_line - 1:
            lines.append("")
        if len(lines) < new_line:
            lines.append(text)
        else:
            lines[new_line - 1] = text
        new_line += 1

    for raw in patch.split("\n"):
        if raw.startswith("@@"):
            match = HUNK_HEADER_RE.match(raw)
            if match:
                new_line = max(1, int(match.group(1)))
            continue
        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        # "\ No newline at end of file" is diff prose, never a line of the file.
        if raw.startswith("\\"):
            continue
        if raw.startswith("-"):
            continue
        text = raw[1:] if raw[:1] in ("+", " ") else raw
        # A transcript artifact keeps its position as a blank line rather than pulling
        # every following line up by one.
        place("" if is_transcript_artifact_line(text) else text)

    return "\n".join(lines)


def _extract_scan_content(file_info: Dict[str, Any]) -> str:
    content = file_info.get("content")
    if isinstance(content, str) and content:
        return content
    extracted = _extract_file_content(file_info.get("patch", ""))
    path = str(file_info.get("path") or "")
    if _file_extension(path) == ".go" and extracted and "package " not in extracted:
        # Patch-only Go snippets are often just statements, which are not parseable
        # as standalone files. Wrap them so OpenGrep can analyze the fragment.
        indented = "\n".join(
            f"    {line}" if line.strip() else ""
            for line in extracted.splitlines()
        )
        return f'package main\n\nimport (\n    "net/http"\n    "os"\n    "path/filepath"\n)\n\nfunc _generated(r *http.Request) {{\n{indented}\n}}\n'
    return extracted


def _build_evidence_details(metadata: Dict[str, Any]) -> Dict[str, Any]:
    sanitizers = metadata.get("sanitizers_seen", [])
    if sanitizers is None:
        sanitizers = []
    elif not isinstance(sanitizers, list):
        sanitizers = [sanitizers]

    analysis_scope = metadata.get("analysis_scope", "ast-pattern")
    return {
        "analysis_scope": analysis_scope,
        "is_taint_based": str(analysis_scope).startswith("taint"),
        "source_type": metadata.get("source_description"),
        "source_expr": metadata.get("source_expr"),
        "sink_type": metadata.get("sink_description"),
        "sink_expr": metadata.get("sink_expr"),
        "sanitizer_exprs": sanitizers,
        "sanitizer_status": metadata.get("sanitizer_status", "none"),
        "trace_steps": [],
        "trace_summary": metadata.get("trace_summary"),
        "reviewability": metadata.get("reviewability", "changed-lines-only"),
        "fix_scope": metadata.get("fix_scope", "line"),
        "fix_target_line": _normalize_trace_line(metadata.get("fix_target_line")),
        "fix_target_expr": metadata.get("fix_target_expr"),
        "missing_control_type": metadata.get("missing_control_type"),
        "auto_fix_eligible": bool(metadata.get("auto_fix_eligible", False)),
    }


def _normalize_trace_line(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _step_expr(explicit_expr: Any, fallback_expr: str) -> str:
    expr = str(explicit_expr or "").strip()
    return expr or fallback_expr.strip()


def _normalize_trace_step(step: Dict[str, Any], default_file: str) -> Optional[Dict[str, Any]]:
    kind = str(step.get("kind") or "").strip().lower()
    if kind not in TRACE_STEP_KINDS:
        return None

    expr = str(step.get("expr") or "").strip()
    if not expr:
        return None

    normalized = {
        "kind": kind,
        "label": str(step.get("label") or kind).strip(),
        "expr": expr,
        "file": str(step.get("file") or default_file).strip() or default_file,
        "line": _normalize_trace_line(step.get("line")),
    }
    status = str(step.get("status") or "").strip()
    if status:
        normalized["status"] = status
    return normalized


def _normalize_name(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(text or "").strip().lower())


def _classify_sanitizer_status(metadata: Dict[str, Any]) -> str:
    sanitizers = metadata.get("sanitizers_seen", [])
    if sanitizers is None:
        sanitizers = []
    elif not isinstance(sanitizers, list):
        sanitizers = [sanitizers]
    if not sanitizers:
        return "none"

    category = _normalize_name(metadata.get("category"))
    validated = VALIDATED_SANITIZERS.get(category, set())
    insufficient = INSUFFICIENT_SANITIZERS.get(category, set())

    normalized_sanitizers = [_normalize_name(value) for value in sanitizers if str(value or "").strip()]
    if any(any(marker in sanitizer for marker in validated) for sanitizer in normalized_sanitizers):
        return "validated"
    if any(any(marker in sanitizer for marker in insufficient) for sanitizer in normalized_sanitizers):
        return "present-but-insufficient"
    return "present"


def _infer_missing_control_type(metadata: Dict[str, Any]) -> Optional[str]:
    category = _normalize_name(metadata.get("category"))
    if category == "pathtraversal":
        return "base_dir_validation"
    if category == "openredirect":
        return "relative_or_allowlisted_redirect_validation"
    if category == "ssrf":
        return "host_or_scheme_allowlist"
    if category == "xss":
        sink = _normalize_name(metadata.get("sink_description"))
        if "html" in sink:
            return "html_sanitization_or_safe_text_rendering"
        return "output_encoding"
    return None


def _infer_fix_scope(metadata: Dict[str, Any]) -> str:
    trace_steps = metadata.get("trace_steps") or []
    if isinstance(trace_steps, list) and any(step.get("kind") == "assignment" for step in trace_steps if isinstance(step, dict)):
        return "block"
    return "line"


def _is_auto_fix_eligible(metadata: Dict[str, Any]) -> bool:
    analysis_scope = str(metadata.get("analysis_scope", "pattern"))
    reviewability = str(metadata.get("reviewability", "changed-lines-only")).strip().lower()
    sanitizer_status = str(metadata.get("sanitizer_status", "none")).strip().lower()
    if not analysis_scope.startswith("taint"):
        return False
    if reviewability in {"context-only", "unreviewable"}:
        return False
    if sanitizer_status == "validated":
        return False
    if not metadata.get("missing_control_type"):
        return False
    return True


def _build_trace_steps(
    metadata: Dict[str, Any],
    file_path: str,
    line_start: int,
    line_end: int,
    code_snippet: str,
) -> List[Dict[str, Any]]:
    if metadata.get("trace_steps"):
        return [
            normalized
            for normalized in (
                _normalize_trace_step(step, file_path)
                for step in metadata["trace_steps"]
                if isinstance(step, dict)
            )
            if normalized
        ]

    analysis_scope = str(metadata.get("analysis_scope", "ast-pattern"))
    if not analysis_scope.startswith("taint"):
        return []

    source_expr = _step_expr(metadata.get("source_expr"), str(metadata.get("source_description", "")))
    sink_expr = _step_expr(metadata.get("sink_expr"), code_snippet)
    source_line = _normalize_trace_line(metadata.get("source_line"))
    sink_line = _normalize_trace_line(metadata.get("sink_line")) or line_start
    propagations = metadata.get("propagation_steps") or []
    if not isinstance(propagations, list):
        propagations = [propagations]

    steps: List[Dict[str, Any]] = []
    if source_expr:
        normalized = _normalize_trace_step({
            "kind": "source",
            "label": metadata.get("source_description") or "taint source",
            "expr": source_expr,
            "file": file_path,
            "line": source_line,
        }, file_path)
        if normalized:
            steps.append(normalized)

    for propagation in propagations:
        if not isinstance(propagation, dict):
            continue
        step_kind = str(propagation.get("kind") or "assignment")
        step_expr = _step_expr(propagation.get("expr"), "")
        if not step_expr:
            continue
        normalized = _normalize_trace_step({
            "kind": step_kind,
            "label": propagation.get("label") or step_kind,
            "expr": step_expr,
            "file": propagation.get("file") or file_path,
            "line": _normalize_trace_line(propagation.get("line")),
        }, file_path)
        if normalized:
            steps.append(normalized)

    sanitizers = metadata.get("sanitizers_seen", [])
    if sanitizers is None:
        sanitizers = []
    elif not isinstance(sanitizers, list):
        sanitizers = [sanitizers]

    sanitizer_status = metadata.get("sanitizer_status", "present")
    sanitizer_line = _normalize_trace_line(metadata.get("sanitizer_line"))
    for sanitizer in sanitizers:
        sanitizer_expr = str(sanitizer or "").strip()
        if not sanitizer_expr:
            continue
        normalized = _normalize_trace_step({
            "kind": "sanitizer",
            "label": "sanitizer",
            "expr": sanitizer_expr,
            "file": file_path,
            "line": sanitizer_line,
            "status": sanitizer_status,
        }, file_path)
        if normalized:
            steps.append(normalized)

    if sink_expr:
        normalized = _normalize_trace_step({
            "kind": "sink",
            "label": metadata.get("sink_description") or "sink",
            "expr": sink_expr,
            "file": file_path,
            "line": sink_line or line_end,
        }, file_path)
        if normalized:
            steps.append(normalized)

    return steps


def _file_extension(path: str) -> Optional[str]:
    ext = Path(path).suffix.lower()
    return ext if ext else None


def _extract_exact_lines(content: str, start_line: int, end_line: int) -> str:
    lines = str(content or "").splitlines()
    start = max(1, int(start_line or 1))
    end = max(start, int(end_line or start))
    selected = lines[start - 1:end]
    return "\n".join(selected).strip()


def _extract_exact_line(content: str, line: Optional[int]) -> str:
    if not line:
        return ""
    return _extract_exact_lines(content, line, line)


def _metavar_info(match: Dict[str, Any], name: Optional[str]) -> Dict[str, Any]:
    if not name:
        return {}
    metavars = match.get("extra", {}).get("metavars", {})
    return metavars.get(name, {}) if isinstance(metavars, dict) else {}


def _metavar_expr(match: Dict[str, Any], name: Optional[str]) -> str:
    info = _metavar_info(match, name)
    return str(info.get("abstract_content") or "").strip()


def _metavar_line(match: Dict[str, Any], name: Optional[str]) -> Optional[int]:
    info = _metavar_info(match, name)
    return _normalize_trace_line((info.get("start") or {}).get("line"))


def _infer_local_propagation_kind(statement: str, source_expr: str) -> str:
    text = str(statement or "").strip()
    source = str(source_expr or "").strip()
    if not text or not source:
        return "assignment"

    assignment_match = re.search(r"(:=|=)", text)
    if not assignment_match:
        return "assignment"

    rhs = text[assignment_match.end():].strip()
    if source not in rhs:
        return "assignment"

    if "(" in rhs and ")" in rhs:
        return "call"

    return "assignment"


def _enrich_metadata_from_match(
    metadata: Dict[str, Any],
    match: Dict[str, Any],
    file_path: str,
    file_content: str,
    line_start: int,
    code_snippet: str,
) -> Dict[str, Any]:
    enriched = dict(metadata)
    enriched["sanitizer_status"] = _classify_sanitizer_status(enriched)

    source_var = enriched.get("source_var")
    sink_var = enriched.get("sink_var")

    source_expr = _metavar_expr(match, source_var)
    source_line = _metavar_line(match, source_var)
    sink_arg_expr = _metavar_expr(match, sink_var)
    sink_line = _metavar_line(match, sink_var) or line_start

    if source_expr:
        enriched["source_expr"] = source_expr
    if source_line:
        enriched["source_line"] = source_line
        source_statement = _extract_exact_line(file_content, source_line)
        if (
            source_statement
            and source_statement.strip() != source_expr
            and source_line != sink_line
        ):
            enriched["propagation_steps"] = [{
                "kind": _infer_local_propagation_kind(source_statement, source_expr),
                "label": _infer_local_propagation_kind(source_statement, source_expr),
                "expr": source_statement,
                "file": file_path,
                "line": source_line,
            }]

    enriched["sink_expr"] = code_snippet
    enriched["sink_line"] = line_start
    if sink_arg_expr:
        enriched["sink_arg_expr"] = sink_arg_expr

    enriched["missing_control_type"] = _infer_missing_control_type(enriched)
    enriched["fix_target_line"] = line_start
    enriched["fix_target_expr"] = code_snippet
    enriched["fix_scope"] = _infer_fix_scope(enriched)
    enriched["auto_fix_eligible"] = _is_auto_fix_eligible(enriched)

    return enriched


# Languages OpenGrep should scan, mapped by file extension
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".swift", ".kt",
}


def _batch_limit(env_name: str, default: int) -> int:
    try:
        value = int(os.getenv(env_name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def batch_max_files() -> int:
    return _batch_limit("OPENGREP_BATCH_MAX_FILES", DEFAULT_BATCH_MAX_FILES)


def batch_max_bytes() -> int:
    return _batch_limit("OPENGREP_BATCH_MAX_BYTES", DEFAULT_BATCH_MAX_BYTES)


def build_scan_batches(
    prepared: List[Dict[str, Any]],
    max_files: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> List[List[Dict[str, Any]]]:
    """Split prepared files into batches bounded by file count and total bytes.

    A single file larger than the byte budget still gets its own batch: the
    scanner enforces its own per-file limit, and dropping it would hide code.
    """
    limit_files = max_files if max_files and max_files > 0 else batch_max_files()
    limit_bytes = max_bytes if max_bytes and max_bytes > 0 else batch_max_bytes()

    batches: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    current_bytes = 0

    for entry in prepared:
        size = int(entry.get("size") or 0)
        if current and (len(current) >= limit_files or current_bytes + size > limit_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(entry)
        current_bytes += size

    if current:
        batches.append(current)

    return batches


# Scanner error classification.
#
# semgrep's JSON `errors` entries follow the cli_error schema of
# semgrep_output_v1 (fields: code, level, type, rule_id, message, path,
# long_msg, short_msg, spans, help). `level` is one of "error", "warn",
# "info". `type` is either a string tag ("Lexical error", "Syntax error",
# "Timeout", "Out of memory", "Too many matches", "Fatal error", ...) or, for
# the parameterised variants, a two element list such as
# ["PartialParsing", [<locations>]] or ["PatternParseError", [...]].
#
# A per-file parse problem means one file was read partially. It must not
# discard the findings semgrep produced for every other file in the batch, so
# those entries become recorded limitations instead of a failed scan.
PARTIAL_PARSE_ERROR_TYPES = {
    "Lexical error",
    "Syntax error",
    "Other syntax error",
    "Parsing error",
    "AST builder error",
    "Partial parsing",
    "PartialParsing",
}

# The scanner gave up on one file because it hit a resource ceiling. Whatever
# it did produce for the other files is still sound.
RESOURCE_LIMIT_ERROR_TYPES = {
    "Timeout",
    "Out of memory",
    "Too many matches",
    "Fixpoint timeout",
    "Stack overflow",
    "Timeout during interfile analysis",
    "OOM during interfile analysis",
}

LIMITATION_PARTIAL_PARSE = "partial_parse"
LIMITATION_NOT_ANALYZED = "not_analyzed"

_ERROR_LINE_PATTERN = re.compile(r"at line [^\s:]*:(\d+)")


# The parameterised variants carry an OCaml style constructor name rather than
# the readable tag the string variants use. These end up in a check run summary,
# so they get the same shape as the rest.
ERROR_TYPE_DISPLAY = {
    "PartialParsing": "Partial parsing",
    "PatternParseError": "Pattern parse error",
    "IncompatibleRule": "Incompatible rule",
    "DependencyResolutionError": "Dependency resolution error",
}


def _scanner_error_type(entry: Dict[str, Any]) -> str:
    """Return the error tag, flattening the ["Tag", payload] parameterised form."""
    raw = entry.get("type")
    if isinstance(raw, str):
        return ERROR_TYPE_DISPLAY.get(raw, raw)
    if isinstance(raw, list) and raw and isinstance(raw[0], str):
        return ERROR_TYPE_DISPLAY.get(raw[0], raw[0])
    return "Unknown"


def _scanner_error_line(entry: Dict[str, Any]) -> Optional[int]:
    """Best-effort line number for a scanner error.

    semgrep puts the location in `spans` when it has one, in the payload of a
    parameterised type otherwise, and always repeats it inside the message.
    """
    spans = entry.get("spans")
    if isinstance(spans, list):
        for span in spans:
            line = _normalize_trace_line((span or {}).get("start", {}).get("line"))
            if line is not None:
                return line

    raw_type = entry.get("type")
    if isinstance(raw_type, list) and len(raw_type) == 2 and isinstance(raw_type[1], list):
        for location in raw_type[1]:
            if not isinstance(location, dict):
                continue
            line = _normalize_trace_line((location.get("start") or {}).get("line"))
            if line is not None:
                return line

    match = _ERROR_LINE_PATTERN.search(str(entry.get("message") or ""))
    if match:
        return int(match.group(1))
    return None


def _scanner_error_path(entry: Dict[str, Any]) -> str:
    path = entry.get("path")
    return path if isinstance(path, str) and path else ""


def _describe_scanner_error(entry: Dict[str, Any]) -> str:
    message = str(entry.get("message") or "")[:200]
    return (
        f"type={_scanner_error_type(entry)} level={entry.get('level')} "
        f"path={_scanner_error_path(entry) or '<none>'} message={message}"
    )


def _classify_scanner_errors(
    errors: List[Any],
    stderr_tail: str,
) -> List[Dict[str, Any]]:
    """Split scanner errors into tolerable per-file limitations and fatal failures.

    Every entry is logged. File scoped parse problems and resource ceilings
    become limitations and the batch results are kept. Anything else - invalid
    rules, config errors, a fatal error, an error level entry with no file to
    attribute it to - still fails the tier closed, now with the error details
    in the raised message so the next failure is diagnosable from the logs.
    """
    limitations: List[Dict[str, Any]] = []
    fatal: List[Dict[str, Any]] = []

    for raw in errors:
        if not isinstance(raw, dict):
            fatal.append({"type": "Unknown", "level": "error", "message": str(raw)})
            print(f"OpenGrep scanner error: type=Unknown level=error path=<none> message={str(raw)[:200]}", flush=True)
            continue

        print(f"OpenGrep scanner error: {_describe_scanner_error(raw)}", flush=True)

        error_type = _scanner_error_type(raw)
        level = raw.get("level")
        path = _scanner_error_path(raw)
        message = str(raw.get("message") or "")

        if path and error_type in RESOURCE_LIMIT_ERROR_TYPES:
            limitations.append({
                "path": path,
                "kind": LIMITATION_NOT_ANALYZED,
                "type": error_type,
                "message": message[:200],
                "line": _scanner_error_line(raw),
            })
            continue

        if path and error_type in PARTIAL_PARSE_ERROR_TYPES and level in ("warn", "info"):
            limitations.append({
                "path": path,
                "kind": LIMITATION_PARTIAL_PARSE,
                "type": error_type,
                "message": message[:200],
                "line": _scanner_error_line(raw),
            })
            continue

        if level == "info":
            # Informational entries say nothing is wrong.
            continue

        fatal.append(raw)

    if fatal:
        details = "; ".join(_describe_scanner_error(entry) for entry in fatal)
        tail = (stderr_tail or "").strip()[-500:]
        raise RuntimeError(
            f"OpenGrep reported incomplete analysis: {details}"
            + (f" | stderr: {tail}" if tail else "")
        )

    return limitations


def _run_semgrep(target_dir: str) -> Dict[str, Any]:
    """Run one scanner process over one batch directory and return its output.

    Tolerable per-file scanner errors are attached to the returned output under
    `analysis_limitations`; fatal ones raise.
    """
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", str(RULES_DIR),
                "--json",
                "--no-git-ignore",
                "--quiet",
                "--timeout", "30",
                "--max-target-bytes", "500000",
                target_dir,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("OpenGrep timed out after 120s")
    except FileNotFoundError:
        raise RuntimeError("OpenGrep executable is unavailable")

    if result.returncode not in (0, 1):
        # returncode 1 = findings found, 0 = no findings
        stderr_tail = (result.stderr or "").strip()[-500:]
        raise RuntimeError(
            f"OpenGrep failed with exit code {result.returncode}"
            + (f" | stderr: {stderr_tail}" if stderr_tail else "")
        )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("OpenGrep returned invalid JSON")

    if not isinstance(output, dict) or not isinstance(output.get("results"), list):
        raise RuntimeError("OpenGrep returned an incomplete result")

    errors = output.get("errors")
    if errors:
        if not isinstance(errors, list):
            raise RuntimeError(f"OpenGrep reported incomplete analysis: errors={str(errors)[:200]}")
        output["analysis_limitations"] = _classify_scanner_errors(errors, result.stderr or "")

    return output


def _build_finding(
    match: Dict[str, Any],
    tmpdir: str,
    extracted_content_by_path: Dict[str, str],
) -> Dict[str, Any]:
    raw_metadata = match.get("extra", {}).get("metadata", {})
    check_id = match.get("check_id", "")
    file_path = match.get("path", "").replace(tmpdir + "/", "")
    line_start = match.get("start", {}).get("line", 1)
    line_end = match.get("end", {}).get("line", line_start)
    code_snippet = _extract_exact_lines(
        extracted_content_by_path.get(file_path, ""),
        line_start,
        line_end,
    )[:500] or match.get("extra", {}).get("lines", "")[:500]
    metadata = _enrich_metadata_from_match(
        raw_metadata,
        match,
        file_path=file_path,
        file_content=extracted_content_by_path.get(file_path, ""),
        line_start=line_start,
        code_snippet=code_snippet,
    )
    opengrep_severity = match.get("extra", {}).get("severity", "WARNING")
    taxonomy = build_taxonomy_metadata(
        rule_id=f"opengrep.{check_id}",
        category=metadata.get("category", "security"),
        cwe_id=metadata.get("cwe", None),
        owasp_category=metadata.get("owasp", None),
        # No internal type unless the rule states one. Passing the check id here made the
        # taxonomy return `cwe-89.sql-template-literal` instead of `sql_injection`, so a
        # tier 2 finding never clustered with the tier 1 finding for the same flaw.
        internal_type=metadata.get("internal_type"),
        title=match.get("extra", {}).get("message", check_id),
        description=match.get("extra", {}).get("message", ""),
        file_path=file_path,
        code_snippet=code_snippet,
        attack_techniques=metadata.get("attack", None),
        capec_ids=metadata.get("capec", None),
    )
    trace_steps = _build_trace_steps(
        metadata,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=code_snippet,
    )
    evidence_details = _build_evidence_details(metadata)
    evidence_details["trace_steps"] = trace_steps

    finding = {
        "rule_id": f"opengrep.{check_id}",
        "internal_type": taxonomy["internal_type"],
        "title": match.get("extra", {}).get("message", check_id),
        "description": match.get("extra", {}).get("message", ""),
        "category": metadata.get("category", "security"),
        "cwe_id": taxonomy["primary_cwe_id"],
        "owasp_category": taxonomy["primary_owasp_category"],
        "taxonomy_mappings": taxonomy["taxonomy_mappings"],
        "taxonomy_versions": taxonomy["taxonomy_versions"],
        "severity": SEVERITY_MAP.get(opengrep_severity, "medium"),
        "confidence": float(metadata.get("confidence", 0.8)),
        "exploitability": "medium",
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "analysis_scope": metadata.get("analysis_scope", "ast-pattern"),
        "source": metadata.get("source_description"),
        "sink": metadata.get("sink_description"),
        "sanitizers_seen": metadata.get("sanitizers_seen", []),
        "trace_summary": metadata.get("trace_summary"),
        "evidence_details": evidence_details,
        "code_snippet": code_snippet,
        "evidence": f"OpenGrep AST match on rule `{check_id}`",
        "exploit_scenario": "",
        "remediation": match.get("extra", {}).get("message", ""),
        "remediation_patch": "",
        "fingerprint": make_fingerprint(
            f"opengrep.{check_id}", file_path, line_start, code_snippet
        ),
    }
    finding["remediation_patch"] = build_remediation_patch(finding) or ""
    return finding


class ScanPathError(RuntimeError):
    """A request-supplied path would land outside the scan directory."""


def contained_scan_path(root: Path, relative_path: str) -> Path:
    """The file under `root` that a snapshot entry may be written to.

    Entry paths come from the request. `Path(root) / path` discards `root` for an
    absolute path and `..` climbs out of it, so the target is resolved (which also
    follows any symlink already under `root`) and must remain inside the resolved root.
    """
    if not relative_path or Path(relative_path).is_absolute():
        raise ScanPathError(f"OpenGrep refused a path outside the scan directory: {relative_path!r}")
    resolved_root = root.resolve()
    target = (resolved_root / relative_path).resolve()
    if target == resolved_root or not target.is_relative_to(resolved_root):
        raise ScanPathError(f"OpenGrep refused a path outside the scan directory: {relative_path!r}")
    # The unresolved form keeps the file under the directory semgrep is pointed at, so
    # reported paths map back to the request the same way they did before.
    return root / relative_path


def _repo_relative_scan_path(scan_path: str, tmpdir: str, known_paths: List[str]) -> str:
    """Map a scanner reported path back to the repository path it came from."""
    relative = scan_path.replace(tmpdir + "/", "")
    if relative in known_paths:
        return relative
    for candidate in known_paths:
        if relative.endswith("/" + candidate) or relative == candidate:
            return candidate
    return relative


def _scan_batch(batch: List[Dict[str, Any]]) -> tuple:
    """Scan one batch and return (findings, limitations).

    A fatal scanner failure still raises, so the tier fails closed. Per-file
    limitations are reported alongside the findings the batch did produce.
    """
    findings: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="mitig8it_") as tmpdir:
        extracted_content_by_path: Dict[str, str] = {}
        for entry in batch:
            file_path = contained_scan_path(Path(tmpdir), entry["path"])
            file_path.parent.mkdir(parents=True, exist_ok=True)
            extracted_content_by_path[entry["path"]] = entry["content"]
            file_path.write_text(entry["content"], encoding="utf-8")

        output = _run_semgrep(tmpdir)

        for match in output.get("results", []):
            findings.append(_build_finding(match, tmpdir, extracted_content_by_path))

        # The scanner reports the temp directory it was pointed at. Both the
        # path and the message go into a check run summary and the database, so
        # they are mapped back to the repository path they came from.
        known_paths = [entry["path"] for entry in batch]
        limitations = [
            {
                **limitation,
                "path": _repo_relative_scan_path(limitation["path"], tmpdir, known_paths),
                "message": str(limitation.get("message") or "").replace(tmpdir + "/", ""),
            }
            for limitation in output.get("analysis_limitations", [])
        ]

    return findings, limitations


def run_opengrep(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run OpenGrep on PR files and return findings, discarding any limitations."""
    findings, _ = run_opengrep_with_limitations(files)
    return findings


def run_opengrep_with_limitations(files: List[Dict[str, Any]]) -> tuple:
    """
    Run OpenGrep on PR files and return (findings, limitations).

    Files are scanned in bounded batches and the results are merged. A batch
    that fails outright still fails the whole tier closed; partial results are
    never returned as if they were complete. A per-file scanner limitation - a
    lexical or syntax error that truncated one file, a per-file timeout or an
    out of memory - keeps the findings from every other file and is reported as
    a limitation instead.

    Args:
        files: List of {path, patch, additions, ...} from the PR diff.

    Returns:
        (findings, limitations) where findings match the Tier 1 format and each
        limitation is {path, kind, type, message, line}.
    """
    if not RULES_DIR.exists() or not any(RULES_DIR.glob("*.yml")):
        raise RuntimeError("OpenGrep rules are unavailable")

    # Test files are scanned like any other file; their findings are classified
    # as informational afterwards.
    scannable = [
        f for f in files
        if is_analyzable_path(f.get("path", ""))
        and _file_extension(f.get("path", "")) in SUPPORTED_EXTENSIONS
        and (f.get("patch") or f.get("content"))
    ]

    if not scannable:
        return [], []

    prepared: List[Dict[str, Any]] = []
    for file_info in scannable:
        content = _extract_scan_content(file_info)
        prepared.append({
            "path": file_info["path"],
            "content": content,
            "size": len(content.encode("utf-8")),
        })

    batches = build_scan_batches(prepared)
    print(
        "OpenGrep scan batches: "
        f"count={len(batches)} files={len(prepared)} "
        f"max_files={batch_max_files()} max_bytes={batch_max_bytes()} "
        f"batch_bytes={[sum(entry['size'] for entry in batch) for batch in batches]} "
        f"batch_files={[len(batch) for batch in batches]}",
        flush=True,
    )

    findings: List[Dict[str, Any]] = []
    limitations: List[Dict[str, Any]] = []
    for index, batch in enumerate(batches, start=1):
        batch_bytes = sum(entry["size"] for entry in batch)
        print(
            f"OpenGrep batch {index}/{len(batches)}: files={len(batch)} bytes={batch_bytes}",
            flush=True,
        )
        batch_findings, batch_limitations = _scan_batch(batch)
        findings.extend(batch_findings)
        limitations.extend(batch_limitations)

    return classify_findings(findings), _dedupe_limitations(limitations)


def _dedupe_limitations(limitations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One entry per (path, kind); the same file can trip the same limit twice."""
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for limitation in limitations:
        key = (limitation.get("path"), limitation.get("kind"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(limitation)
    return deduped
