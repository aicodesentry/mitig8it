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


def _extract_file_content(patch: str) -> str:
    """Extract added lines from a unified diff patch."""
    if not patch:
        return ""
    lines = []
    for line in patch.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            candidate = line[1:]
            if not is_transcript_artifact_line(candidate):
                lines.append(candidate)
        elif not line.startswith("-") and not line.startswith("@@"):
            if not is_transcript_artifact_line(line):
                lines.append(line)
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


def _run_semgrep(target_dir: str) -> Dict[str, Any]:
    """Run one scanner process over one batch directory and return its output."""
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
        raise RuntimeError(f"OpenGrep failed with exit code {result.returncode}")

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("OpenGrep returned invalid JSON")

    if not isinstance(output, dict) or not isinstance(output.get("results"), list):
        raise RuntimeError("OpenGrep returned an incomplete result")
    if output.get("errors"):
        raise RuntimeError("OpenGrep reported incomplete analysis")

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
        internal_type=metadata.get("internal_type", check_id),
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


def _scan_batch(batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan one batch. Any failure raises, so the tier fails closed."""
    findings: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="mitig8it_") as tmpdir:
        extracted_content_by_path: Dict[str, str] = {}
        for entry in batch:
            file_path = Path(tmpdir) / entry["path"]
            file_path.parent.mkdir(parents=True, exist_ok=True)
            extracted_content_by_path[entry["path"]] = entry["content"]
            file_path.write_text(entry["content"], encoding="utf-8")

        output = _run_semgrep(tmpdir)

        for match in output.get("results", []):
            findings.append(_build_finding(match, tmpdir, extracted_content_by_path))

    return findings


def run_opengrep(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run OpenGrep on PR files and return findings.

    Files are scanned in bounded batches and the results are merged. If any
    batch fails the whole tier fails closed; partial results are never returned
    as if they were complete.

    Args:
        files: List of {path, patch, additions, ...} from the PR diff.

    Returns:
        List of finding dicts matching Tier 1 format.
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
        return []

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
    for index, batch in enumerate(batches, start=1):
        batch_bytes = sum(entry["size"] for entry in batch)
        print(
            f"OpenGrep batch {index}/{len(batches)}: files={len(batch)} bytes={batch_bytes}",
            flush=True,
        )
        findings.extend(_scan_batch(batch))

    return classify_findings(findings)
