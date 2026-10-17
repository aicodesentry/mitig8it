"""
Tier 3: LLM-powered triage of Tier 1+2 findings.

Reviews existing findings against code context, filters false positives,
and enriches with reasoning. Non-blocking: returns original findings on failure.
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from llm_client import call_llm, is_llm_configured, redact
from prometheus_client import Counter, Histogram
from remediation_patches import build_remediation_patch

# ── Metrics ─────────────────────────────────────────────────────────────

LLM_TRIAGE_REQUESTS = Counter(
    "codesentry_llm_triage_requests_total",
    "Total LLM triage calls",
    ["status"],
)
LLM_TRIAGE_DURATION = Histogram(
    "codesentry_llm_triage_duration_seconds",
    "LLM triage call runtime",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60],
)
LLM_TRIAGE_VERDICTS = Counter(
    "codesentry_llm_triage_verdicts_total",
    "Verdicts returned by LLM triage",
    ["verdict"],
)
LLM_TRIAGE_TOKENS = Counter(
    "codesentry_llm_triage_tokens_total",
    "Tokens consumed by LLM triage",
    ["direction"],
)
LLM_TRIAGE_DOWNGRADES = Counter(
    "codesentry_llm_triage_downgrades_total",
    "Verdicts the service lowered to uncertain after the model answered",
    ["reason"],
)
LLM_TRIAGE_CRITIC = Counter(
    "codesentry_llm_triage_critic_total",
    "Patch critic outcomes on proposed fixed_code",
    ["outcome"],
)
LLM_TRIAGE_BUDGET_REFUSALS = Counter(
    "codesentry_llm_triage_budget_refusals_total",
    "Calls not made because the per-run call or token cap was reached",
    ["kind"],
)

# ── Configuration ───────────────────────────────────────────────────────

LLM_TRIAGE_TIMEOUT = int(os.getenv("LLM_TRIAGE_TIMEOUT_SECONDS", "45"))
LLM_TRIAGE_MAX_FINDINGS = int(os.getenv("LLM_TRIAGE_MAX_FINDINGS", "100"))

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# The verdict-shaping settings are read per run, not at import, so a deployment can turn
# them without a restart and a test can set them with the environment.
_FALSE_VALUES = {"0", "false", "no", "off"}
DEFAULT_ISOLATE_SEVERITY = "high"
DEFAULT_MAX_CALLS = 24
DEFAULT_MAX_TOKENS = 300_000
PAYLOAD_REQUIRED_RANK = SEVERITY_RANK["high"]


def _env_flag(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw not in _FALSE_VALUES


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def isolate_severity_rank() -> int:
    """Findings at or above this rank are triaged one per call. 0 turns isolation off."""
    raw = (os.getenv("LLM_TRIAGE_ISOLATE_SEVERITY") or DEFAULT_ISOLATE_SEVERITY).strip().lower()
    if raw in {"none", "off", "false", "0"}:
        return 0
    return SEVERITY_RANK.get(raw, SEVERITY_RANK[DEFAULT_ISOLATE_SEVERITY])


def high_severity_model() -> Optional[str]:
    """The model for isolated calls and the patch critic; None means the batch model."""
    return (os.getenv("LLM_TRIAGE_MODEL_HIGH") or "").strip() or None


def require_payload() -> bool:
    return _env_flag("LLM_TRIAGE_REQUIRE_PAYLOAD", True)


def critic_enabled() -> bool:
    return _env_flag("LLM_TRIAGE_CRITIC_ENABLED", True)


def max_calls_per_run() -> int:
    return _env_int("LLM_TRIAGE_MAX_CALLS", DEFAULT_MAX_CALLS)


def max_tokens_per_run() -> int:
    return _env_int("LLM_TRIAGE_MAX_TOKENS", DEFAULT_MAX_TOKENS)


SYSTEM_PROMPT = """You are a security code reviewer triaging static analysis findings. For each finding you decide whether an attacker can reach the flagged sink with input they control, and you show how.

Work in this order for every finding, and do not skip a step:

1. Reachability first. Name the entry point through which untrusted input enters the changed code (a route, handler, CLI argument, message, file, or environment value) and trace how it reaches the flagged sink. Name every sanitizer, validator, type coercion, allowlist and constant on that path. If the value at the sink is a constant, a hard-coded string, or comes only from trusted configuration, say so: that path is not reachable.

2. Exploit construction second. Write one concrete payload: the entry point as the finding's file plus a line or function and the route or parameter, the literal input an attacker sends, and the effect it has at the sink. "Malicious input" or "attacker-controlled value" is not a payload. If you cannot write one, you have not shown the finding is exploitable.

3. Verdict last. true_positive only when you wrote a concrete payload that reaches the sink. false_positive only when you can point at the line that makes the path unreachable or safe. uncertain otherwise.

Confirmation is not the default. A pattern match on a dangerous function name is not a true positive until a payload reaches it. A library's own definition of a helper (for example a framework defining its redirect function) is a false positive when no caller input reaches it in the changed code. A path that is sanitized, resolved inside a fixed base directory, or checked against an allowlist is a false positive unless you can show the bypass.

For each finding, you have the detection metadata, the code context from the PR diff, and optionally a repository profile describing the repo's framework, auth patterns, database usage, and security posture.

Some findings also include structured analysis evidence from deterministic tiers:
- analysis_scope: whether the evidence is pattern-based or taint/dataflow-based
- source: where attacker-controlled input originates
- sink: the dangerous operation reached by that input
- sanitizers_seen: sanitizers or validators observed by the deterministic layer
- trace_summary: a short summary of the deterministic flow

Treat structured analysis evidence as stronger than raw pattern text. If a finding has source/sink or trace data, start the reachability argument from that evidence and use the patch plus repo profile to decide whether the flow is real, sanitized, reachable, or contextually safe.

Use the repository context:
- If the repo uses parameterized queries, check if THIS specific code follows that pattern or bypasses it.
- If auth middleware exists, check if the affected endpoint has it applied.
- If a validation library is present, check if it covers this input path.
- Test code, example code and dead code do not carry a reachable sink.

When proposing a fix, use the finding metadata, the changed code, and the repository profile together:
- Match the repository's framework, language, and validation/auth/query patterns.
- Prefer the smallest safe replacement that can be applied directly on the changed line or small block.
- Do not invent helper functions, imports, or large refactors unless they already exist in the changed lines.
- If you are not confident the fix can be expressed as a drop-in replacement for the flagged lines, return null for fixed_code.

Respond with ONLY a JSON array. Each element must have:
- "fingerprint": the finding's fingerprint (string, copied from input)
- "reachability": 1-3 sentences tracing input from the entry point to the sink, or stating which line stops it
- "exploit_payload": null, or {"entrypoint": "the finding's file with a line or function, and the route or parameter", "input": "the literal value the attacker sends", "expected_effect": "what happens at the sink"}. Required for every true_positive. The entrypoint must name the finding's file.
- "verdict": one of "true_positive", "false_positive", "uncertain"
- "reasoning": 1-2 sentence explanation
- "adjusted_severity": null or one of "critical", "high", "medium", "low"
- "adjusted_confidence": null or a float 0.0-1.0
- "exploit_scenario": null or a 1-2 sentence attacker-focused impact statement grounded in this code
- "remediation": null or a concise actionable fix recommendation
- "fixed_code": null or the exact replacement code lines (only for true_positive findings where you are confident in the fix)

For fixed_code:
- Match the repo's existing code patterns and conventions
- Provide a drop-in replacement for the flagged lines
- Only include the fixed lines, not surrounding context
- Return at most 8 lines
- Do not wrap the code in markdown fences
- Do not include explanations or comments unless the existing code style already uses them on that line/block

Do not include any text outside the JSON array."""

CRITIC_SYSTEM_PROMPT = """You are an adversarial reviewer of one proposed security patch. You are given the finding, the original lines, the proposed replacement lines, the surrounding diff, and the exploit payload that reached the sink before the patch.

Your task is to break the patch. Try the original payload and its variants against the patched lines: different encodings, case, nesting, type confusion, other parameters, and other call sites visible in the diff. Decide whether any concrete input still reaches the dangerous sink, or still produces the same effect, after the patch is applied.

Rules:
- A counterexample is a literal input a caller can send plus a short statement of how it reaches the sink through the patched code. Speculation without a path is not a counterexample.
- If the patch removes the sink, or makes the path unreachable for every input you can construct, there is no counterexample.
- Also note, in one sentence, what the patch may break for legitimate callers: a changed return type, a thrown error, removed behaviour. Write "none" if nothing.

Respond with ONLY a JSON object:
{"counterexample": null or {"input": "literal input", "path": "how it reaches the sink after the patch"}, "behavior_risk": "one sentence, or none"}

Do not include any text outside the JSON object."""

# Values a model writes when it has no payload but was told to fill the field.
_PLACEHOLDER_VALUES = {
    "", "-", "...", "n/a", "na", "none", "null", "nil", "unknown", "tbd", "todo", "any",
    "example", "placeholder", "not applicable", "not provided", "not available", "unspecified",
    "see above", "see reasoning", "string", "value", "input", "payload", "attacker input",
    "attacker-controlled input", "malicious input", "user input", "untrusted input",
}
# Identifiers from the flagged line that do not single out this sink.
_COMMON_IDENTIFIERS = {
    "const", "return", "function", "import", "export", "require", "from", "where", "select",
    "insert", "update", "delete", "true", "false", "null", "none", "this", "self", "await",
    "async", "query", "string", "number", "object", "value", "result", "data", "error",
    "class", "public", "private", "static", "void", "else", "elif", "while", "with", "print",
}


def is_llm_triage_enabled() -> bool:
    return is_llm_configured()


def _select_findings_for_triage(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Select up to LLM_TRIAGE_MAX_FINDINGS for triage.

    Priority: higher severity + lower confidence = more value from triage.
    """
    scored = []
    for f in findings:
        sev = SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0)
        conf = float(f.get("confidence", 0.5))
        patchable_bonus = 2 if _is_likely_patchable(f) else 0
        # High severity + low confidence = highest triage value
        score = sev * 2 + (1 - conf) + patchable_bonus
        scored.append((score, f))

    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored[:LLM_TRIAGE_MAX_FINDINGS]]


def _build_finding_context(
    finding: Dict[str, Any],
    file_patches: Dict[str, str],
) -> Dict[str, Any]:
    """Extract minimal context for a single finding."""
    file_path = finding.get("file_path", "")
    patch = file_patches.get(file_path, "")

    # Send at most 60 lines of patch context around the finding
    patch_lines = patch.split("\n") if patch else []
    if len(patch_lines) > 60:
        target_line = finding.get("line_start", 1)
        start = max(0, target_line - 30)
        patch_lines = patch_lines[start:start + 60]

    evidence_details = finding.get("evidence_details") or {}
    analysis_scope = finding.get("analysis_scope") or evidence_details.get("analysis_scope", "pattern")
    sanitizers_seen = finding.get("sanitizers_seen")
    if sanitizers_seen is None:
        sanitizers_seen = evidence_details.get("sanitizer_exprs", [])
    evidence_strength = _evidence_strength(finding)
    trace_features = _trace_features(finding)
    auto_fix_eligible = _is_auto_fix_eligible(finding)

    return {
        "fingerprint": finding.get("fingerprint", ""),
        "rule_id": finding.get("rule_id", ""),
        "title": finding.get("title", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", 0),
        "cwe_id": finding.get("cwe_id", ""),
        "file_path": file_path,
        "line_start": finding.get("line_start", 0),
        "line_end": finding.get("line_end", 0),
        "code_snippet": finding.get("code_snippet", ""),
        "evidence": finding.get("evidence", ""),
        "description": finding.get("description", ""),
        "remediation_hint": finding.get("remediation", ""),
        "exploit_scenario": finding.get("exploit_scenario", ""),
        "analysis_scope": analysis_scope,
        "source": finding.get("source") or evidence_details.get("source_type"),
        "sink": finding.get("sink") or evidence_details.get("sink_type"),
        "sanitizers_seen": sanitizers_seen or [],
        "sanitizer_status": _sanitizer_status(finding),
        "trace_summary": finding.get("trace_summary") or evidence_details.get("trace_summary"),
        "evidence_strength": evidence_strength,
        "reviewability": evidence_details.get("reviewability", "changed-lines-only"),
        "inline_fix_eligible": _is_inline_reviewable(finding),
        "auto_fix_eligible": auto_fix_eligible,
        "is_taint_based": bool(evidence_details.get("is_taint_based") or str(analysis_scope).startswith("taint")),
        "source_expr": evidence_details.get("source_expr"),
        "sink_expr": evidence_details.get("sink_expr"),
        "fix_scope": _fix_scope(finding),
        "fix_target_line": evidence_details.get("fix_target_line"),
        "fix_target_expr": evidence_details.get("fix_target_expr"),
        "missing_control_type": _missing_control_type(finding),
        "trace_steps": evidence_details.get("trace_steps", []),
        "trace_length": trace_features["trace_length"],
        "trace_kinds": trace_features["trace_kinds"],
        "trace_quality": trace_features["trace_quality"],
        "has_meaningful_trace": trace_features["has_meaningful_trace"],
        "surrounding_code": "\n".join(patch_lines),
    }


def _evidence_strength(finding: Dict[str, Any]) -> str:
    evidence_details = finding.get("evidence_details") or {}
    analysis_scope = str(
        finding.get("analysis_scope")
        or evidence_details.get("analysis_scope")
        or "pattern"
    )
    if analysis_scope.startswith("taint"):
        return "strong"
    if analysis_scope in ("ast-pattern", "ast-match"):
        return "medium"
    return "light"


def _reviewability(finding: Dict[str, Any]) -> str:
    evidence_details = finding.get("evidence_details") or {}
    return str(evidence_details.get("reviewability") or "changed-lines-only").strip().lower()


def _is_inline_reviewable(finding: Dict[str, Any]) -> bool:
    return _reviewability(finding) not in {"context-only", "unreviewable"}


def _has_sanitizer_signal(finding: Dict[str, Any]) -> bool:
    sanitizers_seen = finding.get("sanitizers_seen")
    if sanitizers_seen:
        return True
    evidence_details = finding.get("evidence_details") or {}
    return bool(evidence_details.get("sanitizer_exprs"))


def _missing_control_type(finding: Dict[str, Any]) -> Optional[str]:
    evidence_details = finding.get("evidence_details") or {}
    missing_control = evidence_details.get("missing_control_type")
    if missing_control is None:
        return None

    normalized = str(missing_control).strip()
    return normalized or None


def _fix_scope(finding: Dict[str, Any]) -> str:
    evidence_details = finding.get("evidence_details") or {}
    scope = str(evidence_details.get("fix_scope") or "").strip().lower()
    if scope in {"line", "block"}:
        return scope
    return "unknown"


def _is_auto_fix_eligible(finding: Dict[str, Any]) -> bool:
    evidence_details = finding.get("evidence_details") or {}
    if "auto_fix_eligible" not in evidence_details:
        return False
    return bool(evidence_details.get("auto_fix_eligible"))


def _count_meaningful_lines(text: Any) -> int:
    return len([line for line in str(text or "").split("\n") if line.strip()])


def _is_safe_deterministic_autofix_candidate(finding: Dict[str, Any]) -> bool:
    if not _is_auto_fix_eligible(finding):
        return False
    if not _is_inline_reviewable(finding):
        return False

    analysis_scope = str(
        finding.get("analysis_scope")
        or (finding.get("evidence_details") or {}).get("analysis_scope")
        or "pattern"
    ).strip().lower()
    if analysis_scope.startswith("taint") or analysis_scope in {"ast-pattern", "ast-match"}:
        return False

    fix_scope = _fix_scope(finding)
    if fix_scope not in {"line", "block"}:
        return False

    patch = _normalize_fixed_code(
        finding.get("remediation_patch") or _build_fallback_fixed_code(finding),
        finding.get("code_snippet", ""),
    )
    if not patch or _count_meaningful_lines(patch) > 8:
        return False

    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    cwe_id = str(finding.get("cwe_id", "")).upper()
    allowed_cwes = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-295", "CWE-327", "CWE-502", "CWE-798"}

    return (
        cwe_id in allowed_cwes
        or "sql" in category
        or "secret" in category
        or "code injection" in category
        or "command injection" in category
        or "xss" in category
        or "hardcoded secret" in title
        or "weak hash" in title
        or "unsafe yaml" in title
    )


def _sanitizer_status(finding: Dict[str, Any]) -> str:
    evidence_details = finding.get("evidence_details") or {}
    status = str(evidence_details.get("sanitizer_status") or "").strip().lower()
    if status in {"none", "present", "present-but-insufficient", "validated"}:
        return status
    return "present" if _has_sanitizer_signal(finding) else "none"


def _trace_features(finding: Dict[str, Any]) -> Dict[str, Any]:
    evidence_details = finding.get("evidence_details") or {}
    trace_steps = evidence_details.get("trace_steps") or []
    if not isinstance(trace_steps, list):
        trace_steps = []
    analysis_scope = str(
        finding.get("analysis_scope")
        or evidence_details.get("analysis_scope")
        or "pattern"
    )

    trace_kinds = [str(step.get("kind") or "").strip().lower() for step in trace_steps if isinstance(step, dict)]
    has_source = "source" in trace_kinds
    has_sink = "sink" in trace_kinds
    has_assignment = "assignment" in trace_kinds
    has_call = "call" in trace_kinds
    has_sanitizer = "sanitizer" in trace_kinds
    propagation_count = sum(1 for kind in trace_kinds if kind in {"assignment", "call"})
    has_meaningful_trace = has_source and has_sink

    if not trace_kinds:
        trace_quality = "moderate" if analysis_scope.startswith("taint") else "none"
    elif has_source and has_sink and (propagation_count > 0 or has_sanitizer):
        trace_quality = "strong"
    elif has_source and has_sink:
        trace_quality = "moderate"
    else:
        trace_quality = "weak"

    return {
        "trace_length": len(trace_steps),
        "trace_kinds": trace_kinds,
        "trace_quality": trace_quality,
        "has_meaningful_trace": has_meaningful_trace,
        "has_source_step": has_source,
        "has_sink_step": has_sink,
        "has_assignment_step": has_assignment,
        "has_call_step": has_call,
        "has_sanitizer_step": has_sanitizer,
        "has_only_source_and_sink": has_source and has_sink and len(trace_kinds) == 2,
    }


def _leading_whitespace(line: str) -> str:
    stripped = line.lstrip()
    return line[: len(line) - len(stripped)]


def _normalize_fixed_code(fixed_code: Any, original_snippet: str) -> Optional[str]:
    if fixed_code is None:
        return None

    raw = str(fixed_code)
    if not raw.strip():
        return None

    if raw.lstrip().startswith("```"):
        stripped = raw.strip()
        parts = stripped.split("```")
        if len(parts) >= 3:
            body = parts[1]
            if body.startswith(("json", "javascript", "python", "ts", "typescript", "go", "java", "ruby", "php", "csharp")):
                body = body.split("\n", 1)[1] if "\n" in body else ""
            raw = body

    if "```" in raw:
        return None

    raw = raw.replace("\r\n", "\n")

    lines = raw.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return None

    lines = [line.rstrip() for line in lines]

    original_lines = [ln for ln in str(original_snippet or "").split("\n") if ln.strip()]
    original_indent = _leading_whitespace(original_lines[0]) if original_lines else ""

    content_lines = [ln for ln in lines if ln.strip()]
    if content_lines and original_indent:
        fixed_indent = min((_leading_whitespace(ln) for ln in content_lines), key=len)
        if len(fixed_indent) < len(original_indent):
            pad = original_indent[len(fixed_indent):]
            lines = [pad + ln if ln.strip() else ln for ln in lines]

    if len(lines) > 8:
        return None

    if len(lines) > max(1, len(original_lines)) + 3:
        return None

    normalized = "\n".join(lines)
    return normalized[:2000]


def _normalize_text(value: Any, max_length: int = 500) -> Optional[str]:
    if value is None:
        return None

    normalized = str(value).strip()
    if not normalized:
        return None

    normalized = normalized.replace("\r\n", "\n")
    if normalized.startswith("```"):
        parts = normalized.split("```")
        if len(parts) >= 3:
            normalized = parts[1]
            if "\n" in normalized:
                normalized = normalized.split("\n", 1)[1]
        normalized = normalized.strip()

    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized[:max_length] if normalized else None


def _build_fallback_fixed_code(
    finding: Dict[str, Any],
) -> Optional[str]:
    return build_remediation_patch(finding)


def _should_attach_auto_fix(
    finding: Dict[str, Any],
    trace_features: Dict[str, Any],
    sanitizer_status: str,
) -> bool:
    if not _is_auto_fix_eligible(finding):
        return False
    if not _is_inline_reviewable(finding):
        return False
    if sanitizer_status == "validated":
        return False
    if trace_features["trace_quality"] in {"strong", "moderate"}:
        return True
    return _is_safe_deterministic_autofix_candidate(finding)


def _is_likely_patchable(finding: Dict[str, Any]) -> bool:
    return _build_fallback_fixed_code(finding) is not None


def _build_fallback_exploit_scenario(finding: Dict[str, Any]) -> Optional[str]:
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    cwe_id = str(finding.get("cwe_id", "")).upper()

    if "sql" in category or cwe_id == "CWE-89":
        return "An attacker who controls this input can alter the SQL query and read or modify unintended database records."

    if "xss" in category or "cross-site scripting" in title or cwe_id == "CWE-79":
        return "An attacker can inject script into rendered output and execute code in another user's browser session."

    if "code injection" in category or "eval" in title or cwe_id == "CWE-94":
        return "An attacker who reaches this path with controlled input may execute unintended code within the application context."

    if "secret" in category or cwe_id == "CWE-798":
        return "If this secret is exposed through the repository, logs, or build artifacts, an attacker can reuse it to access protected systems."

    if "path traversal" in category or cwe_id == "CWE-22":
        return "An attacker can manipulate the path input to read or overwrite files outside the intended directory."

    return "If attacker-controlled input reaches this code path, it may trigger the vulnerable behavior and impact confidentiality, integrity, or availability."


def _build_fallback_remediation(finding: Dict[str, Any]) -> Optional[str]:
    existing = _normalize_text(finding.get("remediation"), max_length=300)
    if existing:
        return existing

    missing_control_type = _missing_control_type(finding)
    if missing_control_type == "base_dir_validation":
        return "Resolve the requested path within a fixed base directory and reject paths that escape it."
    if missing_control_type == "relative_or_allowlisted_redirect_validation":
        return "Restrict redirect targets to relative paths or an explicit allowlist of trusted destinations."
    if missing_control_type == "host_or_scheme_allowlist":
        return "Validate the outbound URL against trusted hosts and allowed schemes before making the request."
    if missing_control_type == "html_sanitization_or_safe_text_rendering":
        return "Render untrusted content through a safe text API or sanitize it before writing HTML."
    if missing_control_type == "output_encoding":
        return "Apply the correct output encoding for this sink before rendering untrusted content."

    category = str(finding.get("category", "")).lower()
    cwe_id = str(finding.get("cwe_id", "")).upper()

    if "sql" in category or cwe_id == "CWE-89":
        return "Use parameterized queries and avoid building SQL with string concatenation."

    if "xss" in category or cwe_id == "CWE-79":
        return "Encode or sanitize untrusted output before rendering it in the browser."

    if "code injection" in category or cwe_id == "CWE-94":
        return "Remove dynamic code execution and parse or validate untrusted input with a safe alternative."

    if "secret" in category or cwe_id == "CWE-798":
        return "Move the secret into environment or secret-manager configuration and rotate the exposed credential."

    if "path traversal" in category or cwe_id == "CWE-22":
        return "Validate the requested path against an allowlist and resolve it within a fixed base directory."

    return "Replace the unsafe pattern with a validated, framework-consistent safe alternative."


def _build_triage_prompt(
    findings: List[Dict[str, Any]],
    file_patches: Dict[str, str],
    repo_profile: Optional[Dict[str, Any]] = None,
) -> str:
    """Build the user prompt with findings, code context, and repo profile."""
    parts = []

    if repo_profile and (repo_profile.get("deterministic") or repo_profile.get("interpreted")):
        det = repo_profile.get("deterministic", {})
        interp = repo_profile.get("interpreted", {})
        parts.append("## Repository Profile\n")
        if det.get("framework"):
            parts.append(f"- Framework: {det['framework']}")
        if det.get("languages"):
            parts.append(f"- Languages: {', '.join(det['languages'])}")
        if det.get("database"):
            parts.append(f"- Database: {json.dumps(det['database'])}")
        if det.get("security_libraries"):
            libs = [f"{l['library']} ({l['purpose']})" for l in det["security_libraries"]]
            parts.append(f"- Security libraries: {', '.join(libs)}")
        if interp.get("auth_strategy"):
            parts.append(f"- Auth: {interp['auth_strategy']}")
        if interp.get("database_pattern"):
            parts.append(f"- Query pattern: {interp['database_pattern']}")
        if interp.get("risk_areas"):
            parts.append(f"- Risk areas: {', '.join(interp['risk_areas'])}")
        parts.append("")

    parts.append(
        "## Triage Rules\n"
        "- Treat findings with evidence_strength=strength 'strong' and is_taint_based=true as higher-trust deterministic evidence.\n"
        "- Do not dismiss strong taint findings unless the patch or repo profile shows a real sanitizer, safe wrapper, or unreachable code path.\n"
        "- If sanitizers_seen is non-empty, explicitly evaluate whether those sanitizers are sufficient for this sink before returning true_positive.\n"
        "- Treat sanitizer_status=validated as materially stronger than sanitizer presence alone; it should usually weaken or eliminate the finding unless the trace shows a bypass.\n"
        "- Treat sanitizer_status=present-but-insufficient as a sign to keep the finding but avoid overstating confidence.\n"
        "- Pattern-only findings require more caution; if repo context weakens them, prefer uncertain over overconfident true_positive.\n"
        "- If reviewability is context-only, prefer uncertain unless the deterministic trace is strong, specific, and still actionable from the changed code.\n"
        "- Treat trace_quality=strong as materially better evidence than a source/sink summary alone.\n"
        "- If trace_quality=weak or none, prefer uncertain unless other repo context strongly confirms exploitability.\n"
        "- If trace_quality=moderate, avoid overstating certainty unless the sink and input control are both clear.\n"
        "- Use missing_control_type to anchor remediation to the missing safeguard instead of giving generic advice.\n"
        "- Treat fix_scope=line as a narrow drop-in replacement and fix_scope=block as a small local rewrite only.\n"
        "- Only return fixed_code when inline_fix_eligible=true, auto_fix_eligible=true, and the replacement fits directly on the changed lines or a very small changed block.\n"
        "- If auto_fix_eligible=false, you may still confirm the finding, but do not return fixed_code.\n"
        "- If sanitizer sufficiency is ambiguous, prefer uncertain over a confident true_positive with a speculative fix.\n"
    )
    parts.append("")

    contexts = [_build_finding_context(f, file_patches) for f in findings]
    parts.append("## Findings to triage\n\n" + json.dumps(contexts, indent=2))

    return "\n".join(parts)


def _call_triage_llm(
    user_prompt: str,
    model: Optional[str] = None,
    system_prompt: str = SYSTEM_PROMPT,
) -> tuple[str, int, int]:
    """Call the configured LLM provider. Returns (response_text, input_tokens, output_tokens).

    `model` is passed only when set, so a wrapper around `call_llm` that predates the
    argument still works and the configured model is used by default."""
    kwargs: Dict[str, Any] = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "timeout_seconds": LLM_TRIAGE_TIMEOUT,
        "temperature": 0,
        "max_output_tokens": 4096,
    }
    if model:
        kwargs["model"] = model
    response = call_llm(**kwargs)
    return response.text, response.input_tokens, response.output_tokens


# ── Budget ──────────────────────────────────────────────────────────────


class TriageBudget:
    """The calls and tokens one triage run may spend. Checked before every call."""

    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.refused_calls = 0
        self.refused_findings = 0

    def allows_call(self) -> bool:
        if self.calls >= self.max_calls:
            return False
        return (self.input_tokens + self.output_tokens) < self.max_tokens

    def refuse(self, kind: str, findings: int = 0) -> None:
        self.refused_calls += 1
        self.refused_findings += findings
        LLM_TRIAGE_BUDGET_REFUSALS.labels(kind=kind).inc()

    def record(self, input_tokens: int, output_tokens: int) -> None:
        self.calls += 1
        self.input_tokens += int(input_tokens or 0)
        self.output_tokens += int(output_tokens or 0)
        LLM_TRIAGE_TOKENS.labels(direction="input").inc(int(input_tokens or 0))
        LLM_TRIAGE_TOKENS.labels(direction="output").inc(int(output_tokens or 0))

    def summary(self) -> str:
        return (
            f"{self.calls}/{self.max_calls} calls, "
            f"{self.input_tokens + self.output_tokens}/{self.max_tokens} tokens, "
            f"{self.refused_calls} calls refused covering {self.refused_findings} findings"
        )


# ── Exploit payload ─────────────────────────────────────────────────────


def _payload_field(payload: Dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    return re.sub(r"\s+", " ", value).strip()[:500]


def _is_placeholder(text: str) -> bool:
    low = text.strip().lower().strip("<>[]{}()\"'`.: ")
    if low in _PLACEHOLDER_VALUES or len(low) < 3:
        return True
    return text.strip().startswith("<") and text.strip().endswith(">")


def _sink_identifiers(finding: Dict[str, Any]) -> set:
    evidence_details = finding.get("evidence_details") or {}
    texts = [
        finding.get("code_snippet"), evidence_details.get("sink_expr"),
        evidence_details.get("source_expr"), evidence_details.get("fix_target_expr"),
    ]
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", " ".join(str(t or "") for t in texts)))
    return {t for t in tokens if t.lower() not in _COMMON_IDENTIFIERS}


def _payload_references_sink(text: str, finding: Dict[str, Any]) -> bool:
    """The payload names the finding's file, or an identifier from the flagged line."""
    low = text.lower()
    file_path = str(finding.get("file_path") or "").strip()
    if file_path and file_path.lower() in low:
        return True
    basename = file_path.rsplit("/", 1)[-1]
    if basename and basename.lower() in low:
        return True
    return any(identifier.lower() in low for identifier in _sink_identifiers(finding))


# A token that reads as a source file name: a path segment ending in a code extension.
_FILE_TOKEN = re.compile(
    r"[A-Za-z0-9_.\-/]*[A-Za-z0-9_\-]\.(?:js|jsx|mjs|cjs|ts|tsx|py|rb|go|java|php|cs|kt|rs|vue|html|hbs|ejs|pug)\b",
    re.IGNORECASE,
)


def _entrypoint_is_off_file(entrypoint: str, finding: Dict[str, Any]) -> bool:
    """The entrypoint names one or more source files and none of them is the finding's. A
    payload that starts somewhere the reviewer cannot see in this diff is not concrete."""
    named = [token.lower().lstrip("./") for token in _FILE_TOKEN.findall(entrypoint)]
    if not named:
        return False
    file_path = str(finding.get("file_path") or "").strip().lower()
    if not file_path:
        return False
    basename = file_path.rsplit("/", 1)[-1]
    return not any(
        token in {file_path, basename} or file_path.endswith("/" + token) or token.endswith("/" + file_path)
        for token in named
    )


def _concrete_payload(raw: Any, finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """The payload as three strings, or None when a part is missing, a placeholder, the
    entrypoint names only other files, or nothing in it names the sink's file or the
    flagged line."""
    if not isinstance(raw, dict):
        return None
    fields = {key: _payload_field(raw, key) for key in ("entrypoint", "input", "expected_effect")}
    if any(_is_placeholder(value) for value in fields.values()):
        return None
    if _entrypoint_is_off_file(fields["entrypoint"], finding):
        return None
    if not _payload_references_sink(fields["entrypoint"] + " " + fields["input"], finding):
        return None
    return fields


def _effective_severity_rank(finding: Dict[str, Any], verdict: Dict[str, Any]) -> int:
    ranks = [SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), 0)]
    adjusted = verdict.get("adjusted_severity")
    if adjusted in SEVERITY_RANK:
        ranks.append(SEVERITY_RANK[adjusted])
    return max(ranks)


def _require_concrete_payloads(
    verdicts: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    enforce: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """Normalise each verdict's payload and lower a high or critical true_positive that has
    none to uncertain, with the reason on the verdict for `_apply_verdicts` to record."""
    if enforce is None:
        enforce = require_payload()
    by_fingerprint = {f.get("fingerprint", ""): f for f in findings}
    result = []
    for verdict in verdicts:
        finding = by_fingerprint.get(verdict.get("fingerprint", ""))
        updated = dict(verdict)
        payload = _concrete_payload(verdict.get("exploit_payload"), finding) if finding else None
        updated["exploit_payload"] = payload
        if (
            enforce
            and finding is not None
            and updated["verdict"] == "true_positive"
            and payload is None
            and _effective_severity_rank(finding, updated) >= PAYLOAD_REQUIRED_RANK
        ):
            updated["verdict"] = "uncertain"
            updated["downgrade"] = {"from": "true_positive", "to": "uncertain", "reason": "no_concrete_payload"}
        result.append(updated)
    return result


def _fail_closed_verdicts(findings: List[Dict[str, Any]], reason: str) -> List[Dict[str, Any]]:
    """Uncertain verdicts for findings whose call produced nothing usable. The finding is
    kept, nothing is boosted, and no fix is attached."""
    return [
        {
            "fingerprint": f.get("fingerprint", ""),
            "verdict": "uncertain",
            "reasoning": f"Triage response could not be used ({reason}); the finding is kept without a verdict.",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploit_scenario": None,
            "remediation": None,
            "fixed_code": None,
            "exploit_payload": None,
            "reachability": None,
            "downgrade": {"to": "uncertain", "reason": reason},
        }
        for f in findings
    ]


# ── Patch critic ────────────────────────────────────────────────────────


def _build_critic_prompt(
    finding: Dict[str, Any],
    fixed_code: str,
    payload: Optional[Dict[str, str]],
    file_patches: Dict[str, str],
) -> str:
    context = _build_finding_context(finding, file_patches)
    summary = {
        key: context.get(key)
        for key in (
            "rule_id", "title", "cwe_id", "category", "file_path", "line_start", "line_end",
            "sink", "sink_expr", "source", "source_expr", "sanitizers_seen", "missing_control_type",
        )
    }
    parts = [
        "## Finding\n" + json.dumps(summary, indent=2),
        "## Exploit payload before the patch\n" + json.dumps(payload or {"note": "no concrete payload was recorded"}, indent=2),
        "## Original lines\n" + str(finding.get("code_snippet") or ""),
        "## Proposed replacement\n" + fixed_code,
        "## Surrounding diff\n" + str(context.get("surrounding_code") or ""),
    ]
    return "\n\n".join(parts)


def _parse_critic_response(raw: str) -> Dict[str, Any]:
    """{"counterexample": dict or None, "behavior_risk": str or None}. Raises on junk."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    if text.strip().upper() == "NONE":
        return {"counterexample": None, "behavior_risk": None}

    parsed = json.loads(text)
    if isinstance(parsed, str):
        if parsed.strip().upper() == "NONE":
            return {"counterexample": None, "behavior_risk": None}
        raise json.JSONDecodeError("critic answered with a bare string", text, 0)
    if not isinstance(parsed, dict):
        raise json.JSONDecodeError("critic answer is not an object", text, 0)

    counterexample = parsed.get("counterexample")
    behavior_risk = _normalize_text(parsed.get("behavior_risk"), max_length=300)
    if behavior_risk and behavior_risk.lower().strip(".") == "none":
        behavior_risk = None

    if isinstance(counterexample, str):
        counterexample = {"input": counterexample, "path": ""} if not _is_placeholder(counterexample) else None
    if isinstance(counterexample, dict):
        normalized = {
            "input": _payload_field(counterexample, "input"),
            "path": _payload_field(counterexample, "path") or _payload_field(counterexample, "reaches_sink_via"),
        }
        counterexample = normalized if not _is_placeholder(normalized["input"]) else None
    elif counterexample is not None:
        counterexample = None
    return {"counterexample": counterexample, "behavior_risk": behavior_risk}


def _llm_patch_critic(budget: TriageBudget, model: Optional[str], file_patches: Dict[str, str]):
    """A critic bound to this run's budget. Any failure rejects the fix: a patch nobody
    checked is not attached."""

    def critic(finding: Dict[str, Any], fixed_code: str, payload: Optional[Dict[str, str]]) -> Dict[str, Any]:
        if not budget.allows_call():
            budget.refuse("critic", 1)
            return {"accepted": False, "reason": "budget_exhausted", "counterexample": None, "behavior_risk": None}
        prompt = _build_critic_prompt(finding, fixed_code, payload, file_patches)
        try:
            raw, input_tokens, output_tokens = _call_triage_llm(prompt, model=model, system_prompt=CRITIC_SYSTEM_PROMPT)
        except Exception as exc:
            print(f"LLM patch critic failed (fix withheld): {redact(exc)}")
            return {"accepted": False, "reason": "critic_failed", "counterexample": None, "behavior_risk": None}
        budget.record(input_tokens, output_tokens)
        try:
            parsed = _parse_critic_response(raw)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            print(f"LLM patch critic answer not usable (fix withheld): {redact(exc)}")
            return {"accepted": False, "reason": "critic_unparseable", "counterexample": None, "behavior_risk": None}
        if parsed["counterexample"] is not None:
            return {
                "accepted": False,
                "reason": "counterexample",
                "counterexample": parsed["counterexample"],
                "behavior_risk": parsed["behavior_risk"],
            }
        return {"accepted": True, "reason": "no_counterexample", "counterexample": None, "behavior_risk": parsed["behavior_risk"]}

    return critic


def _record_extra(finding: Dict[str, Any], values: Dict[str, Any]) -> None:
    """Write into evidence_details.extra, the one free-form field that crosses gRPC and is
    stored with the finding, so the UI and the outcome log can see what triage did."""
    details = dict(finding.get("evidence_details") or {})
    extra = dict(details.get("extra") or {})
    extra.update({key: value for key, value in values.items() if value is not None})
    details["extra"] = extra
    finding["evidence_details"] = details


def _parse_triage_response(
    raw: str,
    valid_fingerprints: set,
) -> List[Dict[str, Any]]:
    """Parse LLM JSON response into verdict list."""
    text = raw.strip()

    # Handle markdown-fenced JSON
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    parsed = json.loads(text)
    if isinstance(parsed, dict):
        # A model asked for one finding often answers with the object instead of a list of
        # one, or wraps the list. Anything else is an answer nobody can read, and the caller
        # fails it closed rather than letting the findings through untriaged.
        if "fingerprint" in parsed:
            parsed = [parsed]
        else:
            wrapped = next((parsed[key] for key in ("verdicts", "findings", "results") if isinstance(parsed.get(key), list)), None)
            if wrapped is None:
                raise ValueError("triage answer is an object with no verdict list")
            parsed = wrapped
    if not isinstance(parsed, list):
        raise ValueError("triage answer is not a JSON array")

    verdicts = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        fp = item.get("fingerprint", "")
        verdict = item.get("verdict", "")
        if fp not in valid_fingerprints:
            continue
        if verdict not in ("true_positive", "false_positive", "uncertain"):
            continue

        fixed_code = (
            item.get("fixed_code")
            or item.get("remediation_patch")
            or item.get("remediationPatch")
            or item.get("suggested_patch")
            or item.get("patch")
        )

        exploit_payload = item.get("exploit_payload") or item.get("payload") or item.get("exploit")

        verdicts.append({
            "fingerprint": fp,
            "verdict": verdict,
            "reasoning": str(item.get("reasoning", ""))[:500],
            "reachability": _normalize_text(item.get("reachability"), max_length=600),
            "exploit_payload": exploit_payload if isinstance(exploit_payload, dict) else None,
            "adjusted_severity": item.get("adjusted_severity"),
            "adjusted_confidence": item.get("adjusted_confidence"),
            "exploit_scenario": (
                item.get("exploit_scenario")
                or item.get("exploitScenario")
                or item.get("attack_scenario")
                or item.get("impact")
            ),
            "remediation": (
                item.get("remediation")
                or item.get("recommendation")
                or item.get("recommended_fix")
                or item.get("fix")
            ),
            "fixed_code": fixed_code,
        })

    return verdicts


def _apply_verdicts(
    findings: List[Dict[str, Any]],
    verdicts: List[Dict[str, Any]],
    critic=None,
) -> List[Dict[str, Any]]:
    """Apply LLM verdicts to findings.

    - false_positive: Remove from list
    - true_positive: Boost confidence, apply severity adjustment
    - uncertain: Leave unchanged
    - a verdict carrying `downgrade` (set by `_require_concrete_payloads` or
      `_fail_closed_verdicts`) is recorded on the finding, in `llm_triage` and in
      `evidence_details.extra`, and gets no confidence increase
    - `critic`, when given, is called with (finding, fixed_code, payload) before any
      fixed_code is attached, and a rejection withholds the fix
    """
    verdict_map = {v["fingerprint"]: v for v in verdicts}
    result = []
    rejected_fixes: Dict[tuple, Dict[str, Any]] = {}

    for finding in findings:
        fp = finding.get("fingerprint", "")
        verdict = verdict_map.get(fp)

        if verdict is None:
            result.append(finding)
            continue

        LLM_TRIAGE_VERDICTS.labels(verdict=verdict["verdict"]).inc()
        downgrade = verdict.get("downgrade")
        if downgrade:
            LLM_TRIAGE_DOWNGRADES.labels(reason=str(downgrade.get("reason") or "unknown")).inc()

        if verdict["verdict"] == "false_positive":
            continue

        enriched = dict(finding)
        trace_features = _trace_features(enriched)
        payload = verdict.get("exploit_payload") if isinstance(verdict.get("exploit_payload"), dict) else None
        enriched["llm_triage"] = {
            "verdict": verdict["verdict"],
            "reasoning": verdict["reasoning"],
            "reachability": verdict.get("reachability"),
            "exploit_payload": payload,
            "downgrade": downgrade,
            "evidence_strength": _evidence_strength(finding),
            "reviewability": _reviewability(finding),
            "has_sanitizer_signal": _has_sanitizer_signal(finding),
            "sanitizer_status": _sanitizer_status(finding),
            "trace_quality": trace_features["trace_quality"],
            "trace_length": trace_features["trace_length"],
            "fix_scope": _fix_scope(finding),
            "missing_control_type": _missing_control_type(finding),
            "auto_fix_eligible": _is_auto_fix_eligible(finding),
        }
        if downgrade:
            _record_extra(enriched, {
                "triage_downgrade_reason": str(downgrade.get("reason") or "unknown"),
                "triage_downgraded_from": downgrade.get("from"),
            })

        if verdict["verdict"] == "true_positive":
            evidence_strength = _evidence_strength(enriched)
            sanitizer_status = _sanitizer_status(enriched)
            confidence_boost = 0.05 if evidence_strength == "light" else 0.1
            if trace_features["trace_quality"] == "moderate":
                confidence_boost = min(confidence_boost, 0.05)
            elif trace_features["trace_quality"] in {"weak", "none"}:
                confidence_boost = 0.0
            if not _is_inline_reviewable(enriched):
                confidence_boost = min(confidence_boost, 0.02 if evidence_strength == "strong" else 0.0)
            if sanitizer_status == "validated":
                confidence_boost = 0.0
            elif sanitizer_status == "present-but-insufficient":
                confidence_boost = min(confidence_boost, 0.03)
            elif _has_sanitizer_signal(enriched):
                confidence_boost = 0.0 if not _is_inline_reviewable(enriched) else min(confidence_boost, 0.05)
            enriched["confidence"] = round(min(0.99, float(enriched.get("confidence", 0.5)) + confidence_boost), 2)

        adj_sev = verdict.get("adjusted_severity")
        if adj_sev in ("critical", "high", "medium", "low"):
            enriched["severity"] = adj_sev

        adj_conf = verdict.get("adjusted_confidence")
        if adj_conf is not None and isinstance(adj_conf, (int, float)) and 0 <= adj_conf <= 1:
            # A confidence the model attached to a verdict the service lowered may not raise it.
            if not downgrade or adj_conf < float(enriched.get("confidence", 0.5)):
                enriched["confidence"] = round(adj_conf, 2)

        exploit_scenario = _normalize_text(verdict.get("exploit_scenario"))
        if exploit_scenario:
            enriched["exploit_scenario"] = exploit_scenario
        elif not _normalize_text(enriched.get("exploit_scenario")):
            enriched["exploit_scenario"] = _build_fallback_exploit_scenario(enriched)

        remediation = _normalize_text(verdict.get("remediation"), max_length=300)
        if remediation:
            enriched["remediation"] = remediation
        elif not _normalize_text(enriched.get("remediation"), max_length=300):
            enriched["remediation"] = _build_fallback_remediation(enriched)

        fixed_code = _normalize_fixed_code(verdict.get("fixed_code"), finding.get("code_snippet", ""))
        sanitizer_status = _sanitizer_status(enriched)
        if (
            not fixed_code
            and verdict["verdict"] == "true_positive"
            and sanitizer_status in {"none", "present-but-insufficient"}
            and _should_attach_auto_fix(enriched, trace_features, sanitizer_status)
        ):
            fixed_code = _normalize_fixed_code(
                _build_fallback_fixed_code(finding),
                finding.get("code_snippet", ""),
            )
        attach = bool(
            fixed_code
            and verdict["verdict"] == "true_positive"
            and _should_attach_auto_fix(enriched, trace_features, sanitizer_status)
        )
        if attach and critic is not None:
            critic_result = critic(enriched, fixed_code, payload)
            outcome = "accepted" if critic_result.get("accepted") else str(critic_result.get("reason") or "rejected")
            LLM_TRIAGE_CRITIC.labels(outcome=outcome).inc()
            enriched["llm_triage"]["fix_critic"] = critic_result
            _record_extra(enriched, {
                "fix_critic_accepted": bool(critic_result.get("accepted")),
                "fix_critic_reason": str(critic_result.get("reason") or ""),
                "fix_critic_counterexample": (critic_result.get("counterexample") or {}).get("input"),
                "fix_critic_behavior_risk": critic_result.get("behavior_risk"),
            })
            attach = bool(critic_result.get("accepted"))
            if not attach and critic_result.get("reason") == "counterexample":
                rejected_fixes[(str(finding.get("file_path") or ""), fixed_code.strip())] = critic_result

        if attach:
            enriched["remediation_patch"] = fixed_code
        else:
            enriched.pop("remediation_patch", None)

        result.append(enriched)

    if rejected_fixes:
        _withhold_rejected_fix_elsewhere(result, rejected_fixes)
    return result


def _withhold_rejected_fix_elsewhere(findings: List[Dict[str, Any]], rejected: Dict[tuple, Dict[str, Any]]) -> None:
    """A fix the critic broke on one finding is not shown on another. Tier 1 and tier 2 give
    findings on the same line the same deterministic patch, and the cross-tier fold after
    triage may keep the sibling that was never checked, so the patch is removed from every
    finding in the file that carries it."""
    for index, original in enumerate(findings):
        patch = original.get("remediation_patch")
        if not patch:
            continue
        normalized = _normalize_fixed_code(patch, original.get("code_snippet", "")) or str(patch)
        critic_result = rejected.get((str(original.get("file_path") or ""), normalized.strip()))
        if critic_result is None:
            continue
        # A copy: an untriaged finding here is still the caller's own dictionary.
        finding = dict(original)
        findings[index] = finding
        finding.pop("remediation_patch", None)
        _record_extra(finding, {
            "fix_critic_accepted": False,
            "fix_critic_reason": "same_fix_rejected",
            "fix_critic_counterexample": (critic_result.get("counterexample") or {}).get("input"),
        })


def _split_for_isolation(
    findings: List[Dict[str, Any]],
    isolate_rank: int,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(isolated, batched): findings at or above the rank each get a call of their own,
    so a verdict on one cannot lean on the others in the same answer."""
    if isolate_rank <= 0:
        return [], list(findings)
    isolated = [f for f in findings if SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) >= isolate_rank]
    batched = [f for f in findings if SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) < isolate_rank]
    return isolated, batched


def _triage_group(
    group: List[Dict[str, Any]],
    file_patches: Dict[str, str],
    repo_profile: Optional[Dict[str, Any]],
    budget: TriageBudget,
    model: Optional[str],
) -> List[Dict[str, Any]]:
    """One call for `group`. A provider error returns nothing, so the findings pass through
    untriaged as before. An answer that does not parse returns uncertain verdicts for the
    whole group: the finding is kept, nothing is boosted and no fix is attached."""
    if not budget.allows_call():
        budget.refuse("triage", len(group))
        return []

    user_prompt = _build_triage_prompt(group, file_patches, repo_profile)
    try:
        raw_response, input_tokens, output_tokens = _call_triage_llm(user_prompt, model=model)
    except Exception as exc:
        LLM_TRIAGE_REQUESTS.labels(status="error").inc()
        print(f"LLM triage failed (non-blocking): {redact(exc)} ({len(group)} findings untriaged)")
        return []
    budget.record(input_tokens, output_tokens)

    valid_fps = {f.get("fingerprint", "") for f in group}
    try:
        verdicts = _parse_triage_response(raw_response, valid_fps)
    except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        LLM_TRIAGE_REQUESTS.labels(status="parse_error").inc()
        print(f"LLM triage response not valid JSON (fail closed to uncertain): {redact(exc)}")
        return _fail_closed_verdicts(group, "parse_error")

    if len(group) == 1 and not verdicts:
        # An isolated call that answers about anything but its one finding is a failed call.
        LLM_TRIAGE_REQUESTS.labels(status="parse_error").inc()
        return _fail_closed_verdicts(group, "parse_error")

    LLM_TRIAGE_REQUESTS.labels(status="success").inc()
    return verdicts


def triage_findings(
    findings: List[Dict[str, Any]],
    file_patches: Dict[str, str],
    repo_profile: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Run LLM triage on findings. Non-blocking: returns original findings on failure."""
    if not is_llm_triage_enabled():
        LLM_TRIAGE_REQUESTS.labels(status="skipped").inc()
        return findings

    if not findings:
        return findings

    to_triage = _select_findings_for_triage(findings)
    if not to_triage:
        return findings

    try:
        start = time.perf_counter()
        budget = TriageBudget(max_calls_per_run(), max_tokens_per_run())
        isolated, batched = _split_for_isolation(to_triage, isolate_severity_rank())
        tier_model = high_severity_model()

        verdicts: List[Dict[str, Any]] = []
        for finding in isolated:
            verdicts.extend(_triage_group([finding], file_patches, repo_profile, budget, tier_model))
        if batched:
            verdicts.extend(_triage_group(batched, file_patches, repo_profile, budget, None))

        verdicts = _require_concrete_payloads(verdicts, to_triage)
        critic = _llm_patch_critic(budget, tier_model, file_patches) if critic_enabled() else None
        result = _apply_verdicts(findings, verdicts, critic=critic)

        duration = time.perf_counter() - start
        LLM_TRIAGE_DURATION.observe(duration)

        filtered = len([v for v in verdicts if v["verdict"] == "false_positive"])
        downgraded = len([v for v in verdicts if v.get("downgrade")])
        print(
            f"LLM triage completed: {len(verdicts)} verdicts, {filtered} false positives filtered, "
            f"{downgraded} lowered to uncertain, {len(isolated)} isolated + {1 if batched else 0} batched; "
            f"budget {budget.summary()} ({duration:.1f}s)"
        )

        return result

    except Exception as e:
        LLM_TRIAGE_REQUESTS.labels(status="error").inc()
        print(f"LLM triage failed (non-blocking): {redact(e)}")
        return findings
