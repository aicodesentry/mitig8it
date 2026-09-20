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

# ── Configuration ───────────────────────────────────────────────────────

LLM_TRIAGE_TIMEOUT = int(os.getenv("LLM_TRIAGE_TIMEOUT_SECONDS", "45"))
LLM_TRIAGE_MAX_FINDINGS = int(os.getenv("LLM_TRIAGE_MAX_FINDINGS", "100"))

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

SYSTEM_PROMPT = """You are a security code reviewer triaging static analysis findings and proposing minimal inline fixes.

For each finding, you have the detection metadata, the code context from the PR diff, and optionally a repository profile describing the repo's framework, auth patterns, database usage, and security posture.

Some findings also include structured analysis evidence from deterministic tiers:
- analysis_scope: whether the evidence is pattern-based or taint/dataflow-based
- source: where attacker-controlled input originates
- sink: the dangerous operation reached by that input
- sanitizers_seen: sanitizers or validators observed by the deterministic layer
- trace_summary: a short summary of the deterministic flow

Treat structured analysis evidence as stronger than raw pattern text. If a finding has source/sink or trace data, base your reasoning on that evidence first and use the patch plus repo profile to decide whether the flow is real, sanitized, reachable, or contextually safe.

Use the repository context to make informed decisions:
- If the repo uses parameterized queries, check if THIS specific code follows that pattern or bypasses it.
- If auth middleware exists, check if the affected endpoint has it applied.
- If a validation library is present, check if it covers this input path.

Assess whether each finding is a true positive, false positive, or uncertain.

Consider:
- Is the flagged code actually reachable with user-controlled input?
- Does a sanitizer, validator, or safe wrapper exist upstream?
- Is this test code, example code, or dead code?
- Could the severity be different than what the tool assigned?

When proposing a fix, use the finding metadata, the changed code, and the repository profile together:
- Match the repository's framework, language, and validation/auth/query patterns.
- Prefer the smallest safe replacement that can be applied directly on the changed line or small block.
- Do not invent helper functions, imports, or large refactors unless they already exist in the changed lines.
- If you are not confident the fix can be expressed as a drop-in replacement for the flagged lines, return null for fixed_code.

Respond with ONLY a JSON array. Each element must have:
- "fingerprint": the finding's fingerprint (string, copied from input)
- "verdict": one of "true_positive", "false_positive", "uncertain"
- "reasoning": 1-2 sentence explanation
- "adjusted_severity": null or one of "critical", "high", "medium", "low"
- "adjusted_confidence": null or a float 0.0-1.0
- "exploit_scenario": null or a 1-2 sentence attacker-focused impact path grounded in this code
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


def _call_triage_llm(user_prompt: str) -> tuple[str, int, int]:
    """Call the configured LLM provider. Returns (response_text, input_tokens, output_tokens)."""
    response = call_llm(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        timeout_seconds=LLM_TRIAGE_TIMEOUT,
        temperature=0,
        max_output_tokens=4096,
    )
    return response.text, response.input_tokens, response.output_tokens


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
    if not isinstance(parsed, list):
        return []

    verdicts = []
    for item in parsed:
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

        verdicts.append({
            "fingerprint": fp,
            "verdict": verdict,
            "reasoning": str(item.get("reasoning", ""))[:500],
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
) -> List[Dict[str, Any]]:
    """Apply LLM verdicts to findings.

    - false_positive: Remove from list
    - true_positive: Boost confidence, apply severity adjustment
    - uncertain: Leave unchanged
    """
    verdict_map = {v["fingerprint"]: v for v in verdicts}
    result = []

    for finding in findings:
        fp = finding.get("fingerprint", "")
        verdict = verdict_map.get(fp)

        if verdict is None:
            result.append(finding)
            continue

        LLM_TRIAGE_VERDICTS.labels(verdict=verdict["verdict"]).inc()

        if verdict["verdict"] == "false_positive":
            continue

        enriched = dict(finding)
        trace_features = _trace_features(enriched)
        enriched["llm_triage"] = {
            "verdict": verdict["verdict"],
            "reasoning": verdict["reasoning"],
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
        if (
            fixed_code
            and verdict["verdict"] == "true_positive"
            and _should_attach_auto_fix(enriched, trace_features, sanitizer_status)
        ):
            enriched["remediation_patch"] = fixed_code
        else:
            enriched.pop("remediation_patch", None)

        result.append(enriched)

    return result


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

        user_prompt = _build_triage_prompt(to_triage, file_patches, repo_profile)
        raw_response, input_tokens, output_tokens = _call_triage_llm(user_prompt)

        LLM_TRIAGE_TOKENS.labels(direction="input").inc(input_tokens)
        LLM_TRIAGE_TOKENS.labels(direction="output").inc(output_tokens)

        valid_fps = {f.get("fingerprint", "") for f in to_triage}
        verdicts = _parse_triage_response(raw_response, valid_fps)

        result = _apply_verdicts(findings, verdicts)

        duration = time.perf_counter() - start
        LLM_TRIAGE_DURATION.observe(duration)
        LLM_TRIAGE_REQUESTS.labels(status="success").inc()

        triaged_count = len([v for v in verdicts if v["verdict"] == "false_positive"])
        print(f"LLM triage completed: {len(verdicts)} verdicts, {triaged_count} false positives filtered ({duration:.1f}s)")

        return result

    except json.JSONDecodeError as e:
        LLM_TRIAGE_REQUESTS.labels(status="parse_error").inc()
        print(f"LLM triage response not valid JSON (non-blocking): {redact(e)}")
        return findings
    except Exception as e:
        LLM_TRIAGE_REQUESTS.labels(status="error").inc()
        print(f"LLM triage failed (non-blocking): {redact(e)}")
        return findings
