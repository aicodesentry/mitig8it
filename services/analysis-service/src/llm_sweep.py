"""
Tier 3 sweep: the model as a detector over the changed lines.

Tier 3 triage re-judges what tiers 1 and 2 found. It can lower recall and never raise it, so
recall stays capped at what the rules reach: 0.58 of labelled lines on the September 2026
vulnerable corpus. This module asks the model to find things directly, under constraints
that make every answer checkable before it becomes a finding:

- the class must come from `taxonomy.CANONICAL_INTERNAL_TYPES`, the vocabulary the product
  groups and measures by, so a sweep finding joins the same labels and the same clusterer;
- the line must be a changed line of the patch and the quote must appear verbatim on it, so
  a finding points at code the author wrote in this pull request and not at a paraphrase;
- an exploit payload is required, so the model has to say how and not only what.

Anything that fails a check is rejected, and the reason is logged and counted. Nothing here
decides what is posted. A sweep finding carries a rule id of its own,
`llm.sweep.<internal_type>`, and goes through `main.partition_by_posting_policy` like every
other finding. Which classes may post is data, in `llm_sweep_posting.yml`, and every class
starts quarantined until a measurement exists for it.

The sweep is off by default (`LLM_SWEEP_ENABLED=false`) and non-blocking: on any failure it
returns no findings and says so in its summary.
"""

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from prometheus_client import Counter, Histogram

import request_context
from finding_quality import make_fingerprint, parse_patch_entries
from llm_client import LLMResponse, call_llm, is_llm_provider_configured, redact
from taxonomy import CANONICAL_INTERNAL_TYPES, CWE_INTERNAL_TYPE_MAP, build_taxonomy_metadata
from test_code_scope import (
    SUPPORTED_EXTENSIONS,
    WORKFLOW_DIRECTORY,
    WORKFLOW_EXTENSIONS,
    is_analyzable_path,
    is_prose_path,
)

logger = request_context.get_logger("mitig8it.analysis.sweep")

# ── Identity ────────────────────────────────────────────────────────────

RULE_ID_PREFIX = "llm.sweep."
# What a finding says about where it came from. Tier 1 findings say `deterministic`, tier 2
# findings say `ast-pattern` or `taint-*` in `analysis_scope`; this is neither, and the
# clusterer, the triage prompt and the scorer all read it as its own kind.
TIER_LABEL = "tier3-sweep"
ANALYSIS_SCOPE = "model-sweep"
EVIDENCE_STRENGTH = "model"

POSTING_POST = "post"
POSTING_QUARANTINE = "quarantine"
POSTING_POLICY_PATH = Path(__file__).resolve().parent / "llm_sweep_posting.yml"

SEVERITIES = ("critical", "high", "medium", "low")

# ── Metrics ─────────────────────────────────────────────────────────────

LLM_SWEEP_REQUESTS = Counter(
    "codesentry_llm_sweep_requests_total",
    "Sweep runs by outcome (one run per analysis request)",
    ["status"],
)
LLM_SWEEP_CALLS = Counter(
    "codesentry_llm_sweep_calls_total",
    "Model calls made by the sweep, by outcome",
    ["status"],
)
LLM_SWEEP_CANDIDATES = Counter(
    "codesentry_llm_sweep_candidates_total",
    "Items the model returned, by whether they became findings",
    ["outcome"],
)
LLM_SWEEP_REJECTIONS = Counter(
    "codesentry_llm_sweep_rejections_total",
    "Items the model returned that were rejected, by reason",
    ["reason"],
)
LLM_SWEEP_TOKENS = Counter(
    "codesentry_llm_sweep_tokens_total",
    "Tokens consumed by the sweep",
    ["direction"],
)
LLM_SWEEP_DURATION = Histogram(
    "codesentry_llm_sweep_duration_seconds",
    "Sweep runtime per analysis request",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60, 120],
)

# ── Configuration ───────────────────────────────────────────────────────


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def is_llm_sweep_enabled() -> bool:
    """Off unless `LLM_SWEEP_ENABLED` says on, and never without provider credentials."""
    enabled = os.getenv("LLM_SWEEP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    return enabled and is_llm_provider_configured()


def sweep_timeout_seconds() -> int:
    return _int_env("LLM_SWEEP_TIMEOUT_SECONDS", 45)


def sweep_max_findings() -> int:
    """Findings accepted per analysis request, over every call."""
    return _int_env("LLM_SWEEP_MAX_FINDINGS", 20)


def sweep_max_findings_per_file() -> int:
    return _int_env("LLM_SWEEP_MAX_FINDINGS_PER_FILE", 5)


def sweep_call_token_budget() -> int:
    """Estimated input tokens one call may carry. Files are packed into calls up to this."""
    return _int_env("LLM_SWEEP_CALL_TOKEN_BUDGET", 12000)


def sweep_token_budget() -> int:
    """Estimated input tokens one analysis request may spend over every call."""
    return _int_env("LLM_SWEEP_TOKEN_BUDGET", 48000)


def sweep_max_calls() -> int:
    return _int_env("LLM_SWEEP_MAX_CALLS", 6)


def estimate_tokens(text: str) -> int:
    """A budget estimate, not a count: four characters per token is close enough to bound cost
    and needs no tokenizer for a provider that is chosen at run time."""
    return len(text) // 4 + 1


# ── Posting policy, as data ─────────────────────────────────────────────


def rule_id_for(internal_type: str) -> str:
    return f"{RULE_ID_PREFIX}{internal_type}"


def load_sweep_posting_policy(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """Per-class posting state from `llm_sweep_posting.yml`.

    A file that cannot be read yields an empty policy, which quarantines every class: the
    failure mode of the policy is to post nothing, never to post everything.
    """
    try:
        document = yaml.safe_load(Path(path or POSTING_POLICY_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.warning("sweep posting policy unreadable, quarantining every class: %s", redact(exc))
        return {}
    classes = document.get("classes") if isinstance(document, dict) else None
    if not isinstance(classes, dict):
        return {}
    return {
        str(name): {str(key): str(value) for key, value in (entry or {}).items()}
        for name, entry in classes.items()
        if isinstance(entry, dict)
    }


def sweep_posting_for(internal_type: str, policy: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """`post` only when the class says so and names the measurement that earned it."""
    entries = load_sweep_posting_policy() if policy is None else policy
    entry = entries.get(internal_type) or {}
    posting = str(entry.get("posting", POSTING_QUARANTINE)).strip().lower()
    evidence = str(entry.get("precision_evidence", "")).strip()
    if posting == POSTING_POST and evidence:
        return POSTING_POST
    return POSTING_QUARANTINE


def quarantined_sweep_rule_ids() -> frozenset:
    """Every sweep rule id whose class is not cleared to post. Unioned into
    `main.QUARANTINED_RULE_IDS`, so the one filter both tiers already use applies here too."""
    policy = load_sweep_posting_policy()
    return frozenset(
        rule_id_for(internal_type)
        for internal_type in CANONICAL_INTERNAL_TYPES
        if sweep_posting_for(internal_type, policy) != POSTING_POST
    )


# ── Taxonomy ────────────────────────────────────────────────────────────


def _cwe_by_internal_type() -> Dict[str, str]:
    """The first CWE the taxonomy resolves to each class, for the finding's `cwe_id`.

    Derived rather than written down a second time, so a class with no CWE in the taxonomy
    carries none here either rather than one invented for the sweep.
    """
    mapping: Dict[str, str] = {}
    for cwe, internal_type in CWE_INTERNAL_TYPE_MAP.items():
        mapping.setdefault(internal_type, cwe)
    return mapping


CWE_BY_INTERNAL_TYPE = _cwe_by_internal_type()
MENU = tuple(sorted(CANONICAL_INTERNAL_TYPES))


# ── Prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a security code reviewer reading the changed lines of a pull request. Report only vulnerabilities you can point at on a changed line and can describe a concrete attack for.

Each file is shown with its new-file line numbers. A line marked + was added or changed in this pull request. A line with no mark is unchanged context, shown only to help you read.

Report each vulnerability as a JSON object with exactly these keys:
- "internal_type": one value from the menu below, copied exactly. Nothing outside the menu is accepted.
- "file_path": the file path exactly as shown in its heading.
- "line": the new-file line number of a + line, as an integer.
- "quote": a short piece of text copied verbatim from that line.
- "severity": one of "critical", "high", "medium", "low".
- "confidence": a number from 0.0 to 1.0.
- "rationale": one or two sentences on why this code is vulnerable, naming the untrusted input and the sink.
- "exploit_payload": a concrete input and the entrypoint that delivers it, such as a request line, a form field value or a command argument.

Rules:
- Only + lines may be reported. A report on a context line is discarded.
- The quote must appear on the reported line exactly as written there. A paraphrase is discarded.
- If you cannot name a concrete payload and entrypoint, do not report it. Suspicion is not a finding.
- Do not report test code, fixtures, examples or documentation.
- Report each vulnerability once, on the line of the sink.
- Respond with ONLY a JSON array. Respond with [] when there is nothing to report.

Menu of classes:
""" + "\n".join(f"- {name}" for name in MENU)

MAX_PROMPT_LINE_CHARS = 400


@dataclass
class FileBlock:
    path: str
    rendered: str
    added_lines: Dict[int, str]
    tokens: int = 0

    def __post_init__(self) -> None:
        self.tokens = estimate_tokens(self.rendered)


@dataclass
class SweepSummary:
    enabled: bool = True
    files_considered: int = 0
    files_swept: int = 0
    files_skipped: int = 0
    calls: int = 0
    candidates: int = 0
    accepted: int = 0
    rejected: Dict[str, int] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    limitations: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ok"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "status": self.status,
            "files_considered": self.files_considered,
            "files_swept": self.files_swept,
            "files_skipped": self.files_skipped,
            "calls": self.calls,
            "candidates": self.candidates,
            "accepted": self.accepted,
            "rejected": dict(self.rejected),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "limitations": list(self.limitations),
        }


def is_sweepable_path(path: str) -> bool:
    """The files the sweep reads: what tier 2 reads, less prose.

    Code and template extensions, plus workflows under `.github/workflows/`. A lockfile, a
    JSON fixture or a Kubernetes manifest is cost without a class on the menu to find, and
    prose is excluded for the reason tier 1's code-shape rules exclude it: nothing in it runs.
    """
    if not is_analyzable_path(path) or is_prose_path(path):
        return False
    normalized = str(path or "").strip().replace("\\", "/").lower()
    suffix = "." + normalized.rsplit(".", 1)[-1] if "." in normalized.rsplit("/", 1)[-1] else ""
    if suffix in SUPPORTED_EXTENSIONS:
        return True
    return suffix in WORKFLOW_EXTENSIONS and WORKFLOW_DIRECTORY in normalized


def _render_file(path: str, patch: str) -> Optional[FileBlock]:
    """The patch as the model sees it: numbered lines, added ones marked, and the map of
    added lines the validator will check answers against."""
    # A patch that ends in a newline would otherwise parse a trailing empty context line.
    entries = parse_patch_entries(str(patch or "").rstrip("\n"), path)
    added: Dict[int, str] = {}
    rows: List[str] = []
    for entry in entries:
        number = int(entry.get("line_number") or 0)
        if number <= 0:
            continue
        content = str(entry.get("content") or "")
        mark = "+" if entry.get("kind") == "add" else " "
        if mark == "+":
            added[number] = content
        shown = content if len(content) <= MAX_PROMPT_LINE_CHARS else content[:MAX_PROMPT_LINE_CHARS]
        rows.append(f"{number:>6} {mark} {shown}")
    if not added:
        return None
    rendered = f"### {path}\n" + "\n".join(rows)
    return FileBlock(path=path, rendered=rendered, added_lines=added)


def _file_blocks(file_patches: Dict[str, str], summary: SweepSummary) -> List[FileBlock]:
    blocks: List[FileBlock] = []
    call_budget = sweep_call_token_budget()
    for path, patch in (file_patches or {}).items():
        summary.files_considered += 1
        if not patch or not is_sweepable_path(path):
            summary.files_skipped += 1
            continue
        block = _render_file(path, patch)
        if block is None:
            summary.files_skipped += 1
            continue
        if block.tokens > call_budget:
            # A file the budget cannot hold is a gap, and a gap is reported rather than
            # silently truncated: a truncated patch would let the model answer about half a
            # function and call it the whole.
            summary.files_skipped += 1
            summary.limitations.append({
                "kind": "budget",
                "path": path,
                "message": (
                    f"Sweep skipped this file: about {block.tokens} tokens against a "
                    f"{call_budget} token per-call budget"
                ),
            })
            continue
        blocks.append(block)
    return blocks


def _group_blocks(blocks: List[FileBlock], summary: SweepSummary) -> List[List[FileBlock]]:
    """Pack files into calls, first fit in file order, within the per-call budget, the request
    budget and the call cap. What does not fit is a reported limitation."""
    call_budget = sweep_call_token_budget()
    total_budget = sweep_token_budget()
    max_calls = sweep_max_calls()
    groups: List[List[FileBlock]] = []
    current: List[FileBlock] = []
    current_tokens = 0
    spent = 0
    for index, block in enumerate(blocks):
        if current and current_tokens + block.tokens > call_budget:
            groups.append(current)
            current, current_tokens = [], 0
        if len(groups) >= max_calls or spent + block.tokens > total_budget:
            left = blocks[index:]
            summary.files_skipped += len(left)
            summary.limitations.append({
                "kind": "budget",
                "path": "",
                "message": (
                    f"Sweep stopped after {index} of {len(blocks)} files "
                    f"({total_budget} token request budget, {max_calls} call cap)"
                ),
            })
            break
        current.append(block)
        current_tokens += block.tokens
        spent += block.tokens
    if current and len(groups) < max_calls:
        groups.append(current)
    return groups


def _repo_profile_section(repo_profile: Optional[Dict[str, Any]]) -> List[str]:
    if not repo_profile or not (repo_profile.get("deterministic") or repo_profile.get("interpreted")):
        return []
    det = repo_profile.get("deterministic") or {}
    interp = repo_profile.get("interpreted") or {}
    parts = ["## Repository profile", ""]
    if det.get("framework"):
        parts.append(f"- Framework: {det['framework']}")
    if det.get("languages"):
        parts.append(f"- Languages: {', '.join(str(item) for item in det['languages'])}")
    if det.get("security_libraries"):
        libs = [
            f"{item.get('library')} ({item.get('purpose')})"
            for item in det["security_libraries"]
            if isinstance(item, dict)
        ]
        if libs:
            parts.append(f"- Security libraries: {', '.join(libs)}")
    if interp.get("auth_strategy"):
        parts.append(f"- Auth: {interp['auth_strategy']}")
    if interp.get("database_pattern"):
        parts.append(f"- Query pattern: {interp['database_pattern']}")
    parts.append("")
    return parts


def build_sweep_prompt(group: List[FileBlock], repo_profile: Optional[Dict[str, Any]] = None) -> str:
    parts = _repo_profile_section(repo_profile)
    parts.append("## Changed files")
    parts.append("")
    for block in group:
        parts.append(block.rendered)
        parts.append("")
    return "\n".join(parts)


def _call_sweep_llm(user_prompt: str) -> LLMResponse:
    """The one place the sweep reaches a provider. Tests and the replay harness replace it."""
    return call_llm(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        timeout_seconds=sweep_timeout_seconds(),
        temperature=0,
        max_output_tokens=4096,
    )


# ── Validation ──────────────────────────────────────────────────────────


def _strip_fences(raw: str) -> str:
    text = str(raw or "").strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else ""
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    return text


def parse_sweep_response(raw: str) -> List[Any]:
    """The model's JSON array, or a `json.JSONDecodeError` for the caller to count."""
    parsed = json.loads(_strip_fences(raw))
    if isinstance(parsed, dict):
        # One object where an array was asked for. Read it as an array of one rather than
        # throw away an answer over its brackets.
        return [parsed]
    if not isinstance(parsed, list):
        raise json.JSONDecodeError("sweep response is not a JSON array", str(raw)[:80], 0)
    return parsed


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def validate_item(
    item: Any,
    blocks_by_path: Dict[str, FileBlock],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One item from the model, checked against the patch. Returns (finding, None) when it
    holds up and (None, reason) when it does not.

    Every check is against something the model could not have known without reading the
    patch it was given: the class menu, the changed-line map, the exact text of the line.
    """
    if not isinstance(item, dict):
        return None, "not_an_object"

    internal_type = str(item.get("internal_type") or "").strip().lower()
    if internal_type not in CANONICAL_INTERNAL_TYPES:
        return None, "off_menu_class"

    path = str(item.get("file_path") or "").strip()
    block = blocks_by_path.get(path)
    if block is None:
        return None, "unknown_file"

    line = _as_int(item.get("line"))
    if line is None:
        return None, "line_not_an_integer"
    line_text = block.added_lines.get(line)
    if line_text is None:
        return None, "line_not_changed"

    quote = str(item.get("quote") or "").strip()
    if len(quote) < 3:
        return None, "quote_missing"
    if quote not in line_text:
        return None, "quote_mismatch"

    severity = str(item.get("severity") or "").strip().lower()
    if severity not in SEVERITIES:
        return None, "invalid_severity"

    confidence_raw = item.get("confidence")
    if isinstance(confidence_raw, bool) or not isinstance(confidence_raw, (int, float)):
        return None, "invalid_confidence"
    confidence = float(confidence_raw)
    if not 0.0 <= confidence <= 1.0:
        return None, "invalid_confidence"

    rationale = " ".join(str(item.get("rationale") or "").split()).strip()
    if not rationale:
        return None, "no_rationale"

    exploit_payload = " ".join(str(item.get("exploit_payload") or "").split()).strip()
    if not exploit_payload:
        return None, "no_exploit_payload"

    return _build_finding(
        internal_type=internal_type,
        path=path,
        line=line,
        line_text=line_text,
        quote=quote,
        severity=severity,
        confidence=confidence,
        rationale=rationale[:500],
        exploit_payload=exploit_payload[:500],
    ), None


def _build_finding(
    *,
    internal_type: str,
    path: str,
    line: int,
    line_text: str,
    quote: str,
    severity: str,
    confidence: float,
    rationale: str,
    exploit_payload: str,
) -> Dict[str, Any]:
    """The same dict shape `main.generate_finding` and `opengrep_runner._build_finding` emit,
    so everything downstream reads it without knowing which tier produced it."""
    rule_id = rule_id_for(internal_type)
    label = internal_type.replace("_", " ")
    title = f"Possible {label}"
    taxonomy = build_taxonomy_metadata(
        rule_id=rule_id,
        category=label,
        cwe_id=CWE_BY_INTERNAL_TYPE.get(internal_type),
        internal_type=internal_type,
        title=title,
        description=rationale,
        file_path=path,
        code_snippet=line_text,
    )
    evidence = f"Proposed by the tier 3 model sweep as `{internal_type}` on `{quote}`. {rationale}"
    return {
        "rule_id": rule_id,
        "internal_type": taxonomy["internal_type"],
        "title": title,
        "description": rationale,
        "category": label,
        "cwe_id": taxonomy["primary_cwe_id"],
        "owasp_category": taxonomy["primary_owasp_category"],
        "taxonomy_mappings": taxonomy["taxonomy_mappings"],
        "taxonomy_versions": taxonomy["taxonomy_versions"],
        "severity": severity,
        "confidence": round(confidence, 2),
        "exploitability": "medium",
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "code_snippet": line_text,
        "analysis_scope": ANALYSIS_SCOPE,
        "evidence_strength": EVIDENCE_STRENGTH,
        "is_taint_based": False,
        "detector_tier": TIER_LABEL,
        "evidence": evidence,
        "exploit_scenario": exploit_payload,
        # The model was not asked for a fix. A finding that posts goes through triage's
        # fallbacks for remediation text like any other; none does today.
        "remediation": "",
        "remediation_patch": "",
        "evidence_details": {
            "analysis_scope": ANALYSIS_SCOPE,
            "is_taint_based": False,
            "evidence_strength": EVIDENCE_STRENGTH,
            "detector_tier": TIER_LABEL,
            "reviewability": "changed-lines-only",
            "sanitizer_status": "none",
            "sanitizer_exprs": [],
            "trace_steps": [],
            "auto_fix_eligible": False,
            "quote": quote,
            "rationale": rationale,
            "exploit_payload": exploit_payload,
        },
        "fingerprint": make_fingerprint(rule_id, path, line, line_text),
    }


def _reject(summary: SweepSummary, reason: str, item: Any) -> None:
    summary.rejected[reason] = summary.rejected.get(reason, 0) + 1
    LLM_SWEEP_REJECTIONS.labels(reason=reason).inc()
    LLM_SWEEP_CANDIDATES.labels(outcome="rejected").inc()
    detail = ""
    if isinstance(item, dict):
        detail = " ".join(
            f"{key}={str(item.get(key))[:80]!r}"
            for key in ("internal_type", "file_path", "line", "quote")
            if key in item
        )
    logger.info("sweep rejected an item: %s %s", reason, redact(detail))


def accept_items(
    items: List[Any],
    blocks_by_path: Dict[str, FileBlock],
    summary: SweepSummary,
    accepted: List[Dict[str, Any]],
) -> None:
    """Validate every item of one response into `accepted`, within the per-file and request caps."""
    per_file: Dict[str, int] = {}
    for finding in accepted:
        per_file[finding["file_path"]] = per_file.get(finding["file_path"], 0) + 1
    seen = {(f["file_path"], f["line_start"], f["internal_type"]) for f in accepted}
    max_total = sweep_max_findings()
    max_per_file = sweep_max_findings_per_file()

    for item in items:
        summary.candidates += 1
        finding, reason = validate_item(item, blocks_by_path)
        if finding is None:
            _reject(summary, reason or "invalid", item)
            continue
        key = (finding["file_path"], finding["line_start"], finding["internal_type"])
        if key in seen:
            _reject(summary, "duplicate", item)
            continue
        if len(accepted) >= max_total:
            _reject(summary, "request_cap", item)
            continue
        if per_file.get(finding["file_path"], 0) >= max_per_file:
            _reject(summary, "file_cap", item)
            continue
        seen.add(key)
        per_file[finding["file_path"]] = per_file.get(finding["file_path"], 0) + 1
        accepted.append(finding)
        summary.accepted += 1
        LLM_SWEEP_CANDIDATES.labels(outcome="accepted").inc()


# ── Entry point ─────────────────────────────────────────────────────────


def sweep_with_summary(
    file_patches: Dict[str, str],
    repo_profile: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Candidate findings over the changed lines, and an account of how they were made.

    Non-blocking: a provider error or an unparseable response costs that one call and is
    recorded in the summary, and the findings from other calls are kept.
    """
    summary = SweepSummary()
    if not is_llm_sweep_enabled():
        summary.enabled = False
        summary.status = "disabled"
        LLM_SWEEP_REQUESTS.labels(status="skipped").inc()
        return [], summary.as_dict()

    started = time.perf_counter()
    accepted: List[Dict[str, Any]] = []
    blocks = _file_blocks(file_patches, summary)
    groups = _group_blocks(blocks, summary)
    blocks_by_path = {block.path: block for group in groups for block in group}
    summary.files_swept = len(blocks_by_path)
    failures = 0

    for group in groups:
        if len(accepted) >= sweep_max_findings():
            summary.limitations.append({
                "kind": "cap",
                "path": "",
                "message": f"Sweep stopped at the {sweep_max_findings()} finding cap",
            })
            break
        user_prompt = build_sweep_prompt(group, repo_profile)
        try:
            response = _call_sweep_llm(user_prompt)
        except Exception as exc:  # noqa: BLE001 - one failed call is recorded, not raised.
            failures += 1
            LLM_SWEEP_CALLS.labels(status="error").inc()
            logger.warning("sweep call failed (non-blocking): %s", redact(exc))
            summary.limitations.append({
                "kind": "provider",
                "path": "",
                "message": f"Sweep call failed for {len(group)} file(s): {redact(exc)}"[:300],
            })
            continue
        summary.calls += 1
        summary.input_tokens += int(response.input_tokens or 0)
        summary.output_tokens += int(response.output_tokens or 0)
        LLM_SWEEP_TOKENS.labels(direction="input").inc(int(response.input_tokens or 0))
        LLM_SWEEP_TOKENS.labels(direction="output").inc(int(response.output_tokens or 0))
        try:
            items = parse_sweep_response(response.text)
        except json.JSONDecodeError as exc:
            failures += 1
            LLM_SWEEP_CALLS.labels(status="parse_error").inc()
            logger.warning("sweep response not valid JSON (non-blocking): %s", redact(exc))
            summary.limitations.append({
                "kind": "provider",
                "path": "",
                "message": f"Sweep response for {len(group)} file(s) was not a JSON array",
            })
            continue
        LLM_SWEEP_CALLS.labels(status="success").inc()
        accept_items(items, {block.path: block for block in group}, summary, accepted)

    duration = time.perf_counter() - started
    LLM_SWEEP_DURATION.observe(duration)
    if groups and failures == len(groups):
        summary.status = "failed"
        LLM_SWEEP_REQUESTS.labels(status="error").inc()
    elif failures:
        summary.status = "partial"
        LLM_SWEEP_REQUESTS.labels(status="partial").inc()
    else:
        LLM_SWEEP_REQUESTS.labels(status="success").inc()
    logger.info(
        "sweep completed: files=%d calls=%d candidates=%d accepted=%d rejected=%s tokens=%d/%d (%.1fs)",
        summary.files_swept, summary.calls, summary.candidates, summary.accepted,
        dict(summary.rejected), summary.input_tokens, summary.output_tokens, duration,
    )
    return accepted, summary.as_dict()


def sweep_findings(
    file_patches: Dict[str, str],
    repo_profile: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Candidate findings only. See `sweep_with_summary`."""
    findings, _ = sweep_with_summary(file_patches, repo_profile)
    return findings
