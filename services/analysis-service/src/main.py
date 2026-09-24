import hashlib
import hmac
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

import request_context
from finding_quality import (
    cluster_findings,
    extract_match_context,
    has_path_containment_guard,
    pattern_matches_reviewable_content,
)
from security_rules import DEPENDENCY_RISK_PATTERNS, SECURITY_RULES, likely_llm_repo
from opengrep_runner import run_opengrep
from llm_client import redact
from llm_triage import triage_findings
from remediation_patches import build_remediation_patch
from taxonomy import build_taxonomy_metadata
from test_code_scope import (
    classify_findings,
    count_test_code_files,
    is_analyzable_path,
    is_runtime_scannable_path,
    is_test_code_path,
)


class ChangedFile(BaseModel):
    path: str
    patch: str = ""
    content: str = ""
    additions: int = 0
    deletions: int = 0
    status: str = "modified"
    raw_url: str = ""
    reviewable_line_spans: List[Dict[str, int]] = Field(default_factory=list)


class AnalyzePRRequest(BaseModel):
    repository_full_name: str
    pull_request_number: int
    commit_sha: str
    files: List[ChangedFile] = Field(default_factory=list)


class TriageRequest(BaseModel):
    repository_full_name: str
    pull_request_number: int
    commit_sha: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    file_patches: Dict[str, str] = Field(default_factory=dict)
    repo_profile: Dict[str, Any] = Field(default_factory=dict)


REQUEST_COUNT = Counter("codesentry_analysis_requests_total", "Total analysis requests")
FINDING_COUNT = Counter(
    "codesentry_analysis_findings_total",
    "Findings by category and severity",
    ["category", "severity"],
)
ANALYSIS_DURATION = Histogram(
    "codesentry_analysis_duration_seconds",
    "Analysis runtime",
    buckets=[0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20],
)

request_context.configure_logging(os.getenv("LOG_LEVEL", "INFO"))
logger = request_context.get_logger("mitig8it.analysis")

app = FastAPI(title="Mitig8it Analysis Service", version="1.0.0")


# Every log line this request writes carries the delivery and run identifiers the
# caller sent, without a single handler having to accept them as arguments.
@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    with request_context.use(request_context.from_headers(request.headers)):
        return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:5173"), "http://localhost:5173", "http://localhost:3001"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)



def require_internal_auth(request: Request) -> None:
    expected = (
        os.getenv("ANALYSIS_SERVICE_INTERNAL_SECRET")
        or os.getenv("GITHUB_SERVICE_INTERNAL_SECRET")
    )
    if not expected:
        raise HTTPException(status_code=503, detail="Internal analysis auth is not configured")

    provided = request.headers.get("x-internal-secret", "")
    # Constant-time comparison: `!=` returns at the first differing byte, which lets
    # a caller measure how much of the secret it has guessed.
    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")




def make_fingerprint(rule_id: str, path: str, line_start: int, snippet: str) -> str:
    raw = f"{rule_id}|{path}|{line_start}|{snippet.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _meaningful_line_count(text: str) -> int:
    return len([line for line in str(text or "").split("\n") if line.strip()])


def _deterministic_missing_control_type(rule, finding: Dict[str, Any]) -> str | None:
    category = str(getattr(rule, "category", "") or "").lower()
    title = str(getattr(rule, "title", "") or "").lower()
    cwe_id = str(finding.get("cwe_id", "") or "").upper()

    if "sql" in category or cwe_id == "CWE-89":
        return "parameterized_query"
    if "xss" in category or "cross-site scripting" in title or cwe_id == "CWE-79":
        return "html_sanitization_or_safe_text_rendering"
    if "command injection" in category or cwe_id == "CWE-78":
        return "command_execution_guard"
    if "code injection" in category or cwe_id in {"CWE-94", "CWE-95"}:
        return "safe_parsing_or_no_dynamic_execution"
    if "secret" in category or cwe_id == "CWE-798":
        return "secret_manager_or_environment_variable"
    if cwe_id == "CWE-327":
        return "stronger_cryptography"
    if cwe_id == "CWE-295":
        return "tls_certificate_verification"
    if cwe_id == "CWE-502":
        return "safe_deserialization"
    return None


def _deterministic_fix_metadata(rule, finding: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    remediation_patch = str(finding.get("remediation_patch", "") or "").strip()
    if not remediation_patch:
        return {}

    patch_lines = _meaningful_line_count(remediation_patch)
    if patch_lines == 0 or patch_lines > 8:
        return {}

    snippet = context.get("matched_text") or context.get("code_snippet") or ""
    snippet_lines = _meaningful_line_count(snippet)
    line_start = int(finding.get("line_start") or 1)
    line_end = int(finding.get("line_end") or line_start)

    if patch_lines == 1 and line_start == line_end:
        fix_scope = "line"
    elif patch_lines <= max(2, snippet_lines + 1):
        fix_scope = "block"
    else:
        return {}

    return {
        "reviewability": "changed-lines-only",
        "fix_scope": fix_scope,
        "fix_target_line": line_start,
        "fix_target_expr": context.get("matched_text") or "",
        "missing_control_type": _deterministic_missing_control_type(rule, finding),
        "auto_fix_eligible": True,
    }


def generate_finding(rule, file_path: str, patch: str) -> Dict[str, Any]:
    context = extract_match_context(patch, rule.pattern)
    taxonomy = build_taxonomy_metadata(
        rule_id=rule.rule_id,
        category=rule.category,
        cwe_id=rule.cwe_id,
        owasp_category=rule.owasp_category,
        title=rule.title,
        description=rule.description,
        file_path=file_path,
        code_snippet=context["matched_text"] or context["code_snippet"],
    )

    finding = {
        "rule_id": rule.rule_id,
        "internal_type": taxonomy["internal_type"],
        "title": rule.title,
        "description": rule.description,
        "category": rule.category,
        "cwe_id": taxonomy["primary_cwe_id"],
        "owasp_category": taxonomy["primary_owasp_category"],
        "taxonomy_mappings": taxonomy["taxonomy_mappings"],
        "taxonomy_versions": taxonomy["taxonomy_versions"],
        "severity": rule.severity,
        "confidence": round(rule.confidence, 2),
        "exploitability": rule.exploitability,
        "file_path": file_path,
        "line_start": context["line_start"],
        "line_end": context["line_end"],
        "code_snippet": context["matched_text"] or context["code_snippet"],
        "evidence": (
            f"Matched deterministic rule `{rule.rule_id}` on `{context['matched_text']}`."
            if context["matched_text"]
            else f"Matched deterministic rule `{rule.rule_id}` in changed content."
        ),
        "exploit_scenario": "",
        "remediation": rule.remediation,
        "remediation_patch": "",
        "fingerprint": make_fingerprint(
            rule.rule_id,
            file_path,
            context["line_start"],
            context["matched_text"] or context["code_snippet"],
        ),
    }
    finding["remediation_patch"] = build_remediation_patch(finding) or ""
    evidence_details = _deterministic_fix_metadata(rule, finding, context)
    if evidence_details:
        finding["evidence_details"] = evidence_details
    return finding


def dependency_findings(path: str, patch: str) -> List[Dict[str, Any]]:
    findings = []
    if not any(name in path.lower() for name in ["package.json", "requirements", "poetry.lock", "pom.xml", "go.mod"]):
        return findings

    for pattern, message, severity in DEPENDENCY_RISK_PATTERNS:
        if pattern_matches_reviewable_content(patch, pattern):
            context = extract_match_context(patch, pattern)
            taxonomy = build_taxonomy_metadata(
                rule_id="dependency.risk.version",
                category="dependency/package risk",
                cwe_id="CWE-1104",
                owasp_category="A06:2021",
                internal_type="dependency_version_risk",
                title="Potential vulnerable dependency version",
                description=message,
                file_path=path,
                code_snippet=context["matched_text"] or context["code_snippet"],
            )
            finding = {
                    "rule_id": "dependency.risk.version",
                    "internal_type": taxonomy["internal_type"],
                    "title": "Potential vulnerable dependency version",
                    "description": message,
                    "category": "dependency/package risk",
                    "cwe_id": taxonomy["primary_cwe_id"],
                    "owasp_category": taxonomy["primary_owasp_category"],
                    "taxonomy_mappings": taxonomy["taxonomy_mappings"],
                    "taxonomy_versions": taxonomy["taxonomy_versions"],
                    "severity": severity,
                    "confidence": 0.74,
                    "exploitability": "medium",
                    "file_path": path,
                    "line_start": context["line_start"],
                    "line_end": context["line_end"],
                    "code_snippet": context["matched_text"] or context["code_snippet"],
                    "evidence": (
                        f"Dependency declaration `{context['matched_text']}` matches a known risky version pattern."
                        if context["matched_text"]
                        else "Dependency declaration matches a known risky version pattern."
                    ),
                    "exploit_scenario": "",
                    "remediation": "Upgrade to a patched package version and verify lockfile resolution.",
                    "remediation_patch": "",
                    "fingerprint": make_fingerprint(
                        "dependency.risk.version",
                        path,
                        context["line_start"],
                        context["matched_text"] or context["code_snippet"],
                    ),
                }
            finding["remediation_patch"] = build_remediation_patch(finding) or ""
            findings.append(finding)

    return findings


def pattern_findings(scannable_files: List[ChangedFile]) -> List[Dict[str, Any]]:
    """Tier 1: regex rules and dependency risk patterns over the reviewable patch text."""
    findings: List[Dict[str, Any]] = []
    repo_has_llm_flow = any(likely_llm_repo(f.path, f.patch) for f in scannable_files)

    for changed_file in scannable_files:
        path = changed_file.path
        patch = changed_file.patch or ""

        if len(patch) > 200_000:
            continue

        for rule in SECURITY_RULES:
            if rule.category == "unsafe LLM/prompt injection patterns" and not repo_has_llm_flow:
                continue
            if not pattern_matches_reviewable_content(patch, rule.pattern):
                continue
            if rule.category == "path traversal" and has_path_containment_guard(patch, rule.pattern):
                # The read resolves the candidate path and rejects anything outside the
                # base directory, which is what the taint rule accepts as a sanitizer.
                continue
            findings.append(generate_finding(rule, path, patch))

        findings.extend(dependency_findings(path, patch))

    return findings


def run_tiers_concurrently(
    tier1: Callable[[], List[Dict[str, Any]]],
    tier2: Callable[[], List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Runs both tiers at once and returns tier 1 findings followed by tier 2 findings.

    The merge order is fixed by tier, not by completion time, so fingerprints,
    clustering and the published review are stable across runs. A tier 2 failure
    fails the scan closed even when tier 1 finished cleanly; tier 1 is never
    reported alone as if it were the whole analysis.
    """
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="analysis-tier") as pool:
        tier1_future = pool.submit(tier1)
        tier2_future = pool.submit(tier2)
        tier1_findings = tier1_future.result()
        try:
            tier2_findings = tier2_future.result()
        except Exception as e:
            raise RuntimeError("Required OpenGrep analysis failed") from e
    return [*tier1_findings, *tier2_findings]


def analyze_pull_request_payload(payload: AnalyzePRRequest) -> Dict[str, Any]:
    if len(payload.files) > 300:
        raise ValueError("Too many files in PR payload")

    scannable_files = [f for f in payload.files if is_analyzable_path(f.path)]
    opengrep_files = [{"path": f.path, "patch": f.patch} for f in scannable_files]
    findings = run_tiers_concurrently(
        lambda: pattern_findings(scannable_files),
        lambda: run_opengrep(opengrep_files),
    )

    try:
        file_patches = {f.path: f.patch for f in scannable_files}
        findings = triage_findings(findings, file_patches, None)
    except Exception as e:
        print(f"LLM triage failed (non-blocking): {redact(e)}")
    findings = classify_findings(findings)

    normalized = cluster_findings(classify_findings(findings))
    for finding in normalized:
        FINDING_COUNT.labels(finding["category"], finding["severity"]).inc()

    return {
        "repository_full_name": payload.repository_full_name,
        "pull_request_number": payload.pull_request_number,
        "commit_sha": payload.commit_sha,
        "files_analyzed": len(payload.files),
        "test_files_analyzed": count_test_code_files(f.path for f in scannable_files),
        "findings": normalized,
    }


def analyze_tier1_payload(payload: AnalyzePRRequest) -> Dict[str, Any]:
    if len(payload.files) > 300:
        raise ValueError("Too many files in PR payload")

    scannable_files = [f for f in payload.files if is_analyzable_path(f.path)]
    findings = pattern_findings(scannable_files)

    normalized = cluster_findings(classify_findings(findings))
    return {
        "repository_full_name": payload.repository_full_name,
        "pull_request_number": payload.pull_request_number,
        "commit_sha": payload.commit_sha,
        "files_analyzed": len(payload.files),
        "test_files_analyzed": count_test_code_files(f.path for f in scannable_files),
        "tier": 1,
        "findings": normalized,
    }


def analyze_tier2_payload(payload: AnalyzePRRequest) -> Dict[str, Any]:
    if len(payload.files) > 300:
        raise ValueError("Too many files in PR payload")

    findings: List[Dict[str, Any]] = []
    scannable_files = [f for f in payload.files if is_analyzable_path(f.path)]
    try:
        opengrep_files = [
            {
                "path": f.path,
                "patch": f.patch,
                "content": f.content,
                "reviewable_line_spans": f.reviewable_line_spans,
            }
            for f in scannable_files
        ]
        findings = run_opengrep(opengrep_files)
    except Exception as e:
        raise RuntimeError("Required OpenGrep analysis failed") from e

    normalized = cluster_findings(classify_findings(findings))
    return {
        "repository_full_name": payload.repository_full_name,
        "pull_request_number": payload.pull_request_number,
        "commit_sha": payload.commit_sha,
        "files_analyzed": len(payload.files),
        "test_files_analyzed": count_test_code_files(f.path for f in scannable_files),
        "tier": 2,
        "findings": normalized,
    }


def triage_findings_payload(payload: TriageRequest) -> Dict[str, Any]:
    findings = payload.findings
    if not findings:
        return {
            "repository_full_name": payload.repository_full_name,
            "pull_request_number": payload.pull_request_number,
            "commit_sha": payload.commit_sha,
            "tier": 3,
            "findings": [],
            "filtered_count": 0,
        }

    original_count = len(findings)
    try:
        findings = triage_findings(findings, payload.file_patches, payload.repo_profile)
    except Exception as e:
        print(f"LLM triage failed (non-blocking): {redact(e)}")

    # Triage may adjust severity; test-code findings stay informational.
    findings = classify_findings(findings)

    return {
        "repository_full_name": payload.repository_full_name,
        "pull_request_number": payload.pull_request_number,
        "commit_sha": payload.commit_sha,
        "tier": 3,
        "findings": findings,
        "filtered_count": original_count - len(findings),
    }


@app.middleware("http")
async def track_latency(request: Request, call_next):
    REQUEST_COUNT.inc()
    start = time.perf_counter()
    response = await call_next(request)
    ANALYSIS_DURATION.observe(time.perf_counter() - start)
    return response


@app.get("/health")
async def health():
    return {"status": "ok", "service": "analysis-service"}


@app.get("/metrics")
async def metrics(request: Request):
    require_internal_auth(request)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# The analysis handlers are plain functions on purpose. They run a semgrep
# subprocess with a two-minute timeout and blocking LLM HTTP calls; as `async def`
# they ran on the event loop and one request stalled every other request,
# including /health. FastAPI runs plain functions in its threadpool.
@app.post("/analyze/pr")
def analyze_pr(payload: AnalyzePRRequest, request: Request):
    require_internal_auth(request)
    try:
        return analyze_pull_request_payload(payload)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))


@app.post("/analyze/pr/tier1")
def analyze_pr_tier1(payload: AnalyzePRRequest, request: Request):
    """Tier 1: Regex pattern matching + dependency checks. Fast (<100ms)."""
    require_internal_auth(request)
    try:
        return analyze_tier1_payload(payload)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))


@app.post("/analyze/pr/tier2")
def analyze_pr_tier2(payload: AnalyzePRRequest, request: Request):
    """Tier 2: OpenGrep AST analysis with taint tracking (2-5s)."""
    require_internal_auth(request)
    try:
        return analyze_tier2_payload(payload)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))


@app.post("/analyze/pr/tier3")
def analyze_pr_tier3(payload: TriageRequest, request: Request):
    """Tier 3: LLM triage of existing findings. Filters false positives."""
    require_internal_auth(request)
    return triage_findings_payload(payload)


@app.get("/")
async def root():
    return {"service": "analysis-service", "version": "1.0.0", "status": "ok"}
