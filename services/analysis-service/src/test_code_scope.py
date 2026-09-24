"""Classification of test-code paths.

Findings inside test code are real detections and must be reported, but they do
not describe runtime exposure, so they are downgraded to the non-blocking
``info`` severity instead of being dropped. The original scanner severity is
preserved so nothing is lost.
"""

import re
from typing import Any, Dict, Iterable, List

INFORMATIONAL_SEVERITY = "info"

TEST_CODE_PATH_PATTERNS = [
    re.compile(r"(^|/)tests?/"),
    re.compile(r"(^|/)__tests?__/"),
    re.compile(r"(^|/)test_.*\.(py|js|jsx|ts|tsx|go|java|rb|php|cs)$"),
    re.compile(r"\.(test|spec)\.(js|jsx|ts|tsx|py|go|java|rb|php|cs)$"),
]

# Scanner assets, not reviewable source. These are never analyzed at all.
EXCLUDED_PATH_PATTERNS = [
    re.compile(r"(^|/)opengrep_rules/"),
]

NON_RUNTIME_PATH_PATTERNS = TEST_CODE_PATH_PATTERNS + EXCLUDED_PATH_PATTERNS

# Prose: documentation, changelogs and translation catalogues. Nothing in them executes,
# so a rule that recognizes the shape of executable code cannot have a true positive
# there; a changelog entry quoting `app.get('/user/:id')` is not a route without an auth
# check. Rules that look for committed data rather than code keep scanning these files.
PROSE_EXTENSIONS = {
    ".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc", ".asciidoc", ".textile", ".pod",
    ".po", ".pot",
}
PROSE_STEMS = {
    "changelog", "changes", "history", "news", "authors", "contributors", "contributing",
    "readme", "license", "licence", "notice", "copying", "codeowners",
}


def _normalize_path(path: Any) -> str:
    return str(path or "").strip().replace("\\", "/").lower()


def is_test_code_path(path: Any) -> bool:
    normalized = _normalize_path(path)
    if not normalized:
        return False
    return any(pattern.search(normalized) for pattern in TEST_CODE_PATH_PATTERNS)


def is_excluded_path(path: Any) -> bool:
    normalized = _normalize_path(path)
    if not normalized:
        return True
    return any(pattern.search(normalized) for pattern in EXCLUDED_PATH_PATTERNS)


def is_analyzable_path(path: Any) -> bool:
    """Every path we scan, including test code."""
    return not is_excluded_path(path)


def is_prose_path(path: Any) -> bool:
    """True for documentation, changelogs and translation catalogues.

    An unrecognized extension is not prose: the classification only ever narrows what a
    code-shape rule scans, so anything it is unsure about keeps being scanned.
    """
    normalized = _normalize_path(path)
    if not normalized:
        return False
    name = normalized.rsplit("/", 1)[-1]
    stem, _, extension = name.rpartition(".")
    if extension and f".{extension}" in PROSE_EXTENSIONS:
        return True
    # A file with no extension at all, such as `CHANGELOG` or `AUTHORS`.
    return not stem and name in PROSE_STEMS


def is_runtime_scannable_path(path: Any) -> bool:
    """Runtime source only: neither an excluded asset nor test code."""
    return is_analyzable_path(path) and not is_test_code_path(path)


def _recorded_original_severity(finding: Dict[str, Any], extra: Dict[str, Any]) -> str:
    recorded = finding.get("original_severity") or extra.get("original_severity")
    if recorded:
        return str(recorded).lower()
    current = str(finding.get("severity") or "").lower()
    # A finding that already carries the informational severity without a
    # recorded original has been classified before; do not overwrite history.
    return "" if current == INFORMATIONAL_SEVERITY else current


def classify_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Tag a finding with its test-code status and apply the effective severity.

    The classification is idempotent: re-running it after a transport round trip
    or an LLM triage pass restores the informational severity without losing the
    original scanner severity.
    """
    if not isinstance(finding, dict):
        return finding

    details = finding.get("evidence_details")
    if not isinstance(details, dict):
        details = {}
    extra = details.get("extra")
    if not isinstance(extra, dict):
        extra = {}

    in_test_code = is_test_code_path(finding.get("file_path"))
    finding["in_test_code"] = in_test_code

    if in_test_code:
        original = _recorded_original_severity(finding, extra)
        if original:
            finding["original_severity"] = original
            extra["original_severity"] = original
        finding["severity"] = INFORMATIONAL_SEVERITY
        extra["in_test_code"] = True
        details["extra"] = extra
        finding["evidence_details"] = details

    return finding


def classify_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [classify_finding(finding) for finding in findings or []]


def count_test_code_files(paths: Iterable[Any]) -> int:
    return len({_normalize_path(path) for path in paths or [] if is_test_code_path(path)})
