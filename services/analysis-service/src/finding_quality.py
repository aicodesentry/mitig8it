import re
from typing import Any, Dict, Iterable, List, Optional

from comment_stripper import strip_lines


HUNK_RE = re.compile(r"@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@")
TRANSCRIPT_LINE_RE = re.compile(
    r"^\s*(?:"
    r"\d+\s+[+-]\s+|"
    r"@@\s|"
    r"diff --git|"
    r"\+\+\+\s|---\s|"
    r"[⏺⎿❯✻]|"
    r"(?:Bash|Update|Write|Read)\(|"
    r"Summary of the two tiers|"
    r"PR #\d+ created:|"
    r"Want me to|"
    r"Ready for PR"
    r")"
)

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def detector_kind(finding: Dict[str, Any]) -> str:
    rule_id = str(finding.get("rule_id") or "")
    if rule_id.startswith("opengrep."):
        return "opengrep"
    if rule_id.startswith("dependency."):
        return "dependency"
    return "deterministic"


def is_transcript_artifact_line(line: str) -> bool:
    text = str(line or "")
    stripped = text.strip()
    if not stripped:
        return False
    if TRANSCRIPT_LINE_RE.search(text):
        return True
    return False


def parse_patch_entries(patch: str, path: Any = None) -> List[Dict[str, Any]]:
    """Reviewable lines of `patch`, in file order, each with its new-side line number.

    When `path` names a language the comment stripper models, every entry also carries
    `scan_text` (comments blanked) and `scan_text_no_strings` (comments and string bodies
    blanked). `content` is always the untouched line, so a finding quotes what the author
    wrote. Comment state is scanned per hunk, because a diff does not show what came
    before the hunk.
    """
    entries: List[Dict[str, Any]] = []
    if not patch:
        return entries

    old_line = 0
    new_line = 0
    hunk = 0

    for raw_line in patch.split("\n"):
        if raw_line.startswith("@@"):
            match = HUNK_RE.search(raw_line)
            if match:
                old_line = int(match.group("old_start"))
                new_line = int(match.group("new_start"))
                hunk += 1
            continue

        if raw_line.startswith("+++ ") or raw_line.startswith("--- "):
            continue

        if raw_line.startswith("+"):
            entries.append(
                {
                    "kind": "add",
                    "line_number": new_line,
                    "content": raw_line[1:],
                    "hunk": hunk,
                }
            )
            new_line += 1
            continue

        if raw_line.startswith("-"):
            old_line += 1
            continue

        content = raw_line[1:] if raw_line.startswith(" ") else raw_line
        entries.append(
            {
                "kind": "context",
                "line_number": new_line,
                "content": content,
                "hunk": hunk,
            }
        )
        old_line += 1
        new_line += 1

    _annotate_scan_text(entries, path)
    return entries


def _annotate_scan_text(entries: List[Dict[str, Any]], path: Any) -> None:
    by_hunk: Dict[int, List[Dict[str, Any]]] = {}
    for entry in entries:
        by_hunk.setdefault(entry.get("hunk", 0), []).append(entry)

    for hunk_entries in by_hunk.values():
        lines = [entry["content"] for entry in hunk_entries]
        stripped = strip_lines(lines, path)
        blanked = strip_lines(lines, path, blank_strings=True)
        for entry, code_only, no_strings in zip(hunk_entries, stripped, blanked):
            entry["scan_text"] = code_only
            entry["scan_text_no_strings"] = no_strings


def entry_scan_text(entry: Dict[str, Any], *, blank_strings: bool = False) -> str:
    key = "scan_text_no_strings" if blank_strings else "scan_text"
    return str(entry.get(key, entry.get("content", "")) or "")


def find_pattern_match_entry(
    patch: str,
    pattern,
    *,
    path: Any = None,
    exclusion=None,
    blank_strings: bool = False,
) -> Optional[Dict[str, Any]]:
    """First reviewable line of `patch` that `pattern` matches and `exclusion` does not.

    `exclusion` is the second pass that replaces a negative lookahead: the condition is
    evaluated against the same text the pattern saw, where backtracking cannot defeat it.
    """
    entries = parse_patch_entries(patch, path)
    if not entries:
        return None

    for require_added in (True, False):
        for entry in entries:
            if require_added and entry["kind"] != "add":
                continue
            if is_transcript_artifact_line(entry["content"]):
                continue
            text = entry_scan_text(entry, blank_strings=blank_strings)
            if not pattern.search(text):
                continue
            if exclusion is not None and exclusion.search(text):
                continue
            return entry
    return None


def pattern_matches_reviewable_content(
    patch: str,
    pattern,
    *,
    path: Any = None,
    exclusion=None,
    blank_strings: bool = False,
) -> bool:
    return find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion, blank_strings=blank_strings
    ) is not None


# The containment repair the taint rule accepts (see the `cwe-22.path-traversal-fs` sanitizer in
# opengrep_rules/javascript.yml): resolve the candidate path against the base directory, then
# reject it unless the resolved path stays under that base. `path.basename` is not one of these:
# it is an INSUFFICIENT_SANITIZER in opengrep_runner.py, so a basename-only defence keeps
# reporting. Tier 1 has no taint tracking, so it ties the two halves together by name, requiring
# the containment check to be made on the very variable the resolve call assigned.
PATH_RESOLVE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)?\s*\b(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?"
    r"(?:path\.resolve|path\.posix\.resolve|fs\.realpathSync|fs\.realpath|"
    r"os\.path\.realpath|os\.path\.abspath|filepath\.Abs)\s*\(",
)
PATH_CONTAINMENT_WINDOW = 12


def _containment_check_re(name: str):
    escaped = re.escape(name)
    return re.compile(
        rf"\b{escaped}\s*\.(?:startsWith|startswith|is_relative_to)\s*\("
        rf"|\b(?:path\.relative|os\.path\.commonpath|os\.path\.relpath|filepath\.Rel)\s*\([^)]*\b{escaped}\b"
        rf"|\bstrings\.HasPrefix\s*\(\s*{escaped}\b"
    )


def has_path_containment_guard(
    patch: str,
    pattern,
    window: int = PATH_CONTAINMENT_WINDOW,
    *,
    path: Any = None,
    exclusion=None,
    blank_strings: bool = False,
) -> bool:
    """True when a filesystem read matched by `pattern` is guarded by resolve-and-contain.

    The guard has to sit above the read, within `window` lines of it, and has to do both halves
    of the job on the same value: resolve the candidate path into a variable, and compare that
    variable against the base directory. Either half alone, or a check made on some other value,
    leaves the finding in place.
    """
    match_entry = find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion, blank_strings=blank_strings
    )
    if match_entry is None:
        return False

    entries = parse_patch_entries(patch, path)
    match_index = None
    for index, entry in enumerate(entries):
        if entry == match_entry:
            match_index = index
            break
    if match_index is None:
        return False

    preceding = entries[max(0, match_index - window):match_index + 1]
    text = "\n".join(str(entry.get("content") or "") for entry in preceding)
    return any(
        _containment_check_re(match.group("name")).search(text)
        for match in PATH_RESOLVE_ASSIGN_RE.finditer(text)
    )


def extract_match_context(
    patch: str,
    pattern,
    *,
    path: Any = None,
    exclusion=None,
    blank_strings: bool = False,
    context_before: int = 2,
    context_after: int = 3,
    max_lines: int = 8,
) -> Dict[str, Any]:
    entries = parse_patch_entries(patch, path)
    if not entries:
        return {
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "matched_text": "",
        }

    match_entry = find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion, blank_strings=blank_strings
    )
    match_index = None
    if match_entry is not None:
        for index, entry in enumerate(entries):
            if entry == match_entry:
                match_index = index
                break

    if match_index is None:
        snippet_entries = entries[:max_lines]
        snippet = "\n".join(entry["content"] for entry in snippet_entries if entry["content"].strip())
        first_line = snippet_entries[0]["line_number"] if snippet_entries else 1
        last_line = snippet_entries[-1]["line_number"] if snippet_entries else first_line
        return {
            "line_start": first_line or 1,
            "line_end": last_line or first_line or 1,
            "code_snippet": snippet,
            "matched_text": "",
        }

    start = max(0, match_index - context_before)
    end = min(len(entries), match_index + context_after + 1)
    snippet_entries = entries[start:end]

    if len(snippet_entries) > max_lines:
        snippet_entries = snippet_entries[:max_lines]

    snippet = "\n".join(entry["content"] for entry in snippet_entries if entry["content"].strip())
    match_entry = entries[match_index]
    first_line = next((entry["line_number"] for entry in snippet_entries if entry["line_number"]), match_entry["line_number"])
    last_line = next((entry["line_number"] for entry in reversed(snippet_entries) if entry["line_number"]), match_entry["line_number"])

    return {
        "line_start": match_entry["line_number"] or 1,
        "line_end": last_line or match_entry["line_number"] or 1,
        "code_snippet": snippet,
        "matched_text": match_entry["content"],
        "context_start_line": first_line or 1,
    }


def _merge_unique(values: Iterable[Any]) -> List[str]:
    merged: List[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, list):
            for nested in value:
                if nested and nested not in merged:
                    merged.append(nested)
            continue
        if value and value not in merged:
            merged.append(value)
    return merged


def _merge_taxonomy(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    merged = {"cwe": [], "owasp": [], "attack": [], "capec": []}
    for finding in findings:
        mappings = finding.get("taxonomy_mappings") or {}
        for key in merged:
            merged[key] = _merge_unique([merged[key], mappings.get(key, [])])
    return merged


def _merge_taxonomy_versions(findings: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    versions = {"cwe": None, "attack": None, "capec": None, "owasp": None}
    for finding in findings:
        current = finding.get("taxonomy_versions") or {}
        for key in versions:
            versions[key] = versions[key] or current.get(key)
    return versions


def _same_cluster(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    if left.get("file_path") != right.get("file_path"):
        return False
    if left.get("internal_type") != right.get("internal_type"):
        return False

    left_line = int(left.get("line_start") or 0)
    right_line = int(right.get("line_start") or 0)
    if left_line and right_line and abs(left_line - right_line) > 2:
        return False

    left_snippet = (left.get("code_snippet") or "").strip()
    right_snippet = (right.get("code_snippet") or "").strip()
    if left.get("internal_type") == "hardcoded_secret" and left_snippet and right_snippet and left_snippet != right_snippet:
        return False

    return True


def _choose_primary(current: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    current_kind = detector_kind(current)
    candidate_kind = detector_kind(candidate)

    if current_kind != "opengrep" and candidate_kind == "opengrep":
        return candidate
    if current_kind == "opengrep" and candidate_kind != "opengrep":
        return current

    current_severity = SEVERITY_RANK.get(str(current.get("severity") or "").lower(), 0)
    candidate_severity = SEVERITY_RANK.get(str(candidate.get("severity") or "").lower(), 0)
    if candidate_severity > current_severity:
        return candidate
    if current_severity > candidate_severity:
        return current

    if float(candidate.get("confidence") or 0) > float(current.get("confidence") or 0):
        return candidate
    return current


def _choose_review_anchor(cluster: List[Dict[str, Any]], primary: Dict[str, Any]) -> Dict[str, Any]:
    primary_kind = detector_kind(primary)
    if primary_kind != "opengrep":
        return primary

    for finding in cluster:
        if detector_kind(finding) == "opengrep":
            continue
        if finding.get("file_path") != primary.get("file_path"):
            continue
        if int(finding.get("line_start") or 0) <= 0:
            continue
        return finding

    return primary


def cluster_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    exact_seen = set()
    deduped: List[Dict[str, Any]] = []
    for finding in findings:
        exact_key = (
            finding.get("rule_id"),
            finding.get("file_path"),
            int(finding.get("line_start") or 0),
            (finding.get("code_snippet") or "").strip(),
        )
        if exact_key in exact_seen:
            continue
        exact_seen.add(exact_key)
        deduped.append(finding)

    clusters: List[List[Dict[str, Any]]] = []
    for finding in deduped:
        target = None
        for cluster in clusters:
            if any(_same_cluster(existing, finding) for existing in cluster):
                target = cluster
                break
        if target is None:
            clusters.append([finding])
        else:
            target.append(finding)

    clustered: List[Dict[str, Any]] = []
    for cluster in clusters:
        primary = cluster[0]
        for candidate in cluster[1:]:
            primary = _choose_primary(primary, candidate)

        if len(cluster) == 1:
            clustered.append(primary)
            continue

        supporting_rules = _merge_unique([finding.get("rule_id") for finding in cluster if finding.get("rule_id") != primary.get("rule_id")])
        supporting_detectors = _merge_unique([detector_kind(finding) for finding in cluster if detector_kind(finding) != detector_kind(primary)])

        merged = dict(primary)
        anchor = _choose_review_anchor(cluster, primary)
        merged["confidence"] = min(
            0.99,
            max(float(finding.get("confidence") or 0) for finding in cluster) + 0.05,
        )
        merged["line_start"] = anchor.get("line_start") or merged.get("line_start")
        merged["line_end"] = anchor.get("line_end") or merged.get("line_end")
        merged["code_snippet"] = anchor.get("code_snippet") or merged.get("code_snippet")
        merged["taxonomy_mappings"] = _merge_taxonomy(cluster)
        merged["taxonomy_versions"] = _merge_taxonomy_versions(cluster)
        if merged["taxonomy_mappings"].get("cwe"):
            merged["cwe_id"] = merged["taxonomy_mappings"]["cwe"][0]
        if merged["taxonomy_mappings"].get("owasp"):
            merged["owasp_category"] = merged["taxonomy_mappings"]["owasp"][0]

        evidence_lines = [str(primary.get("evidence") or primary.get("description") or "").strip()]
        if supporting_rules:
            evidence_lines.append(f"Supporting detections: {', '.join(supporting_rules)}.")
        if supporting_detectors:
            evidence_lines.append(f"Corroborated by: {', '.join(supporting_detectors)}.")
        merged["evidence"] = " ".join(part for part in evidence_lines if part)
        clustered.append(merged)

    clustered.sort(
        key=lambda finding: (
            -SEVERITY_RANK.get(str(finding.get("severity") or "").lower(), 0),
            -(float(finding.get("confidence") or 0)),
            str(finding.get("file_path") or ""),
            int(finding.get("line_start") or 0),
        )
    )
    return clustered
