import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional

from comment_stripper import strip_lines
from test_code_scope import is_non_code_text_path


def make_fingerprint(rule_id: str, path: str, line_start: int, snippet: str) -> str:
    """The identity of a finding, and the key everything downstream joins on.

    It lives here, in the module that owns finding shape, because four modules need it and
    none of them may import the others: `main` and `opengrep_runner` had identical copies, and
    `secret_detection` reaching into `main` for it made the import order decide which service's
    `main` answered when the Action puts two of them on `sys.path`. `main.make_fingerprint` and
    `opengrep_runner.make_fingerprint` are re-exports of this, so every existing caller and the
    GitHub comment marker are unchanged.
    """
    raw = f"{rule_id}|{path}|{line_start}|{snippet.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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


def parse_patch_entries(patch: str, path: Any = None, content: Any = None) -> List[Dict[str, Any]]:
    """Reviewable lines of `patch`, in file order, each with its new-side line number.

    When `path` names a language the comment stripper models, every entry also carries
    `scan_text` (comments blanked) and `scan_text_no_strings` (comments and string bodies
    blanked). `content` is always the untouched line, so a finding quotes what the author
    wrote.

    Comment state is scanned per hunk when the file's own text is not available, because a
    diff does not show what came before the hunk. Given `content` - the file at the head
    revision, which both the App and the Action already fetch for the semgrep tier - the
    state is scanned over the whole file instead, so a hunk that opens inside a docstring is
    read as being inside one.
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

        # Named apart from the `content` parameter, which is the whole file: rebinding it here
        # emptied the file text before `_annotate_scan_text` ever saw it.
        line_text = raw_line[1:] if raw_line.startswith(" ") else raw_line
        entries.append(
            {
                "kind": "context",
                "line_number": new_line,
                "content": line_text,
                "hunk": hunk,
            }
        )
        old_line += 1
        new_line += 1

    _annotate_scan_text(entries, path, content)
    return entries


def _file_lines(content: Any) -> List[str]:
    text = str(content or "")
    if not text:
        return []
    return text.replace("\r\n", "\n").split("\n")


def _annotate_scan_text(entries: List[Dict[str, Any]], path: Any, content: Any = None) -> None:
    """Attach the comment-blanked text of every entry, from the file when there is one.

    Scanning a hunk on its own cannot know what came before it. A hunk that begins inside a
    Python docstring therefore reads as code: flask `src/flask/views.py:158` was reported as
    "Potential open redirect" on `return redirect(url_for("counter"))`, which sits inside a
    `.. code-block:: python` example in the `MethodView` docstring and redirects to a
    hard-coded endpoint. It was the only false positive of the September 2026 action trial.

    Given the file, the state is scanned over the whole of it and each entry takes the mask of
    its own line. A line is only taken from the file when the file's text at that line number is
    exactly the entry's text, so a patch against a different revision, a truncated fetch or a
    line-number quirk falls back to the per-hunk scan rather than blanking the wrong line.
    """
    file_lines = _file_lines(content)
    whole_code: List[str] = []
    whole_blanked: List[str] = []
    if file_lines:
        whole_code = strip_lines(file_lines, path)
        whole_blanked = strip_lines(file_lines, path, blank_strings=True)

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
            number = int(entry.get("line_number") or 0)
            if 1 <= number <= len(file_lines) and file_lines[number - 1] == entry["content"]:
                entry["scan_text"] = whole_code[number - 1]
                entry["scan_text_no_strings"] = whole_blanked[number - 1]


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
    content: Any = None,
) -> Optional[Dict[str, Any]]:
    """First reviewable line of `patch` that `pattern` matches and `exclusion` does not.

    `exclusion` is the second pass that replaces a negative lookahead: the condition is
    evaluated against the same text the pattern saw, where backtracking cannot defeat it.
    """
    entries = parse_patch_entries(patch, path, content)
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
    content: Any = None,
) -> bool:
    return find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion,
        blank_strings=blank_strings, content=content,
    ) is not None


def pattern_match_lines(
    patch: str,
    pattern,
    *,
    path: Any = None,
    exclusion=None,
    blank_strings: bool = False,
    content: Any = None,
) -> List[int]:
    """Every reviewable line of `patch` that `pattern` matches, in file order.

    `find_pattern_match_entry` answers "does this rule fire here", which is all tier 1 needs
    to emit its one finding per rule per file. A static assertion needs more than that: clause
    1 asks whether the rule matches *the finding's line* and clause 2 asks whether it matches
    the patched file *anywhere*, and a first-match answer cannot decide either on a file with
    two instances of the same defect. So this walks every entry rather than stopping.
    """
    lines: List[int] = []
    for entry in parse_patch_entries(patch, path, content):
        if is_transcript_artifact_line(entry["content"]):
            continue
        text = entry_scan_text(entry, blank_strings=blank_strings)
        if not pattern.search(text):
            continue
        if exclusion is not None and exclusion.search(text):
            continue
        lines.append(int(entry["line_number"]))
    return sorted(set(lines))


def rule_scan_options(rule, file_path: str, content: str = "") -> Dict[str, Any]:
    """How a rule reads a patch: which file it is, what it must not see, what it may.

    `content` is the file at the head revision when the request carried it. It is what lets the
    comment stripper know that a hunk began inside a docstring, which a diff cannot show.
    """
    exclusion = getattr(rule, "exclusion", None)
    prose_exclusion = getattr(rule, "non_code_text_exclusion", None)
    if prose_exclusion is not None and is_non_code_text_path(file_path):
        # Both conditions have to hold, and `find_pattern_match_entry` takes one pattern, so
        # they are combined into a single alternation rather than threaded through as a list.
        exclusion = (
            re.compile(f"(?:{exclusion.pattern})|(?:{prose_exclusion.pattern})")
            if exclusion is not None
            else prose_exclusion
        )
    return {
        "path": file_path,
        "exclusion": exclusion,
        "blank_strings": not getattr(rule, "reads_string_literals", True),
        "content": content,
    }


def whole_file_patch(content: str) -> str:
    """A file's full text as an all-context unified diff, so a rule can be run over it.

    Every tier 1 entry point reads a patch, because detection only ever looks at changed
    lines. A static assertion has to read whole files instead: clause 2 is a claim about the
    patched file anywhere, not about its diff. Rather than teach the matchers a second input
    shape, the file is presented as a diff in which every line is context, with a hunk header
    so the reported line numbers are the file's own. Each line is prefixed with one space, so
    a body line that itself starts with `-` or `+` is read as text and not as a diff marker.
    """
    lines = str(content or "").split("\n")
    header = f"@@ -1,{len(lines)} +1,{len(lines)} @@"
    return "\n".join([header, *(" " + line for line in lines)])


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
    content: Any = None,
) -> bool:
    """True when a filesystem read matched by `pattern` is guarded by resolve-and-contain.

    The guard has to sit above the read, within `window` lines of it, and has to do both halves
    of the job on the same value: resolve the candidate path into a variable, and compare that
    variable against the base directory. Either half alone, or a check made on some other value,
    leaves the finding in place.
    """
    match_entry = find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion,
        blank_strings=blank_strings, content=content,
    )
    if match_entry is None:
        return False

    entries = parse_patch_entries(patch, path, content)
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
    content: Any = None,
    context_before: int = 2,
    context_after: int = 3,
    max_lines: int = 8,
) -> Dict[str, Any]:
    entries = parse_patch_entries(patch, path, content)
    if not entries:
        return {
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "matched_text": "",
        }

    match_entry = find_pattern_match_entry(
        patch, pattern, path=path, exclusion=exclusion,
        blank_strings=blank_strings, content=content,
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


# One weakness described twice, where the two descriptions are not the same kind of thing.
#
# `_same_cluster` merges findings that share an `internal_type`, which is the symmetric case: two
# detectors saw the same flaw and either name is the right name for it. This table is the
# asymmetric one. The key subsumes the values: a finding of a subsumed type at the same site
# exists *because* of the subsuming finding, and the subsuming finding's fix removes it. Reporting
# both asks a reviewer to make one change twice.
#
# It is directional on purpose, and the direction is not a preference between two equals. Under
# `pull_request_target`, `persist-credentials: true` leaves the base repository's token in
# `.git/config` only because the step checked out a contributor's revision; stop doing that and
# there is nothing left to fix. The reverse does not hold, so an ordinary `pull_request` workflow
# that leaves `persist-credentials` on is still reported on its own.
#
# This lives here rather than in the rule patterns because it is a question about two findings,
# and a rule can only see one. A `pattern-not` in `workflow_coverage.yml` would have had to
# re-express the other rule's whole pattern inside this one, and the two would then drift apart
# silently the first time either was narrowed.
SUBSUMED_INTERNAL_TYPES: Dict[str, frozenset] = {
    "untrusted_code_checkout": frozenset({"workflow_credential_persistence"}),
}

# How far apart two findings may be and still be the same site, in lines.
#
# Both workflow rules already require their keys to be within six lines of each other, because
# what makes the pair a pair is that they are one `actions/checkout` step. Eight lines is that
# distance plus the two the rules can each be anchored off by, and it is a proxy for "the same
# step" rather than a parse: the clusterer has the findings, not the document.
SUBSUMPTION_LINE_WINDOW = 8


def _record_supporting_detections(
    survivor: Dict[str, Any],
    supporting: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """A copy of `survivor` carrying the rule ids and taxonomy of the findings that did not survive.

    Shared by the symmetric merge in `cluster_findings` and the directional fold in
    `_apply_subsumption`, so a finding that was folded is as traceable as one that was clustered:
    `merged_rule_ids` names every rule that matched, in the survivor's own evidence and in the
    extras map that crosses the gRPC contract intact.
    """
    supporting_rules = _merge_unique(
        [
            finding.get("rule_id")
            for finding in supporting
            if finding.get("rule_id") != survivor.get("rule_id")
        ]
    )
    supporting_detectors = _merge_unique(
        [
            detector_kind(finding)
            for finding in supporting
            if detector_kind(finding) != detector_kind(survivor)
        ]
    )

    merged = dict(survivor)
    # The union of the rule ids that detected this flaw, the survivor's first. Downstream
    # mapping by rule id (the remediation service's repair families) then still resolves the
    # finding whichever rule id survived. It also travels in the evidence extras, the one map on
    # the finding that crosses the gRPC contract intact.
    merged_rule_ids = _merge_unique(
        [*(survivor.get("merged_rule_ids") or [survivor.get("rule_id")]), *supporting_rules]
    )
    merged["merged_rule_ids"] = merged_rule_ids
    details = dict(merged.get("evidence_details") or {})
    extra = dict(details.get("extra") or {})
    extra["merged_rule_ids"] = merged_rule_ids
    details["extra"] = extra
    merged["evidence_details"] = details

    evidence_lines = [str(survivor.get("evidence") or survivor.get("description") or "").strip()]
    if supporting_rules:
        evidence_lines.append(f"Supporting detections: {', '.join(supporting_rules)}.")
    if supporting_detectors:
        evidence_lines.append(f"Corroborated by: {', '.join(supporting_detectors)}.")
    merged["evidence"] = " ".join(part for part in evidence_lines if part)
    return merged


def _subsumes(survivor: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    """True when `candidate` is a consequence of `survivor` at the same site."""
    subsumed = SUBSUMED_INTERNAL_TYPES.get(str(survivor.get("internal_type") or ""))
    if not subsumed or str(candidate.get("internal_type") or "") not in subsumed:
        return False
    if survivor.get("file_path") != candidate.get("file_path"):
        return False
    survivor_line = int(survivor.get("line_start") or 0)
    candidate_line = int(candidate.get("line_start") or 0)
    if not survivor_line or not candidate_line:
        return False
    return abs(survivor_line - candidate_line) <= SUBSUMPTION_LINE_WINDOW


def _apply_subsumption(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop every finding another finding at the same site already accounts for.

    The survivor is pinned by the table, never chosen by severity or confidence, because the
    point is which fix a reviewer should make and that is not a question about scores.

    Confidence is deliberately left alone. The symmetric merge raises it, because two detectors
    agreeing is evidence; a consequence agreeing with its cause is not, so folding one in says
    nothing new about whether the survivor is real.
    """
    if not any(str(finding.get("internal_type") or "") in SUBSUMED_INTERNAL_TYPES for finding in findings):
        # Nothing here subsumes anything, which is the overwhelmingly common case.
        return findings

    folded: Dict[int, List[Dict[str, Any]]] = {}
    absorbed: set = set()
    for index, candidate in enumerate(findings):
        for survivor_index, survivor in enumerate(findings):
            if survivor_index == index or survivor_index in absorbed:
                continue
            if _subsumes(survivor, candidate):
                folded.setdefault(survivor_index, []).append(candidate)
                absorbed.add(index)
                break

    if not absorbed:
        return findings

    result: List[Dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if index in absorbed:
            continue
        supporting = folded.get(index)
        result.append(_record_supporting_detections(finding, supporting) if supporting else finding)
    return result


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

        merged = _record_supporting_detections(primary, cluster)
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

        clustered.append(merged)

    # Clustering answers "are these the same flaw". Subsumption answers the different question of
    # whether one of them only exists because of another, and it runs afterwards so that what it
    # folds is a cluster survivor rather than one member of a cluster.
    clustered = _apply_subsumption(clustered)

    clustered.sort(
        key=lambda finding: (
            -SEVERITY_RANK.get(str(finding.get("severity") or "").lower(), 0),
            -(float(finding.get("confidence") or 0)),
            str(finding.get("file_path") or ""),
            int(finding.get("line_start") or 0),
        )
    )
    return clustered
