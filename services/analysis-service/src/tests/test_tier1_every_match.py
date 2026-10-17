"""A tier 1 rule reports every line it matches in a file, not the first one.

`pattern_findings` used to emit one finding per rule per file, at the first match. On the
vulnerable corpus that cost nine of the eighteen labels that were "found in the file but not
on the labelled line": `enrocrypt/hashing.py` offers eight digests including MD5,
`crypto.weak.hash` reported the first at line 16 and the CVE was at line 70
(docs/validation/vulnerable-corpus-2026-09.md, Recall). The cap existed so a file with fifty
weak hashes did not produce fifty comments, which is a rendering question, and it was being
answered by truncating detection.

Now every match is a finding on its own line, up to `TIER1_MAX_MATCHES_PER_RULE_PER_FILE`,
and past that the run records a `match_cap` limitation saying how many of how many it
reported. The roll-up into one row per rule per file happens in the review body builders,
where it belongs. docs/validation/every-match-2026-10.md is the record.
"""
from __future__ import annotations

import re
import time

from main import (
    AnalyzePRRequest,
    ChangedFile,
    LIMITATION_MATCH_CAP,
    TIER1_MAX_MATCHES_PER_RULE_PER_FILE,
    analyze_tier1_payload,
    pattern_findings,
)

WEAK_HASH_RULE = "crypto.weak.hash"

# Eight digest helpers over strings, bytes, files and streams, the shape of enrocrypt's
# `hashing.py`: one class, one method per digest, the weak ones spread through the file.
EIGHT_DIGESTS = '''\
"""Message digests over strings, bytes, files and streams."""
import hashlib

CHUNK = 65536


class Hashing:
    """Every digest the library offers, in the order the documentation lists them."""

    def md5_string(self, text):
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    def md5_bytes(self, data):
        return hashlib.md5(data).hexdigest()

    def md5_file(self, path):
        with open(path, "rb") as handle:
            return hashlib.md5(handle.read()).hexdigest()

    def md5_stream(self, stream):
        digest = hashlib.md5()
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
        return digest.hexdigest()

    def sha1_string(self, text):
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    def sha1_bytes(self, data):
        return hashlib.sha1(data).hexdigest()

    def sha1_file(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha1(handle.read()).hexdigest()

    def sha1_stream(self, stream):
        digest = hashlib.sha1()
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
        return digest.hexdigest()
'''

HASHING_PATH = "enrocrypt/hashing.py"


def _added_patch(text: str) -> str:
    lines = text.rstrip("\n").split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join(f"+{line}" for line in lines)


def _weak_hash_lines(text: str) -> list[int]:
    return [
        number
        for number, line in enumerate(text.rstrip("\n").split("\n"), start=1)
        if re.search(r"\b(md5|sha1)\s*\(", line)
    ]


def _weak_hash_findings(findings):
    return [finding for finding in findings if finding["rule_id"] == WEAK_HASH_RULE]


def _scan(path: str, text: str, limitations=None):
    files = [ChangedFile(path=path, patch=_added_patch(text), content=text)]
    return pattern_findings(files, [] if limitations is None else limitations)


class TestEveryMatchIsAFinding:
    def test_the_fixture_has_eight_weak_digests(self):
        """Otherwise the tests below pass without measuring anything."""
        assert len(_weak_hash_lines(EIGHT_DIGESTS)) == 8

    def test_eight_weak_hashes_are_eight_findings_on_eight_lines(self):
        findings = _weak_hash_findings(_scan(HASHING_PATH, EIGHT_DIGESTS))

        assert len(findings) == 8
        assert [f["line_start"] for f in findings] == _weak_hash_lines(EIGHT_DIGESTS)
        assert all(f["file_path"] == HASHING_PATH for f in findings)

    def test_each_finding_quotes_its_own_line(self):
        findings = _weak_hash_findings(_scan(HASHING_PATH, EIGHT_DIGESTS))
        source_lines = EIGHT_DIGESTS.split("\n")
        for finding in findings:
            assert finding["code_snippet"] == source_lines[finding["line_start"] - 1]

    def test_fingerprints_are_distinct_per_line_and_stable_across_runs(self):
        first = _weak_hash_findings(_scan(HASHING_PATH, EIGHT_DIGESTS))
        second = _weak_hash_findings(_scan(HASHING_PATH, EIGHT_DIGESTS))

        fingerprints = [f["fingerprint"] for f in first]
        assert len(set(fingerprints)) == 8
        assert fingerprints == [f["fingerprint"] for f in second]

    def test_no_limitation_under_the_ceiling(self):
        limitations: list = []
        _scan(HASHING_PATH, EIGHT_DIGESTS, limitations)
        assert limitations == []


class TestAddedLinesTakePrecedence:
    """The one-line rule picked an added line over a context line. Every-match keeps that."""

    def test_only_the_added_matches_are_reported_when_any_added_line_matches(self):
        patch = (
            "@@ -1,3 +1,4 @@\n"
            " import hashlib\n"
            " legacy = hashlib.md5(a).hexdigest()\n"
            "+recent = hashlib.sha1(b).hexdigest()\n"
            " done = True\n"
        )
        findings = _weak_hash_findings(pattern_findings([ChangedFile(path="h.py", patch=patch)], []))
        assert [f["line_start"] for f in findings] == [3]

    def test_every_context_match_is_reported_when_no_added_line_matches(self):
        patch = (
            "@@ -1,4 +1,4 @@\n"
            " import hashlib\n"
            " first = hashlib.md5(a).hexdigest()\n"
            " second = hashlib.sha1(b).hexdigest()\n"
            " done = True\n"
        )
        findings = _weak_hash_findings(pattern_findings([ChangedFile(path="h.py", patch=patch)], []))
        assert [f["line_start"] for f in findings] == [2, 3]


class TestTheCeiling:
    MANY = 40

    def _many_hashes(self) -> str:
        lines = ["import hashlib", ""]
        lines.extend(f"digest_{i} = hashlib.md5(chunk_{i}).hexdigest()" for i in range(self.MANY))
        return "\n".join(lines) + "\n"

    def test_the_ceiling_is_the_named_constant(self):
        assert TIER1_MAX_MATCHES_PER_RULE_PER_FILE == 25

    def test_a_file_over_the_ceiling_reports_the_ceiling_and_says_so(self):
        limitations: list = []
        findings = _weak_hash_findings(_scan("bulk/hashes.py", self._many_hashes(), limitations))

        assert len(findings) == TIER1_MAX_MATCHES_PER_RULE_PER_FILE
        assert len({f["line_start"] for f in findings}) == TIER1_MAX_MATCHES_PER_RULE_PER_FILE
        assert [f["line_start"] for f in findings] == list(range(3, 3 + TIER1_MAX_MATCHES_PER_RULE_PER_FILE))

        # One limitation per rule that went over. `null.pointer.deref` also matches all forty
        # lines (it reads `.hexdigest()` chains), but it is quarantined: nothing it finds is
        # posted, so its ceiling is not a gap in what a reviewer was told and is not stated.
        assert all(item["kind"] == LIMITATION_MATCH_CAP for item in limitations)
        assert len(limitations) == 1
        limitation = limitations[0]
        assert limitation["path"] == "bulk/hashes.py"
        assert limitation["message"] == f"{WEAK_HASH_RULE} reported 25 of {self.MANY} matches in bulk/hashes.py"
        assert limitation["type"] == f"{WEAK_HASH_RULE} reported 25 of {self.MANY} matches"

    def test_the_tier1_response_carries_the_limitation_and_the_findings(self):
        text = self._many_hashes()
        payload = AnalyzePRRequest(
            repository_full_name="acme/bulk",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": "bulk/hashes.py", "patch": _added_patch(text), "content": text}],
        )
        result = analyze_tier1_payload(payload)

        assert any(
            item["kind"] == LIMITATION_MATCH_CAP and item["path"] == "bulk/hashes.py"
            for item in result["analysis_limitations"]
        )
        reported = _weak_hash_findings(result["findings"])
        assert len(reported) == TIER1_MAX_MATCHES_PER_RULE_PER_FILE, (
            "the fold after detection must keep one finding per line; it used to chain adjacent "
            "same-rule findings into one cluster through the two-line window"
        )
        assert len({f["line_start"] for f in reported}) == TIER1_MAX_MATCHES_PER_RULE_PER_FILE


# A guarded read and an unguarded read in one file. The guard is the containment repair the
# taint rule accepts (test_path_containment_contract.py), and it has to be more than
# `PATH_CONTAINMENT_WINDOW` lines above the second read or the window would see it.
GUARDED_THEN_UNGUARDED = """\
const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const REPORT_DIR = path.join(__dirname, '..', 'reports');

router.get('/reports/download', (req, res) => {
  const base = path.resolve(REPORT_DIR);
  const target = path.resolve(base, String(req.query.name || ''));
  if (target !== base && !target.startsWith(base + path.sep)) {
    return res.status(400).json({ error: 'invalid report name' });
  }
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});

// Padding so the second read sits well outside the first read's guard window.
function describe(entry) {
  return {
    name: entry.name,
    size: entry.size,
    modified: entry.mtime,
    owner: entry.owner,
    group: entry.group,
    mode: entry.mode,
    kind: entry.kind,
    tags: entry.tags,
    notes: entry.notes,
  };
}

router.get('/reports/preview', (req, res) => {
  const preview = path.join(REPORT_DIR, req.query.name);
  fs.readFile(preview, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});

module.exports = router;
"""


class TestEachMatchIsJudgedOnItsOwnGuard:
    def test_an_unguarded_read_below_a_guarded_one_is_still_reported(self):
        """The first read's guard used to silence the rule for the whole file."""
        findings = [
            f for f in _scan("services/reports.js", GUARDED_THEN_UNGUARDED)
            if f["category"] == "path traversal"
        ]
        lines = GUARDED_THEN_UNGUARDED.split("\n")
        preview_route = next(i for i, line in enumerate(lines, start=1) if "/reports/preview" in line)

        assert len(findings) == 1
        assert findings[0]["line_start"] > preview_route


def _tier2_twin(tier1: dict, line: int | None = None) -> dict:
    """What the AST tier says about the same line, under its own rule id."""
    twin = dict(tier1)
    twin["rule_id"] = "opengrep.cwe-327.weak-hash"
    twin["severity"] = "high"
    twin["confidence"] = 0.9
    twin["fingerprint"] = f"tier2-{line or tier1['line_start']}"
    if line is not None:
        twin["line_start"] = twin["line_end"] = line
    return twin


class TestTheFoldKeepsOneCommentPerLine:
    """`cluster_findings` merges detectors, not lines."""

    def _consecutive(self, count: int):
        text = "import hashlib\n" + "\n".join(
            f"d{i} = hashlib.md5(part{i}).hexdigest()" for i in range(count)
        ) + "\n"
        findings = _weak_hash_findings(_scan("h.py", text))
        assert [f["line_start"] for f in findings] == list(range(2, 2 + count))
        return findings

    def test_same_rule_findings_on_consecutive_lines_stay_separate(self):
        from finding_quality import cluster_findings

        clustered = cluster_findings(self._consecutive(8))

        assert sorted(f["line_start"] for f in clustered) == list(range(2, 10))
        assert all("merged_rule_ids" not in f for f in clustered)

    def test_a_cross_tier_pair_on_one_line_still_folds_and_its_neighbours_survive(self):
        from finding_quality import cluster_findings

        tier1 = self._consecutive(8)
        twin = _tier2_twin(tier1[4])

        clustered = cluster_findings([*tier1, twin])

        assert sorted(f["line_start"] for f in clustered) == list(range(2, 10))
        folded = [f for f in clustered if "merged_rule_ids" in f]
        assert len(folded) == 1
        assert folded[0]["line_start"] == tier1[4]["line_start"]
        assert set(folded[0]["merged_rule_ids"]) == {WEAK_HASH_RULE, twin["rule_id"]}

    def test_the_fold_goes_to_the_nearest_line_not_the_first_within_the_window(self):
        """Eight hashes, and the AST tier reports the one on line 6: the fold lands on line 6.

        With same-rule clusters kept apart, line 4 is also within the two-line window and
        comes first; joining the first cluster seen would put the tier 2 finding two lines
        from where it was reported.
        """
        from finding_quality import cluster_findings

        tier1 = self._consecutive(8)
        twin = _tier2_twin(tier1[4])
        clustered = cluster_findings([*tier1, twin])

        folded = [f for f in clustered if "merged_rule_ids" in f]
        assert [f["line_start"] for f in folded] == [tier1[4]["line_start"]]

    def test_a_tier2_finding_anchored_a_line_off_still_meets_its_twin_and_only_its_twin(self):
        """The two-line window is for detectors that anchor one flaw a line apart."""
        from finding_quality import cluster_findings

        text = "import hashlib\n" + "".join(
            f"d{i} = hashlib.md5(part{i}).hexdigest()\n\n" for i in range(3)
        )
        tier1 = _weak_hash_findings(_scan("h.py", text))
        assert [f["line_start"] for f in tier1] == [2, 4, 6]
        # The AST tier anchors the last hash one line below it, where nothing else is.
        off_by_one = _tier2_twin(tier1[2], line=7)

        clustered = cluster_findings([*tier1, off_by_one])

        assert sorted(f["line_start"] for f in clustered) == [2, 4, 6]
        folded = [f for f in clustered if "merged_rule_ids" in f]
        assert [f["line_start"] for f in folded] == [6]

    def test_two_different_detectors_on_one_line_are_still_one_comment(self):
        """Issue 487's case, unchanged: the fold was never the problem."""
        from finding_quality import cluster_findings

        tier1 = self._consecutive(1)
        clustered = cluster_findings([tier1[0], _tier2_twin(tier1[0])])

        assert len(clustered) == 1


class TestCost:
    def test_the_fold_over_a_file_of_two_hundred_matches_is_cheap(self):
        """`cluster_findings` is quadratic in the findings; this is the bound the change relies on."""
        from finding_quality import cluster_findings

        findings = [
            {
                "rule_id": WEAK_HASH_RULE,
                "internal_type": "weak_cipher_algorithm",
                "file_path": HASHING_PATH,
                "line_start": 10 + index,
                "line_end": 10 + index,
                "code_snippet": f"h{index} = hashlib.md5(data{index})",
                "severity": "medium",
                "confidence": 0.78,
                "category": "insecure cryptography",
            }
            for index in range(200)
        ]
        started = time.monotonic()
        clustered = cluster_findings(findings)
        elapsed = time.monotonic() - started

        assert elapsed < 1.0, f"clustering 200 findings took {elapsed:.2f} s"
        assert len(clustered) == 200
