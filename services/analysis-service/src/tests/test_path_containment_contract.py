"""The path-containment contract between the analysis and remediation services.

The remediation service teaches its repair agent one shape for a path-traversal fix
(services/remediation-service/src/families.py, the `path_containment` family): resolve the
candidate path against the base directory and reject it unless the resolved path is the base
itself or starts with base + path.sep, before any filesystem access. These tests are the
analysis side of that agreement. Tier 1 and tier 2 must both go quiet on that shape, and both
must keep reporting a `path.basename`-only defence, which `INSUFFICIENT_SANITIZERS` in
opengrep_runner.py already calls out as not good enough.
"""

import shutil
import subprocess

import pytest

from main import AnalyzePRRequest, analyze_tier1_payload, analyze_tier2_payload


def _can_run_opengrep() -> bool:
    opengrep_path = shutil.which("semgrep")
    if not opengrep_path:
        return False
    try:
        result = subprocess.run(
            [opengrep_path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return result.returncode == 0


skip_no_opengrep = pytest.mark.skipif(
    not _can_run_opengrep(),
    reason="OpenGrep not available or TLS trust anchors missing",
)


PREAMBLE = """const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const REPORT_DIR = path.join(__dirname, '..', 'reports');
"""

TAIL = """
module.exports = router;
"""

# The repair the remediation service asks for: resolve against the base, reject anything that
# leaves it, and only then read.
CONTAINED = PREAMBLE + """
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
""" + TAIL

# The same repair written as a positive guard around the read.
CONTAINED_POSITIVE_GUARD = PREAMBLE + """
router.get('/reports/download', (req, res) => {
  const base = path.resolve(REPORT_DIR);
  const target = path.resolve(base, String(req.query.name || ''));
  if (target === base || target.startsWith(base + path.sep)) {
    fs.readFile(target, (error, data) => {
      if (error) return res.status(404).end();
      res.type('application/pdf').send(data);
    });
  } else {
    res.status(400).end();
  }
});
""" + TAIL

# What the repair agent used to produce: a basename-only defence.
BASENAME_ONLY = PREAMBLE + """
router.get('/reports/download', (req, res) => {
  const target = path.join(REPORT_DIR, path.basename(req.query.name));
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});
""" + TAIL

# No defence at all.
UNGUARDED = PREAMBLE + """
router.get('/reports/download', (req, res) => {
  const target = path.join(REPORT_DIR, req.query.name);
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});
""" + TAIL

# Resolving without the containment check is not a repair either.
RESOLVE_WITHOUT_CHECK = PREAMBLE + """
router.get('/reports/download', (req, res) => {
  const target = path.resolve(REPORT_DIR, req.query.name);
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});
""" + TAIL

# A containment check on some other value must not launder the tainted path.
GUARD_ON_ANOTHER_VALUE = PREAMBLE + """
router.get('/reports/download', (req, res) => {
  const owner = String(req.query.owner || '');
  const target = path.resolve(REPORT_DIR, req.query.name);
  if (!owner.startsWith('acme-')) {
    return res.status(400).end();
  }
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});
""" + TAIL


def _payload(content: str) -> AnalyzePRRequest:
    added = "\n".join("+" + line for line in content.splitlines())
    patch = f"@@ -0,0 +1,{len(content.splitlines())} @@\n{added}"
    return AnalyzePRRequest(
        repository_full_name="nebullii/test-only",
        pull_request_number=1,
        commit_sha="0" * 40,
        files=[{"path": "services/orders.js", "patch": patch, "content": content}],
    )


def _traversal(result) -> list:
    return [f for f in result["findings"] if f.get("category") == "path traversal"]


@pytest.mark.parametrize("source", [CONTAINED, CONTAINED_POSITIVE_GUARD])
def test_tier1_accepts_resolve_and_contain(source):
    assert _traversal(analyze_tier1_payload(_payload(source))) == []


@pytest.mark.parametrize(
    "source",
    [BASENAME_ONLY, UNGUARDED, RESOLVE_WITHOUT_CHECK, GUARD_ON_ANOTHER_VALUE],
)
def test_tier1_still_matches_anything_short_of_containment(source):
    """The tier 1 rule still fires on every uncontained shape; it is withheld, not removed.

    `path.traversal.user_path` is quarantined on a measured precision of 0.43
    (docs/validation/vulnerable-corpus-2026-09.md), so its findings no longer reach a
    reviewer. That is a posting decision and not a change to what the rule recognizes: it
    still has to match all four of these, or the measurement that justifies the quarantine
    has silently stopped describing the rule and nothing could ever re-enable it.
    """
    result = analyze_tier1_payload(_payload(source))
    assert _traversal(result) == []
    assert result["quarantined_findings"] == {"path.traversal.user_path": 1}


@pytest.mark.parametrize(
    "source",
    [BASENAME_ONLY, UNGUARDED, RESOLVE_WITHOUT_CHECK, GUARD_ON_ANOTHER_VALUE],
)
@skip_no_opengrep
def test_a_reviewer_still_gets_the_finding_from_tier2(source):
    """Quarantining the tier 1 rule must not take the contract's output away.

    Tier 1's rule was the broad one and tier 2's is the narrow one. If the narrow one ever
    stops covering these four shapes, the quarantine turns into a silent removal of path
    traversal reporting, which is the failure this file exists to prevent.
    """
    findings = _traversal(analyze_tier2_payload(_payload(source)))
    assert [f["rule_id"] for f in findings] == ["opengrep.cwe-22.path-traversal-fs"]


@skip_no_opengrep
@pytest.mark.parametrize("source", [CONTAINED, CONTAINED_POSITIVE_GUARD])
def test_tier2_accepts_resolve_and_contain(source):
    assert _traversal(analyze_tier2_payload(_payload(source))) == []


@skip_no_opengrep
@pytest.mark.parametrize(
    "source",
    [BASENAME_ONLY, UNGUARDED, RESOLVE_WITHOUT_CHECK, GUARD_ON_ANOTHER_VALUE],
)
def test_tier2_still_reports_anything_short_of_containment(source):
    findings = _traversal(analyze_tier2_payload(_payload(source)))
    assert len(findings) == 1
    assert findings[0]["rule_id"].endswith("cwe-22.path-traversal-fs")
