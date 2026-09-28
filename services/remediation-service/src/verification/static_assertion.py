"""The static assertion level: what it claims, and the five clauses it has to clear.

An executed proof runs a regression test that fails on the original tree and passes on the
patched one. It is the strongest thing this product does and it is what `docs/design/
prove-before-post.md` is about. It is also unavailable for most findings: 84 of the 249
supported-family findings on the September 2026 corpus get no proof because the module the proof
would load imports a package the sandbox has no copy of
(`docs/validation/pairs-2026-09.md`), and for two categories the product needs next, a tampered
workflow and a committed secret, no regression test could exist at all.

So there is a second, weaker, honestly named level. A candidate is verified at
`static_assertion` when all five of these hold and the evidence records each one:

1. The rule that produced the finding matches the original file at the finding's line.
2. The same rule does not match the patched file anywhere.
3. The patch touches only the finding's own file, and within it only lines inside the finding's
   region plus whatever the template declares. No other line in the file changed.
4. No rule that did not already match the original file matches the patched file. This is the
   clause that stops a repair from trading one vulnerability for another, and it is the one that
   makes the level worth putting in front of a reviewer at all.
5. Nothing was executed. The evidence says so in those words.

It is strictly weaker than `development_unverified`, which is itself the weakest executed level,
and `VERIFICATION_LEVEL_ORDER` in `verifier.py` says so. It is never an upgrade: the engine
reaches for it only for a family that declares it (`families.declares_static_assertion`, which is
`FAMILY_VERIFICATION`) or for a
finding whose execution was refused for a reason that goes into the evidence.

**Where the rules run.** Not here. This service cannot install semgrep: its image pins
`opentelemetry-api==1.44.0` and semgrep needs `~=1.37.0`, which is the reason
`action/requirements.txt` gives for excluding them from one environment. The rules and the runner
belong to the analysis service, so the match sets are asked of it through a `RuleOracle`. Two
implementations, because the two deployments differ:

* `InProcessRuleOracle` imports the analysis service's own modules. This is what the GitHub
  Action uses, where the engine and the analysis service already run in one process with semgrep
  present (`action/orchestrator/analysis.py`), and what the benchmark and the replay harness use.
* `HttpRuleOracle` posts to `POST /verify/static-assertion` with the shared internal secret, the
  same header and env var the api-service uses to reach the analysis service. This is the App,
  where the two are separate Cloud Run services.

An oracle that cannot answer refuses the candidate. It never returns an empty match set: an
empty match set is the shape of "the rule no longer matches", which is the thing being claimed.
That holds for a missing match set as well as for an absent oracle, which is what
`_require_match_sets` is for: a side of the answer with no `all_matches` at all is not a file
that matched nothing, and clause 4 is never decided from it. An oracle that has no scanner to run
says so under its own code rather than by failing at the first query, so a deployment reading the
reason can tell "install the scanner" from "the scanner crashed".
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..digests import digest_json
from ..models import FindingSnapshot, RepairRequest
from ..patches import PatchBundle
from ..retrieval import Snapshot

STATIC_ASSERTION_VERIFICATION_LEVEL = "static_assertion"

# The words clause 5 is stated in, here and in the analysis service and in the rendered line.
NOTHING_EXECUTED = "No code was executed."

# The code an unproven finding carries when no clause decided it. Declared here rather than in
# `verifier`, which imports this module, so the two never hold two spellings of one string.
NOT_REPAIRED = "not_repaired"

DEFAULT_ORACLE_TIMEOUT_SECONDS = 60

# The oracle error codes, and which of them mean the rule was never evaluated at all.
#
# The distinction is the whole point of the level. `rule_oracle_failed` is a scanner that ran and
# broke; `rule_oracle_scanner_unavailable` is a process that never had a scanner, so no rule was
# ever asked anything. Both refuse the candidate, but only the second is a deployment fault a
# reason code should be able to name, and neither may ever look like an empty match set.
ORACLE_FAILED = "rule_oracle_failed"
ORACLE_SCANNER_UNAVAILABLE = "rule_oracle_scanner_unavailable"
ORACLE_UNREACHABLE = "rule_oracle_unreachable"
ORACLE_REJECTED_REQUEST = "rule_oracle_rejected_request"
ORACLE_RESPONSE_INVALID = "rule_oracle_response_invalid"

# Every code above says the rule was not evaluated, because none of them carries match sets. They
# are listed rather than derived so adding a code is a decision about this set.
RULE_NOT_EVALUATED_CODES = frozenset(
    {ORACLE_FAILED, ORACLE_SCANNER_UNAVAILABLE, ORACLE_UNREACHABLE, ORACLE_REJECTED_REQUEST, ORACLE_RESPONSE_INVALID}
)


class RuleOracleError(Exception):
    """The match sets could not be obtained. The candidate is refused, never passed."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class RuleOracle(Protocol):
    async def match_sets(self, rule_id: str, path: str, original: str, patched: str) -> dict[str, Any]:
        ...


class InProcessRuleOracle:
    """The analysis service's own module, called directly.

    The Action runs both services in one process and the benchmark and replay harnesses import
    the engine from a checkout, so in both there is no second process to post to. The scanning
    code, the rule files and the posting policy are the analysis service's, unchanged; only the
    transport is gone. Modelled on `action/orchestrator/analysis.py`, which does the same for
    detection.
    """

    def __init__(self, module: Any):
        self._module = module

    @staticmethod
    def unavailable_reason() -> str | None:
        """Why this process cannot answer with the in-process oracle, or None when it can.

        Two separate things have to be true, and before this was asked they were conflated: the
        analysis service's module has to be importable, *and* the scanner that module shells out
        to has to be installed. A checkout with the rules and no scanner satisfies the first and
        fails the second, which is what the repair service's own CI job is, and an oracle built
        in that state answers nothing while looking like an oracle.
        """
        module = _load_analysis_static_assertion()
        if module is None:
            return "the analysis service is not importable from this process"
        if not module.scanner_available():
            return "the analysis service's rule scanner is not installed in this process"
        return None

    @staticmethod
    def load() -> "InProcessRuleOracle | None":
        """The oracle if this process can both import the analysis module and run its scanner.

        None rather than an oracle that raises on first use: a caller with no oracle refuses the
        candidate by name (`verifier.STATIC_ASSERTION_ORACLE_UNAVAILABLE`), which is a better
        answer than a candidate refused halfway through an assertion.
        """
        module = _load_analysis_static_assertion()
        if module is None or not module.scanner_available():
            return None
        return InProcessRuleOracle(module)

    async def match_sets(self, rule_id: str, path: str, original: str, patched: str) -> dict[str, Any]:
        try:
            # The scanner is a subprocess and the tier 1 pass is CPU-bound regex work, so it
            # goes off the event loop: the worker's lease heartbeat shares this loop.
            return await asyncio.to_thread(self._module.match_sets, rule_id, path, original, patched)
        except Exception as exc:  # noqa: BLE001 - any scanner failure refuses the candidate
            raise RuleOracleError(self._error_code(exc), f"{type(exc).__name__}: {exc}") from exc

    def _error_code(self, exc: BaseException) -> str:
        """Which kind of failure this was: no scanner at all, or a scanner that broke.

        `load` checks for the scanner, so reaching this means it went away between the check and
        the query. Rare, and still worth its own code: a deployment reading the reason should not
        have to guess whether to install something or to look at a crash.
        """
        unavailable = getattr(self._module, "ScannerUnavailableError", None)
        if isinstance(unavailable, type) and issubclass(unavailable, BaseException) and isinstance(exc, unavailable):
            return ORACLE_SCANNER_UNAVAILABLE
        return ORACLE_FAILED


class HttpRuleOracle:
    """`POST /verify/static-assertion` on the analysis service, with the shared internal secret.

    The same edge the api-service already uses for detection: `ANALYSIS_SERVICE_URL` for the
    base, `ANALYSIS_SERVICE_INTERNAL_SECRET` (falling back to `GITHUB_SERVICE_INTERNAL_SECRET`)
    in an `x-internal-secret` header, compared on the far side with `hmac.compare_digest`.
    """

    def __init__(self, base_url: str, secret: str, timeout_seconds: float = DEFAULT_ORACLE_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self._secret = secret
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def from_env() -> "HttpRuleOracle | None":
        base_url = os.getenv("ANALYSIS_SERVICE_URL")
        secret = os.getenv("ANALYSIS_SERVICE_INTERNAL_SECRET") or os.getenv("GITHUB_SERVICE_INTERNAL_SECRET")
        if not base_url or not secret:
            return None
        return HttpRuleOracle(base_url, secret, _oracle_timeout_seconds())

    async def match_sets(self, rule_id: str, path: str, original: str, patched: str) -> dict[str, Any]:
        import httpx  # noqa: PLC0415 - deferred so importing this module never needs the client

        payload = {"rule_id": rule_id, "path": path, "original_content": original, "patched_content": patched}
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/verify/static-assertion",
                    json=payload,
                    headers={"x-internal-secret": self._secret},
                )
        except Exception as exc:  # noqa: BLE001 - connect, DNS, timeout: all refuse the candidate
            raise RuleOracleError(ORACLE_UNREACHABLE, f"{type(exc).__name__}: {exc}") from exc
        if response.status_code == 503:
            # What the analysis service answers when its scanner did not run at all
            # (`main.verify_static_assertion`). The same state the in-process oracle reports, so
            # the two deployments give a reviewer the same reason.
            raise RuleOracleError(ORACLE_SCANNER_UNAVAILABLE, "HTTP 503: the analysis service could not run the rule")
        if response.status_code != 200:
            raise RuleOracleError(ORACLE_REJECTED_REQUEST, f"HTTP {response.status_code}")
        try:
            document = response.json()
        except ValueError as exc:
            raise RuleOracleError(ORACLE_RESPONSE_INVALID, "the response body is not JSON") from exc
        if not isinstance(document, dict):
            raise RuleOracleError(ORACLE_RESPONSE_INVALID, "the response body is not an object")
        return document


def _oracle_timeout_seconds() -> float:
    raw = os.getenv("STATIC_ASSERTION_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else 0.0
    except (TypeError, ValueError):
        value = 0.0
    return value if value > 0 else DEFAULT_ORACLE_TIMEOUT_SECONDS


def _load_analysis_static_assertion() -> Any | None:
    """The analysis service's `static_assertion` module, if this process can reach it.

    Tried in the order the deployments are: already imported, then importable from `sys.path`
    (the Action's image puts the analysis source there), then from a checkout beside this one.

    A module counts only when it carries both of the names this side uses: `match_sets` to ask,
    and `scanner_available` to ask first whether asking is worth anything.
    """
    import sys  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    loaded = sys.modules.get("static_assertion")
    if loaded is not None and hasattr(loaded, "match_sets") and hasattr(loaded, "scanner_available"):
        return loaded
    candidates = []
    configured = os.getenv("MITIG8IT_ANALYSIS_SRC")
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path("/opt/mitig8it/services/analysis-service/src"))
    # A checkout rather than an image: .../services/remediation-service/src/verification/this.py,
    # so parents[3] is `services/`. This is how the benchmark and the replay harness reach it.
    candidates.append(Path(__file__).resolve().parents[3] / "analysis-service/src")
    for source in candidates:
        if not (source / "static_assertion.py").is_file():
            continue
        if str(source) not in sys.path:
            sys.path.insert(0, str(source))
        try:
            import static_assertion  # noqa: PLC0415

            return static_assertion
        except Exception:  # noqa: BLE001 - a source tree that will not import is not an oracle
            return None
    return None


def create_rule_oracle() -> RuleOracle | None:
    """The oracle this process can use, or None when it has neither.

    The HTTP edge wins when it is configured, because a deployment that configured it meant the
    assertion to be answered by the analysis service rather than by whatever happens to be
    importable beside this code.
    """
    http = HttpRuleOracle.from_env()
    if http is not None:
        return http
    return InProcessRuleOracle.load()


# --- the clauses -----------------------------------------------------------------------------

CLAUSE_CODES = (
    "rule_matches_original_at_finding_line",
    "rule_does_not_match_patch",
    "patch_confined_to_finding_region",
    "patch_introduces_no_new_rule_match",
    "nothing_executed",
)

REFUSAL_RULE_NOT_MATCHING_ORIGINAL = "static_assertion_rule_does_not_match_original"
REFUSAL_RULE_STILL_MATCHES = "static_assertion_rule_still_matches_patch"
REFUSAL_UNRELATED_FILE = "static_assertion_patch_changes_another_file"
REFUSAL_UNRELATED_LINE = "static_assertion_patch_changes_unrelated_line"
REFUSAL_NEW_RULE_MATCH = "static_assertion_patch_introduces_new_rule_match"
REFUSAL_RULE_UNKNOWN = "static_assertion_rule_not_recognized"
REFUSAL_NO_RULE_ID = "static_assertion_finding_has_no_rule_id"

# The one sentence a passing static assertion is summarized by, in the evidence and in the line
# the GitHub adapter renders. It says what was checked and what was not, and it ends with the
# clause 5 words.
ASSERTION_SENTENCE = (
    "The rule that flagged this line no longer matches the patched file, no other rule started "
    f"matching it, and nothing else in the file changed. {NOTHING_EXECUTED}"
)


@dataclass(frozen=True)
class StaticAssertionResult:
    """One patch's static assertion over one or more findings.

    `proven` is every finding whose five clauses all hold. `unproven` carries the rest with the
    clause each one failed, so a caller shows a reviewer why a finding was not claimed rather
    than dropping it silently. The evidence is one document for the whole patch, with a
    `findings` map holding each finding's clauses and match sets.
    """

    proven: list[str]
    unproven: list[dict[str, str]]
    evidence: dict[str, Any]
    reason_code: str | None = None
    message: str = ""

    @property
    def passed(self) -> bool:
        return bool(self.proven) and not self.unproven


def _finding_region(finding: FindingSnapshot) -> tuple[int, int]:
    start = max(1, int(finding.line_start or 1))
    end = max(start, int(finding.line_end or start))
    return start, end


def declared_regions(bundle: PatchBundle, path: str) -> list[tuple[int, int]]:
    """The line regions the patch declared it would change, on this path.

    Clause 3 allows the finding's own region plus whatever the template declares, and the
    template's declaration *is* its hunk list: a repair that has to add an `import` above the
    finding says so by carrying a hunk there. A bundle with no located hunks declares nothing,
    so such a candidate is held to its findings' regions alone.
    """
    return sorted((hunk.start_line, hunk.end_line) for hunk in bundle.hunks if hunk.path == path)


def changed_lines(original: str, patched: str) -> list[int]:
    """Every original-file line number the patch changed, plus the anchor of each insertion.

    Deletions and replacements name the lines they replace. A pure insertion replaces no line,
    so it is attributed to the line it was inserted before, which is the line a reviewer would
    say it touched and the line clause 3 has to be able to refuse.
    """
    # Imported here rather than at module scope: `patches` reaches this package's siblings, and a
    # top-level import would make that cycle real.
    from ..patches import _changed_ranges  # noqa: PLC0415

    original_lines = original.splitlines(keepends=True)
    lines: set[int] = set()
    for start, end, _replacement in _changed_ranges(original_lines, patched.splitlines(keepends=True)):
        if start == end:
            lines.add(min(start + 1, max(1, len(original_lines))))
            continue
        lines.update(range(start + 1, end + 1))
    return sorted(lines)


def _within(line: int, regions: list[tuple[int, int]]) -> bool:
    return any(start <= line <= end for start, end in regions)


def _clauses(
    matches_original: bool = False,
    gone_from_patch: bool = False,
    confined: bool = False,
    introduces_nothing: bool = False,
    nothing_executed: bool = True,
) -> dict[str, bool]:
    return dict(zip(CLAUSE_CODES, (matches_original, gone_from_patch, confined, introduces_nothing, nothing_executed)))


def _lines(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {int(item["line"]) for item in value if isinstance(item, dict) and isinstance(item.get("line"), int)}


def _rule_ids(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item["rule_id"]) for item in value if isinstance(item, dict) and item.get("rule_id")}


MATCH_SET_KEYS = ("rule_matches", "all_matches")


def _require_match_sets(side: dict[str, Any], which: str) -> None:
    """Both match sets on one side of the answer, present as lists, or no answer at all.

    `_lines` and `_rule_ids` read anything that is not a list as the empty set, which is right
    for a list with junk in it and wrong for a key that is not there: an answer with no
    `all_matches` would make clause 4 hold over a rule set nothing ever ran. Clause 4 is the one
    that stops a repair trading one vulnerability for another, so it is never decided from a key
    the oracle did not send.
    """
    missing = [key for key in MATCH_SET_KEYS if not isinstance(side.get(key), list)]
    if missing:
        raise RuleOracleError(
            ORACLE_RESPONSE_INVALID,
            f"the {which} side of the answer carries no " + " and no ".join(missing),
        )


def _unproven(finding_id: str, code: str, message: str) -> dict[str, str]:
    return {"finding_id": finding_id, "code": code, "message": message}


async def assert_statically(
    request: RepairRequest,
    snapshot: Snapshot,
    bundle: PatchBundle,
    findings: list[FindingSnapshot],
    oracle: RuleOracle,
    *,
    reason: str,
) -> StaticAssertionResult:
    """Decide the five clauses for a candidate patch over `findings`. Nothing is executed.

    `reason` is why this candidate is being asserted rather than executed. It goes into the
    evidence unchanged, so a reviewer reading a static assertion sees that the engine chose the
    weaker level for a stated cause and not by preference.

    Clause 3 is whole-patch and is decided first, from the patch alone: a patch that reached a
    file no finding names, or a line no finding's region and no declared hunk covers, is refused
    before a single rule is run. Clauses 1, 2 and 4 are then decided per finding, on that
    finding's own file, from the match sets the oracle returns.
    """
    patched_by_path = {patch.path: patch.replacement_content for patch in bundle.patches}
    paths = {finding.affected_path for finding in findings if finding.affected_path}
    evidence: dict[str, Any] = {
        "verification_level": STATIC_ASSERTION_VERIFICATION_LEVEL,
        "static_assertion_reason": reason,
        "changed_paths": sorted(patched_by_path),
        "finding_paths": sorted(paths),
        # Clause 5. Recorded before any clause is evaluated, because it is a property of the
        # whole procedure rather than an outcome of it.
        "executed": False,
        "nothing_executed": NOTHING_EXECUTED,
        "findings": {},
    }

    # Clause 3, part one: the patch reached no file a finding does not name.
    foreign = sorted(set(patched_by_path) - paths)
    if foreign:
        evidence["paths_outside_findings"] = foreign
        message = (
            "A static assertion covers only the files its findings name, and this patch also changes "
            + ", ".join(foreign[:5])
            + "."
        )
        for finding in findings:
            evidence["findings"][finding.stable_id] = {"clauses": _clauses(confined=False), "path": finding.affected_path}
        return StaticAssertionResult(
            [], [_unproven(finding.stable_id, REFUSAL_UNRELATED_FILE, message) for finding in findings],
            evidence, REFUSAL_UNRELATED_FILE, message,
        )

    # Clause 3, part two: within each file, only lines a finding's region or a declared hunk covers.
    by_path: dict[str, list[FindingSnapshot]] = {}
    for finding in findings:
        by_path.setdefault(finding.affected_path, []).append(finding)
    outside_by_path: dict[str, list[int]] = {}
    touched_by_path: dict[str, list[int]] = {}
    allowed_by_path: dict[str, list[tuple[int, int]]] = {}
    for path, content in sorted(patched_by_path.items()):
        original_content = snapshot.full_content(path)
        allowed = [_finding_region(item) for item in by_path.get(path, [])] + declared_regions(bundle, path)
        allowed_by_path[path] = allowed
        touched = changed_lines(original_content, content)
        touched_by_path[path] = touched
        outside = [line for line in touched if not _within(line, allowed)]
        if outside:
            outside_by_path[path] = outside
    evidence["changed_lines"] = dict(touched_by_path)
    evidence["allowed_regions"] = {
        path: [{"start_line": start, "end_line": end} for start, end in sorted(regions)]
        for path, regions in allowed_by_path.items()
    }
    if outside_by_path:
        evidence["lines_outside_allowed_regions"] = outside_by_path
        detail = "; ".join(
            f"{path} line " + ", ".join(str(line) for line in lines[:5]) for path, lines in sorted(outside_by_path.items())
        )
        message = (
            f"The patch changes {detail}, which is outside every finding's region and outside what the "
            "repair declared it would change."
        )
        for finding in findings:
            evidence["findings"][finding.stable_id] = {
                "clauses": _clauses(confined=finding.affected_path not in outside_by_path),
                "path": finding.affected_path,
            }
        return StaticAssertionResult(
            [], [_unproven(finding.stable_id, REFUSAL_UNRELATED_LINE, message) for finding in findings],
            evidence, REFUSAL_UNRELATED_LINE, message,
        )

    # Clauses 1, 2 and 4, per finding, on that finding's own file.
    proven: list[str] = []
    unproven: list[dict[str, str]] = []
    for finding in findings:
        record, verdict = await _assert_one(snapshot, bundle, finding, patched_by_path, oracle)
        evidence["findings"][finding.stable_id] = record
        if verdict is None:
            proven.append(finding.stable_id)
        else:
            unproven.append(verdict)

    evidence["digest"] = digest_json(
        {
            "findings": evidence["findings"],
            "changed_lines": evidence["changed_lines"],
            "changed_paths": evidence["changed_paths"],
            "executed": False,
            "policy_version": request.policy.policy_version,
            "artifact_digest": bundle.artifact_digest,
            "original_tree_digest": snapshot.tree_digest,
        }
    )
    if unproven:
        first = unproven[0]
        return StaticAssertionResult(proven, unproven, evidence, str(first["code"]), str(first["message"]))
    return StaticAssertionResult(proven, [], evidence, None, ASSERTION_SENTENCE)


async def _assert_one(
    snapshot: Snapshot,
    bundle: PatchBundle,
    finding: FindingSnapshot,
    patched_by_path: dict[str, str],
    oracle: RuleOracle,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    """Clauses 1, 2 and 4 for one finding, and its evidence record.

    Returns `(record, None)` when the finding is asserted and `(record, verdict)` otherwise.
    Clause 3 has already been decided for the whole patch by the caller, so it is recorded here
    as held.
    """
    finding_id = finding.stable_id
    path = finding.affected_path
    rule_id = str(finding.rule_id or "").strip()
    region = _finding_region(finding)
    record: dict[str, Any] = {
        "path": path,
        "rule_id": rule_id,
        "finding_region": {"start_line": region[0], "end_line": region[1]},
        "clauses": _clauses(confined=True),
    }
    if not rule_id:
        return record, _unproven(
            finding_id, REFUSAL_NO_RULE_ID,
            "The finding names no rule, so there is nothing to assert the patch against.",
        )
    patched_content = patched_by_path.get(path)
    if patched_content is None:
        # The candidate does not change this finding's file at all, so nothing about it was
        # asserted. `not_repaired` rather than a clause failure: no clause was reached.
        return record, _unproven(finding_id, NOT_REPAIRED, "The patch does not change this finding's file.")
    original_content = snapshot.full_content(path)

    document = await oracle.match_sets(rule_id, path, original_content, patched_content)
    refusal = document.get("refusal")
    if refusal:
        record["oracle_refusal"] = str(refusal)[:120]
        return record, _unproven(
            finding_id, REFUSAL_RULE_UNKNOWN,
            f"The rule that produced this finding could not be re-run over the file ({refusal}).",
        )
    original_side, patched_side = document.get("original"), document.get("patched")
    if not isinstance(original_side, dict) or not isinstance(patched_side, dict):
        # An answer with no match sets is not "the rule found nothing". It is no answer, and a
        # candidate is never passed on one.
        raise RuleOracleError(ORACLE_RESPONSE_INVALID, "the response carries no match sets")
    _require_match_sets(original_side, "original")
    _require_match_sets(patched_side, "patched")
    original_rule = _lines(original_side.get("rule_matches"))
    patched_rule = _lines(patched_side.get("rule_matches"))
    original_all = _rule_ids(original_side.get("all_matches"))
    patched_all = _rule_ids(patched_side.get("all_matches"))
    record["tier"] = document.get("tier")
    record["match_sets"] = {
        "original": {"rule": sorted(original_rule), "all": sorted(original_all)},
        "patched": {"rule": sorted(patched_rule), "all": sorted(patched_all)},
    }

    matches_finding_line = any(region[0] <= line <= region[1] for line in original_rule)
    gone_from_patch = not patched_rule
    introduced = sorted(patched_all - original_all)
    record["clauses"] = _clauses(matches_finding_line, gone_from_patch, True, not introduced)
    if introduced:
        record["rules_introduced_by_patch"] = introduced
    if not matches_finding_line:
        return record, _unproven(
            finding_id, REFUSAL_RULE_NOT_MATCHING_ORIGINAL,
            f"The rule that flagged this finding does not match the original file at line {region[0]}, "
            "so there is nothing for the patch to have removed.",
        )
    if not gone_from_patch:
        return record, _unproven(
            finding_id, REFUSAL_RULE_STILL_MATCHES,
            "The rule that flagged this finding still matches the patched file at line "
            + ", ".join(str(line) for line in sorted(patched_rule)[:5]) + ".",
        )
    if introduced:
        return record, _unproven(
            finding_id, REFUSAL_NEW_RULE_MATCH,
            "The patched file matches " + ", ".join(introduced[:5]) + ", which did not match the original file.",
        )
    return record, None

