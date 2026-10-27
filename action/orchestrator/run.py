"""The action's driver: one pull request, start to finish, inside the runner.

This is what the api-service does in production, minus everything that needs a database. There
is no queue, no run record, no finding table, no suppression list, no baseline and no outcome
metric. A run reads the pull request, scans it, tries to repair what it can, publishes, and
exits. Nothing it learns survives the job except the comments and the check it posted.

The order matters and mirrors production: list the changed files at a head that did not move,
fetch the content the scanner needs, scan, repair, publish, then decide the exit code.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import analysis, github_api, pr_scope, repo_config

CHECK_RUN_NAME = "Mitig8it Security Review"
FAIL_ON_CHOICES = ("none", "high", "critical")


def fix_publication_ready() -> bool:
    root = Path(os.environ.get("MITIG8IT_GITHUB_SERVICE_ROOT")
                or Path(__file__).resolve().parents[2] / "services/github-service")
    try:
        release = json.loads((root / "src/quality-release.json").read_text(encoding="utf-8"))
        expires = release.get("expires_at")
        expiry = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        provider, sandbox, service = release.get("provider") or {}, release.get("sandbox") or {}, release.get("service") or {}
        image = re.compile(r"[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[0-9a-f]{64}\Z")
        # This Action currently verifies repairs in a local subprocess and labels
        # them development_unverified. A production receipt requires the separate
        # independent sandbox, so the Action must keep fixes withheld even when
        # that receipt enables the deployed App. Detection review remains enabled.
        return (release.get("schema_version") == "v1" and release.get("remediation_release_verified") is True
                and re.fullmatch(r"[0-9a-f]{40}", str(release.get("source_revision") or "")) is not None
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(release.get("receipt_digest") or "")) is not None
                and expiry > datetime.now(timezone.utc)
                and provider.get("kind") == "live-provider" and bool(provider.get("model_id"))
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(provider.get("configuration_digest") or "")) is not None
                and sandbox.get("verification_level") == "development_unverified"
                and image.fullmatch(str(sandbox.get("image_digest") or "")) is not None
                and image.fullmatch(str(service.get("image_digest") or "")) is not None)
    except (OSError, ValueError, TypeError, AttributeError):
        return False

# A workflow that grants write access to file contents has handed the action the power to change
# the code it is reviewing. The action does not want it and will not run with it, because the
# claim that it cannot alter your repository has to be enforced rather than promised.
REFUSED_PERMISSION_MESSAGE = (
    "Mitig8it refuses to run with `contents: write`.\n"
    "\n"
    "This action reviews code and posts suggestions. It never commits, pushes or merges, and it\n"
    "is built so that it cannot: the only write permissions it asks for are `pull-requests` and\n"
    "`checks`. A workflow that grants `contents: write` gives it the ability to rewrite the\n"
    "branch it is reviewing, and that is a power you should not have to trust it not to use.\n"
    "\n"
    "Set the permissions block to exactly:\n"
    "\n"
    "    permissions:\n"
    "      contents: read\n"
    "      pull-requests: write\n"
    "      checks: write\n"
    "\n"
    "If another job in this workflow needs `contents: write`, give that job its own permissions\n"
    "block and leave the workflow default read-only."
)


class ActionError(Exception):
    """A condition the run cannot continue past, reported without a traceback.

    Like every other failure, it decides the exit code by `fail-on`: a run that could not finish
    exits 0 under `fail-on: none`, because adding the action must not turn a merge red for a
    reason that is ours.
    """

    # True for a refusal the workflow's author has to act on, which fails the job whatever
    # `fail-on` says. A refusal that exited 0 would read as a review that ran.
    always_fails = False


class RefusalError(ActionError):
    """The workflow asked for something the action will not do, or left out something it needs
    (a token, the event payload, the repository name): fix the workflow to proceed."""

    always_fails = True


class PublishError(ActionError):
    """The review or the check run could not be published."""


DEFAULT_MAX_FILES = 200
PUBLIC_API_URL = "https://api.github.com"


def enterprise_server_message(api_url: str) -> str:
    """Why the action stops on GitHub Enterprise Server rather than half-working there.

    The reads would go to the runner's API base, but the writes reuse github-service's
    publishing code, which addresses api.github.com directly. On GHES that sends the
    workflow token to the wrong host and every write fails, so the run stops first.
    """
    return (
        f"Mitig8it does not support GitHub Enterprise Server yet (GITHUB_API_URL is {api_url}). "
        "Its publishing code addresses api.github.com directly, so on this host it would send "
        "the workflow token to the wrong server. Nothing was read or posted."
    )


# --- what produced this review ---------------------------------------------------------------
#
# A bug report used to have to name a date. The trial's own defects were filed as "the review on
# the 24th said X", which is unanswerable once main has moved: nothing on the pull request said
# which code reviewed it. Every review now carries the version, in the check run summary and in
# one line of the review body, and the composition happens here so that one string reaches both.
#
# `action.yml` supplies the four variables. They are deliberately about what happened rather than
# what was intended: a released ref whose image pull failed reports `source`, because a review that
# came out of a local build must not claim to be the published image.

UNRELEASED_LABEL = "unreleased"


def version_identity(environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The version line a review carries, and the parts it was built from.

    `label` is what a user is asked to quote. It is `v1.0.0` on a released ref that ran the
    published image, and it says so plainly when it is anything else, because "v1.0.0" on a run
    that built its own image from a branch would send a bug report to the wrong code.
    """
    env = os.environ if environ is None else environ
    version = (env.get("MITIG8IT_ACTION_VERSION") or "").strip()
    digest = (env.get("MITIG8IT_ACTION_IMAGE_DIGEST") or "").strip()
    source = (env.get("MITIG8IT_ACTION_SOURCE") or "").strip().lower()
    ref = (env.get("MITIG8IT_ACTION_REF") or "").strip()

    if version and source == "registry":
        label = f"v{version}"
    elif version:
        label = f"v{version} (built from source, not the released image)"
    elif ref:
        label = f"{UNRELEASED_LABEL} ({ref}, built from source)"
    else:
        label = f"{UNRELEASED_LABEL} (local checkout, built from source)"

    return {
        "label": label,
        "version": version,
        "digest": digest,
        "source": source or "source",
        "ref": ref,
    }


def input_value(name: str, default: str = "") -> str:
    """Read an action input. GitHub passes them as INPUT_<NAME> with dashes as underscores."""
    key = f"INPUT_{name.replace('-', '_').upper()}"
    value = os.environ.get(key)
    return default if value is None or value == "" else value


def boolean_input(name: str, default: bool) -> bool:
    value = input_value(name, "true" if default else "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def log(message: str) -> None:
    print(message, flush=True)


def plural(count: int, noun: str) -> str:
    """`1 finding`, `2 findings`. The trial read "1 runtime findings" in the check summary."""
    return f"{count} {noun}{'' if count == 1 else 's'}"


def annotate(level: str, message: str) -> None:
    """A workflow annotation, so the message shows on the run summary and not only in the log."""
    single_line = message.replace("\n", "%0A")
    print(f"::{level}::{single_line}", flush=True)


def load_event() -> Dict[str, Any]:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not Path(path).is_file():
        raise RefusalError("GITHUB_EVENT_PATH is not set; this action runs on pull_request events")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, ValueError) as error:
        raise RefusalError(f"the event payload at GITHUB_EVENT_PATH could not be read: {error}") from error
    if not isinstance(event, dict):
        raise RefusalError("the event payload at GITHUB_EVENT_PATH is not a JSON object")
    return event


def pull_request_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        raise RefusalError(
            "This action only runs on pull_request events. Add "
            "`on: pull_request` to the workflow."
        )
    return pull


def assert_least_privilege(reader: github_api.GitHubReader) -> Dict[str, bool]:
    """Refuse to run when the workflow granted write access to file contents."""
    permissions = reader.repository_permissions()
    if permissions.get("push"):
        raise RefusalError(REFUSED_PERMISSION_MESSAGE)
    return permissions


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# The reason an unanchored finding carries when it sits on a line the pull request did not add,
# in a file whose patch is known. The action has no baseline, so this is how it tells code the
# author wrote from code they only touched the file around.
PRE_EXISTING = "pre_existing"


def is_pre_existing(finding: Dict[str, Any], patches_by_path: Dict[str, str]) -> bool:
    """True for a finding on a line the pull request did not add, in a file whose patch is known.

    Tier 2 scans the whole file and tier 1 reads context lines, so a one-line edit to a legacy
    file reports every old problem in it. Those are listed, not counted: a pull request must not
    be blocked by code its author did not write. A file with no patch (GitHub omits the patch of
    a very large diff) cannot be told apart, so its findings are counted, which is the side that
    cannot let a new file slip past `fail-on`.
    """
    path = str(finding.get("file_path") or "")
    line = int(finding.get("line_start") or 0)
    patch = patches_by_path.get(path) or ""
    if not path or line <= 0 or not patch:
        return False
    return line not in pr_scope.reviewable_lines(patch)


def counted_findings(
    findings: Sequence[Dict[str, Any]], patches_by_path: Dict[str, str]
) -> List[Dict[str, Any]]:
    """The findings `fail-on` and the blocking total count: everything not pre-existing."""
    return [finding for finding in findings if not is_pre_existing(finding, patches_by_path)]


def plan_comments(
    findings: Sequence[Dict[str, Any]],
    patches_by_path: Dict[str, str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Where every runtime finding goes: on the diff, or into the review body by name.

    A finding on a line the pull request did not change cannot have an inline comment. GitHub
    rejects it, and posting it against the nearest changed line would point the reader at code
    that is not the problem. What the action used to do with those findings was nothing: they
    stayed in the count and left the review. On nodejs-goof the trial saw six findings, five of
    them critical, a check that said "6 critical/high findings", and not one sentence anywhere
    naming a file or a line. Across ten repositories 28 of 93 findings existed only as a number.

    So they are returned here too, and the publisher lists them in the review body under their
    own heading, with a permalink each. A count a reader cannot act on is worse than no count:
    it says something is wrong and refuses to say what.

    An informational finding is still neither. It is a finding in test code, downgraded upstream,
    that cannot block the check and that the author is not being asked to fix. The self-review
    posted eighteen of them across `services/*/tests` and they buried the runtime findings the
    review existed to show. They are counted in the check summary and in the review body instead,
    which says they were not posted.
    """

    def rank(item: Dict[str, Any]) -> tuple:
        # No `info` key: an informational finding never reaches either list. An unknown severity
        # still sorts last rather than first, so a malformed finding cannot displace a critical.
        return (
            SEVERITY_ORDER.get(item["severity"], 5),
            item["path"],
            item["line"],
        )

    anchored: List[Dict[str, Any]] = []
    unanchored: List[Dict[str, Any]] = []
    for finding in findings:
        if analysis.is_informational(finding):
            continue
        path = str(finding.get("file_path") or "")
        line = int(finding.get("line_start") or 0)
        severity = str(finding.get("severity") or "").lower()
        if not path or line <= 0:
            continue
        patch = patches_by_path.get(path, "") or ""
        if line in pr_scope.reviewable_lines(patch):
            anchored.append(
                {
                    "path": path,
                    "line": line,
                    "body": render_finding_comment(finding),
                    "fingerprint": comment_fingerprint(finding),
                    "severity": severity,
                }
            )
            continue
        unanchored.append(
            {
                "path": path,
                "line": line,
                "severity": severity,
                "rule": str(finding.get("rule_id") or finding.get("title") or ""),
                "reason": PRE_EXISTING if patch else "line_outside_diff",
            }
        )

    anchored.sort(key=rank)
    # The cap is the app's. A finding past it is as invisible as one off the diff, so it is
    # reported the same way rather than dropped for a second, different reason nobody is told.
    over_cap = anchored[pr_scope.INLINE_COMMENT_CAP :]
    for comment in over_cap:
        unanchored.append(
            {
                "path": comment["path"],
                "line": comment["line"],
                "severity": comment["severity"],
                "rule": "",
                "reason": "over_inline_cap",
            }
        )
    unanchored.sort(key=rank)
    return {
        "comments": anchored[: pr_scope.INLINE_COMMENT_CAP],
        "unanchored": unanchored,
    }


def build_inline_comments(
    findings: Sequence[Dict[str, Any]],
    patches_by_path: Dict[str, str],
) -> List[Dict[str, Any]]:
    """The comments alone, for callers that do not care where the rest went."""
    return plan_comments(findings, patches_by_path)["comments"]


def review_totals(
    counts: Dict[str, int],
    comments: Sequence[Dict[str, Any]],
    unanchored: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """The one set of numbers the check title, the check summary and the review body all use.

    On pygoat the trial read four different numbers for one review: the check title said 32,
    the check summary said 37, the review body said 37 and there were 16 comments on the diff.
    Each was arithmetically explicable and no two agreed, so the reader had to reconstruct the
    arithmetic to trust any of them. They are computed once here and rendered three times.
    """
    runtime = sum(int(counts.get(key, 0)) for key in ("critical", "high", "medium", "low"))
    # Pre-existing findings stay in every total a reader sees and leave the blocking one, which
    # is the number `fail-on` acts on.
    pre_existing = [item for item in unanchored if item.get("reason") == PRE_EXISTING]
    pre_existing_blocking = sum(
        1 for item in pre_existing if str(item.get("severity") or "") in ("critical", "high")
    )
    return {
        "runtime": runtime,
        "critical": int(counts.get("critical", 0)),
        "high": int(counts.get("high", 0)),
        "medium": int(counts.get("medium", 0)),
        "low": int(counts.get("low", 0)),
        "informational": int(counts.get("info", 0)),
        "blocking": max(
            0, int(counts.get("critical", 0)) + int(counts.get("high", 0)) - pre_existing_blocking
        ),
        "inline": len(comments),
        "unanchored": len(unanchored),
        "preexisting": len(pre_existing),
    }


def active_fingerprints(findings: Sequence[Dict[str, Any]]) -> List[str]:
    """The findings whose threads this run wants kept open.

    Every runtime finding the run reported, anchored or not: one that exists but had nowhere to
    comment must not have its thread resolved as though it had gone away.

    Informational findings are deliberately absent. The action no longer posts them inline, so a
    thread that an earlier version opened for one is now stale by definition and the same
    reconciliation that closes a fixed finding closes it too. That is the only thing that retires
    the eighteen test-code threads already sitting open on the self-review.
    """
    return [
        comment_fingerprint(finding)
        for finding in findings
        if not analysis.is_informational(finding)
    ]


def thread_summary_line(threads: Optional[Dict[str, Any]]) -> str:
    """What the reconciliation did, in one line, on every run.

    The resolver matched nothing for weeks and nobody could tell, because it logged only when it
    acted: a run that resolved zero threads read exactly like a run with nothing to resolve. So
    the line is unconditional and states the denominator too. `seen` is every review thread on
    the pull request and `ours` is how many carried our marker; the two being far apart is the
    symptom that a matching bug produces, and it is now visible in the log.

    `minimized` is gone and `retired` and `kept` are in its place. A minimized thread is still an
    unresolved conversation, so the trial's fixed finding left the pull request blocked; the
    action deletes its own stale comment now instead, and keeps the one carrying a published fix.

    `marked fixed` is the comment of a fix that was applied: the finding has gone and the
    comment, kept, now says so instead of still offering the suggestion. `kept` is one that was
    already in that form, or one the publisher could not rewrite and left as it was.
    """
    if not isinstance(threads, dict):
        return "Review threads: the publisher reported no reconciliation."
    numbers = {
        key: int(threads.get(key) or 0)
        for key in ("seen", "ours", "resolved", "retired", "applied", "kept", "failed")
    }
    line = (
        f"Review threads: {numbers['seen']} seen, {numbers['ours']} with our marker, "
        f"{numbers['resolved']} resolved, {numbers['retired']} retired, "
        f"{numbers['applied']} marked fixed, {numbers['kept']} kept for a published fix, "
        f"{numbers['failed']} failed."
    )
    unavailable = str(threads.get("unavailable") or "")
    if unavailable:
        return f"{line} The GraphQL API could not be reached: {unavailable}"
    errors = [str(error) for error in (threads.get("errors") or []) if str(error)]
    if errors:
        return f"{line} First failure: {errors[0]}"
    return line


def comment_fingerprint(finding: Dict[str, Any]) -> str:
    """The fingerprint the marker carries, which is never empty.

    github-service matches its own comment with `/<!-- mitig8it-finding:[^>]+ -->/`. A finding
    with no fingerprint rendered `<!-- mitig8it-finding: -->`, which that pattern does not match,
    so the marker branch was skipped and a second comment was created on every single run. A
    derived identity is worse than the scanner's, because it moves when the rule or the line
    moves, but it is stable across two runs over the same tree, which is what idempotency needs.
    """
    supplied = str(finding.get("fingerprint") or "").strip()
    if supplied:
        return supplied
    seed = "|".join(
        str(finding.get(key) or "")
        for key in ("rule_id", "file_path", "line_start", "title")
    )
    return f"derived-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:32]}"


def render_finding_comment(finding: Dict[str, Any]) -> str:
    """The body of one inline finding comment, marker first.

    The marker is what makes a re-run idempotent: the publishing code finds its own previous
    comment by this string and edits it rather than posting a second one.
    """
    fingerprint = comment_fingerprint(finding)
    severity = str(finding.get("severity") or "unknown").lower()
    title = str(finding.get("title") or finding.get("rule_id") or "Security finding")
    # Test-code findings are downgraded to `info` by the analysis service, which the action calls
    # in process, so the action already inherits the policy: they never count towards the check
    # conclusion and never reach fix generation.
    #
    # `build_inline_comments` no longer sends one of these to be rendered, so the branch below is
    # not reached from the publishing path today. It is kept because it is the wording the App
    # puts on the same finding, and because a renderer that silently mislabelled an informational
    # finding as blocking would be a worse thing to leave behind than an unused branch.
    informational = analysis.is_informational(finding)
    scanner_severity = str(
        finding.get("original_severity")
        or ((finding.get("evidence_details") or {}).get("extra") or {}).get("original_severity")
        or ""
    ).lower()
    lines = [
        f"<!-- mitig8it-finding:{fingerprint} -->",
        f"**INFORMATIONAL - TEST CODE** - {title}" if informational else f"**{title}**",
        "",
        f"Severity: {severity}",
    ]
    if informational:
        lines.append(
            f"In test code{f'; scanner severity {scanner_severity}' if scanner_severity else ''}. "
            "Informational only, it does not block this pull request."
        )
    cwe = str(finding.get("cwe_id") or "")
    if cwe:
        lines.append(f"Weakness: {cwe}")
    # The OpenGrep rules set title, description and remediation to the rule's own message, so
    # two thirds of the trial's comments said one sentence three times: 40 of 65. The whole body
    # of `views/admin.ejs:17` was "EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so
    # the value is escaped" in bold, again as prose, and a third time after "Remediation:". A
    # field that only repeats what the reader has already read is dropped.
    description = str(finding.get("description") or "")
    if description and not _same_sentence(description, title):
        lines.extend(["", description])
    else:
        description = ""
    evidence = str(finding.get("evidence") or "")
    if evidence:
        lines.extend(["", evidence])
    remediation = str(finding.get("remediation") or "")
    # The description is compared against the title and dropped when it repeats it, which left
    # `description` empty and made the old check here vacuous: a remediation identical to the
    # title survived on 40 of the trial's 65 comments. A field is dropped when it repeats
    # anything the reader has already been shown, which is the title or a description that
    # survived it.
    already_said = [title] + ([description] if description else [])
    if remediation and not any(_same_sentence(remediation, said) for said in already_said):
        lines.extend(["", f"Remediation: {remediation}"])
    return "\n".join(lines)


def _same_sentence(left: str, right: str) -> bool:
    """Two fields saying the same thing, allowing for spacing and a trailing stop."""
    def normalise(value: str) -> str:
        return " ".join(str(value or "").split()).rstrip(".").casefold()

    return bool(normalise(left)) and normalise(left) == normalise(right)


def fail_conclusion(fail_on: str, counts: Dict[str, int]) -> str:
    """The check run conclusion, which is also what decides the job's exit code.

    All 26 runs of the trial concluded `neutral`, including the five that found nothing at all,
    so a repository with a clean review and a repository with 22 critical findings both showed
    the same grey check and only the title told them apart. `neutral` is what a review held back
    by `fail-on: none` deserves; it is not what an empty review deserves. So: `failure` when the
    repository's own threshold is met, `neutral` when there is something to report and the
    repository asked not to be blocked by it, and `success` otherwise.
    """
    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    runtime = sum(int(counts.get(key, 0)) for key in ("critical", "high", "medium", "low"))
    if fail_on == "critical" and critical > 0:
        return "failure"
    if fail_on == "high" and (critical + high) > 0:
        return "failure"
    if fail_on == "none" and runtime > 0:
        return "neutral"
    return "success"


# --- the publish envelope --------------------------------------------------------------------

# github-service validates every envelope that carries fixes, and `manifest_digest` has to be a
# bare 64-character SHA-256 in hex: `validateActionEnvelope` in
# services/github-service/src/services/githubInternalOperations.js takes it through
# `requireString(..., 64)` and then `/^[0-9a-f]{64}$/i`. No `sha256:` prefix survives that, and
# neither does a 40-character Git object ID, which is what the action used to send: a run with
# fixes died at `publishing failed: publish error: fixes: manifest_digest must be a SHA-256
# digest`, after the review and the check had already been posted.
def section_artifact_digest(section: Dict[str, Any]) -> str:
    """One published section's content, as a digest. The manifest binds these, not the prose."""
    body = json.dumps(
        {"path": str(section.get("path") or ""), "unified_diff": str(section.get("unified_diff") or "")},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def manifest_digest(action_id: str, head_sha: str, base_sha: str, sections: Sequence[Dict[str, Any]]) -> str:
    """The envelope's digest, computed the way the app computes it.

    `manifestDigestFor` in services/api-service/src/db/remediation.js builds
    `{job, head, base, candidates: [{id, artifact_digest}]}` and hands it to `hash`, which is
    `crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex')`. `JSON.stringify`
    emits keys in insertion order with no whitespace, so the manifest is assembled here in that
    same order and dumped with the same separators. `sort_keys=True` would hash a different
    string for the same manifest and quietly stop being the app's function.

    The action has no job row, so `action_id` names the run the app would name by job id, and
    the candidates are the ordered sections this publish carries. The digest therefore binds the
    exact ordered set of fixes: reorder them, or change one diff, and it changes.

    A run with no fixes still gets a well-formed digest. github-service only validates the
    envelope when sections are sent, but a payload that could not be validated is not one worth
    building, and the app's own fallback does the same thing rather than sending nothing.
    """
    manifest = {
        "job": action_id,
        "head": head_sha,
        "base": base_sha,
        "candidates": [
            {"id": str(section.get("candidate_id") or ""), "artifact_digest": section_artifact_digest(section)}
            for section in sections
        ],
    }
    body = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


LIMITATION_ANNOTATION_HEADING = "Not fully analysed"


def normalize_limitation(limitation: Dict[str, Any]) -> Dict[str, str]:
    """One limitation in the three fields every surface renders: what kind, where, and why."""
    return {
        "kind": str(limitation.get("kind") or ""),
        "path": str(limitation.get("path") or ""),
        "message": str(limitation.get("message") or "").strip(),
    }


def limitation_line(limitation: Dict[str, str]) -> str:
    path = limitation.get("path") or ""
    message = limitation.get("message") or limitation.get("kind") or "not analysed"
    return f"{path}: {message}" if path else message


def fix_count(sections: Sequence[Dict[str, Any]]) -> int:
    """Sections that carry a fix. One without a candidate is a `No automatic fix` line."""
    return sum(1 for section in sections if section.get("candidate_id"))


def build_publish_request(
    *,
    token: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    installation_id: int,
    actor_login: str,
    counts: Dict[str, int],
    findings: int,
    fix_sections: Sequence[Dict[str, Any]],
    inline_comments: Sequence[Dict[str, Any]],
    model_configured: bool,
    conclusion: str,
    unanchored_findings: Sequence[Dict[str, Any]] = (),
    scope: Optional[Dict[str, Any]] = None,
    excluded_files: int = 0,
    active_fingerprints: Sequence[str] = (),
    bot_login: str = "github-actions[bot]",
    action_id: Optional[str] = None,
    version_label: Optional[str] = None,
    limitations: Sequence[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Everything the Node publisher needs, in one place the tests can build without a network."""
    action_id = action_id or f"action-{uuid.uuid4().hex[:16]}"
    base_sha = base_sha or head_sha
    return {
        "token": token,
        "repository_full_name": repository,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "installation_id": installation_id,
        "actor_login": actor_login,
        "bot_login": bot_login,
        "action_id": action_id,
        "idempotency_key": f"{repository}:{pr_number}:{head_sha}",
        "manifest_digest": manifest_digest(
            action_id, head_sha, base_sha, [section for section in fix_sections if section.get("candidate_id")]
        ),
        "counts": counts,
        "findings": findings,
        "fixes": fix_count(fix_sections),
        "modelConfigured": model_configured,
        # One string, composed once here, rendered by the publisher in two places. The publisher
        # derives nothing of its own from it, the same rule `counts` follows, so a check summary
        # and a review body can never name two different versions of the same run.
        "versionLabel": version_label or version_identity()["label"],
        "failConclusion": conclusion,
        "excludedFiles": int(excluded_files),
        # What the review looked at, split into analysed, excluded and skipped. The check
        # summary states all three, because a reader who sees no finding on a directory is
        # entitled to know whether it was clean, excluded or never read whole.
        "scope": dict(scope or {}),
        # One arithmetic, computed once, rendered by the publisher in three places. The
        # publisher derives nothing of its own from `counts`.
        "totals": review_totals(counts, inline_comments, unanchored_findings),
        # Every finding that could not be anchored, so the review body can name it rather
        # than leave the reader with a count and no location.
        "unanchored_findings": list(unanchored_findings),
        # Every finding this run reported, not only the ones that could be anchored to a changed
        # line. A finding that exists but has nowhere to comment must not have its thread
        # resolved as though it had gone away.
        "active_fingerprints": sorted(set(active_fingerprints)),
        "inline_comments": list(inline_comments),
        "fix_sections": list(fix_sections),
        # What the review could not read in full. The check summary and the review body list
        # them under "Not fully analysed", because a partial review must never read as a
        # complete, clean one.
        "limitations": [normalize_limitation(item) for item in limitations],
    }


def limitations_markdown(limitations: Sequence[Dict[str, str]]) -> str:
    """The job summary's "Not fully analysed" list, or "" when the review was complete."""
    if not limitations:
        return ""
    rows = [f"- {limitation_line(item)}" for item in limitations[:50]]
    if len(limitations) > 50:
        rows.append(f"- and {len(limitations) - 50} more")
    return f"#### {LIMITATION_ANNOTATION_HEADING}\n\n" + "\n".join(rows) + "\n\n"


READ_ONLY_REASON = (
    "GitHub gives fork and Dependabot pull requests a read-only token, so nothing could be posted"
)
READ_ONLY_ANNOTATION_CAP = 50


def fork_reason(pull: Dict[str, Any], repository: str) -> str:
    """Why this run's token is read-only, or "" when nothing says so before the first write.

    A pull request whose head lives in another repository is a fork's, and a workflow run on it
    gets a read-only token. A head repository that is missing altogether is a fork that was
    deleted. Same-repository pull requests carry no such signal in the event.
    """
    head_repo = (pull.get("head") or {}).get("repo")
    base_repo = (pull.get("base") or {}).get("repo") or {}
    base_name = str(base_repo.get("full_name") or repository or "")
    head_name = str((head_repo or {}).get("full_name") or "")
    if head_repo is None or (head_name and base_name and head_name.lower() != base_name.lower()):
        return f"This pull request comes from a fork. {READ_ONLY_REASON}."
    return ""


def _annotation_property(value: Any) -> str:
    return (
        str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        .replace(":", "%3A").replace(",", "%2C")
    )


def report_read_only(reason: str, report: Dict[str, Any]) -> int:
    """A review that could not be posted, reported where a read-only token can still write.

    The job summary carries the findings, the counts and the reason, and each runtime finding
    becomes a workflow annotation on its file and line. The exit code is the one `fail-on`
    would have given, worked out from the same counts.
    """
    counts = report["counts"]
    counted = report["counted"]
    plan = report["plan"]
    entries = [
        {**comment, "counted": True} for comment in plan["comments"]
    ] + [
        {**item, "counted": item.get("reason") != PRE_EXISTING} for item in plan["unanchored"]
    ]
    titles = {
        (str(f.get("file_path") or ""), int(f.get("line_start") or 0)):
            str(f.get("title") or f.get("rule_id") or "Security finding")
        for f in report["findings"]
    }
    annotate("warning", reason)
    for entry in entries[:READ_ONLY_ANNOTATION_CAP]:
        title = titles.get((entry["path"], entry["line"]), "Security finding")
        note = "" if entry["counted"] else " (pre-existing in a touched file, not counted)"
        print(
            f"::warning file={_annotation_property(entry['path'])},line={entry['line']},"
            f"title={_annotation_property('Mitig8it ' + str(entry['severity']))}::"
            + f"{title}{note}".replace("%", "%25").replace("\n", "%0A"),
            flush=True,
        )

    rows = []
    for entry in entries[:READ_ONLY_ANNOTATION_CAP]:
        title = titles.get((entry["path"], entry["line"]), "Security finding").replace("|", "/")
        counted_label = "yes" if entry["counted"] else "pre-existing, not counted"
        rows.append(f"| {entry['severity']} | {title} | `{entry['path']}:{entry['line']}` | {counted_label} |")
    table = (
        "| Severity | Finding | Location | Counted |\n| --- | --- | --- | --- |\n" + "\n".join(rows) + "\n\n"
        if rows else ""
    )
    if len(entries) > READ_ONLY_ANNOTATION_CAP:
        table += f"{plural(len(entries) - READ_ONLY_ANNOTATION_CAP, 'further finding')} not listed.\n\n"
    write_summary(
        f"### {CHECK_RUN_NAME}\n\n{reason}\n\n"
        f"{plural(len(report['findings']), 'finding')}: {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
        f"{counts['info']} informational. Counted towards fail-on: {counted['critical']} critical, "
        f"{counted['high']} high.\n\n"
        + table
        + limitations_markdown(report["limitations"])
    )
    write_outputs(
        {
            "findings": len(report["findings"]),
            "critical": counted["critical"],
            "high": counted["high"],
            "fixes": 0,
            "conclusion": report["conclusion"],
            "excluded": report["excluded"],
        }
    )
    if report["conclusion"] == "failure":
        annotate(
            "error",
            f"Mitig8it: {counted['critical']} critical and {counted['high']} high findings on "
            f"lines this pull request added exceed fail-on: {report['fail_on']}.",
        )
        return 1
    return 0


def write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def write_outputs(values: Dict[str, Any]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def run_publisher(request: Dict[str, Any]) -> Dict[str, Any]:
    """Hand the publish request to the Node publisher and return what it reports."""
    publisher = os.environ.get("MITIG8IT_PUBLISHER") or str(
        Path(__file__).resolve().parents[1] / "publisher/publish.js"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(request, handle)
        request_path = handle.name
    try:
        completed = subprocess.run(
            ["node", publisher, request_path],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    finally:
        os.unlink(request_path)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    try:
        results = json.loads(completed.stdout) if (completed.stdout or "").strip() else None
    except json.JSONDecodeError:
        results = None
    if not isinstance(results, dict):
        if completed.returncode != 0:
            # The publisher died before it could say what it did, so nothing is known to have
            # been posted.
            raise PublishError(
                f"publishing failed: {completed.stderr.strip()[-2000:] or 'unknown error'}"
            )
        return {}
    # A nonzero exit with a report is a publish that ran and lost something. The report says
    # what, and the caller decides which of those losses fail the run.
    return results


def requested_fail_on() -> str:
    return input_value("fail-on", "none").strip().lower()


def max_files_input() -> int:
    """The `max-files` input, or the default with a warning when it is not a number.

    `int("two hundred")` used to end the run with a traceback before anything was read.
    """
    raw = input_value("max-files", str(DEFAULT_MAX_FILES))
    try:
        return max(1, int(raw.strip()))
    except (TypeError, ValueError):
        annotate(
            "warning",
            f"max-files must be a whole number, got {raw!r}; using {DEFAULT_MAX_FILES}.",
        )
        return DEFAULT_MAX_FILES


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv
    context: Dict[str, Any] = {}
    try:
        return _run(context)
    except Exception as error:  # noqa: BLE001 - every failure gets the same defined outcome
        return report_failure(error, context)


def report_failure(error: BaseException, context: Dict[str, Any]) -> int:
    """What a run that could not finish does instead of a traceback.

    An error annotation says what went wrong. A neutral check run says the commit was not
    reviewed, when the token and the host allow one, so the pull request never shows a clean
    result it did not earn. The exit code follows `fail-on`: 0 under `none`, because the
    repository asked never to be blocked, and 1 otherwise, because a repository that asked to be
    blocked on findings should not pass a commit nobody reviewed. A refusal the workflow author
    has to fix fails either way.
    """
    known = isinstance(error, ActionError)
    message = str(error) if known else f"{type(error).__name__}: {error}"
    annotate("error", message if known else f"Mitig8it did not complete: {message}")
    if not known:
        import traceback  # noqa: PLC0415

        print("::group::Traceback", flush=True)
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stdout)
        print("::endgroup::", flush=True)

    target = context.get("check_target")
    if target and not getattr(error, "always_fails", False):
        try:
            outcome = run_publisher(
                {
                    **target,
                    "mode": "error_check",
                    "error_class": type(error).__name__,
                    "error_message": message[:1000],
                }
            )
            for problem in outcome.get("errors") or []:
                annotate("warning", f"the neutral check run could not be posted: {problem}")
        except Exception as check_error:  # noqa: BLE001 - reporting must not fail the report
            annotate("warning", f"the neutral check run could not be posted: {check_error}")

    write_summary(
        f"### {CHECK_RUN_NAME}\n\nThe review did not complete: {message}\n\n"
        "No result is reported for this commit, and it is not a clean review.\n"
    )
    if getattr(error, "always_fails", False):
        return 1
    fail_on = context.get("fail_on") or requested_fail_on()
    return 0 if fail_on == "none" else 1


def _run(context: Optional[Dict[str, Any]] = None) -> int:
    context = {} if context is None else context
    # First line of every log, so a run that fails before it publishes still says what it was.
    identity = version_identity()
    log(f"Mitig8it {identity['label']}.")
    if identity["digest"]:
        log(f"Image {identity['digest']}.")

    token = input_value("github-token") or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RefusalError("no github-token was provided")

    fail_on = requested_fail_on()
    if fail_on not in FAIL_ON_CHOICES:
        raise RefusalError(f"fail-on must be one of {', '.join(FAIL_ON_CHOICES)}")
    context["fail_on"] = fail_on
    post_fixes = boolean_input("post-fixes", True)
    max_files = max_files_input()

    model_key = input_value("model-api-key")
    model_configured = bool(model_key)
    if not model_configured:
        # Belt and braces: the analysis service treats triage as on by default, so the action
        # turns it off rather than relying on the absence of a key.
        os.environ["LLM_TRIAGE_ENABLED"] = "false"

    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if repository.count("/") != 1 or not all(repository.split("/")):
        raise RefusalError(
            f"GITHUB_REPOSITORY must be owner/name, got {repository!r}; run the action from a "
            "GitHub Actions workflow, which sets it"
        )
    api_url = os.environ.get("GITHUB_API_URL") or PUBLIC_API_URL
    if api_url.rstrip("/") != PUBLIC_API_URL:
        # Checked before the first request, so the token never reaches a host it was not
        # issued for.
        raise ActionError(enterprise_server_message(api_url))
    event = load_event()
    pull = pull_request_from_event(event)
    try:
        pr_number = int(pull.get("number") or 0)
    except (TypeError, ValueError):
        pr_number = 0
    head_sha = str((pull.get("head") or {}).get("sha") or "")
    base_sha = str((pull.get("base") or {}).get("sha") or "")
    if not pr_number or not head_sha:
        raise RefusalError("the event payload carried no pull request number or head sha")

    reader = github_api.GitHubReader(token=token, repository=repository, api_url=api_url)
    installation_id = int(((event.get("repository") or {}).get("id")) or 1)
    # A pull request from a fork runs with a read-only token, so the review is reported into
    # the job summary and nothing is attempted on the pull request. Dependabot's come from the
    # same repository and are recognised by the 403 on the first write instead.
    read_only = fork_reason(pull, repository)
    if read_only:
        log(read_only)
    else:
        # From here on a failure can say so on the pull request with a neutral check run.
        context["check_target"] = {
            "token": token,
            "repository_full_name": repository,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "installation_id": installation_id,
            "bot_login": "github-actions[bot]",
            "versionLabel": identity["label"],
        }

    log("Checking that the workflow granted no more permission than the review needs.")
    assert_least_privilege(reader)

    # Read before anything is fetched or scanned: an excluded path never becomes a finding
    # because it never becomes an analysis input.
    exclusions, config_problem = repo_config.load(Path(os.environ.get("GITHUB_WORKSPACE") or "."))
    if config_problem:
        annotate("warning", config_problem)

    log(f"Reading the changed files on #{pr_number} at {head_sha[:8]}.")
    raw_files = reader.list_pull_request_files(pr_number, head_sha)
    scoped = pr_scope.scope_changed_files(raw_files, exclusions)
    excluded_files = pr_scope.excluded_file_count(raw_files, exclusions)
    if excluded_files:
        log(repo_config.exclusion_summary(excluded_files) + ".")
    limitations: List[Dict[str, Any]] = []
    cap_limitation = pr_scope.changed_file_limitation(raw_files, exclusions)
    if cap_limitation:
        limitations.append(cap_limitation)
        log(cap_limitation["message"] + "; the rest of the change was not reviewed.")
    if len(scoped) > max_files:
        raise ActionError(
            f"this pull request changes {len(scoped)} files, above the max-files input of "
            f"{max_files}. Raise the input or split the change."
        )
    scope = pr_scope.scope_report(raw_files, exclusions)
    log(pr_scope.scope_summary(scope) or "Nothing in this pull request is reviewable.")

    wanted = [f["path"] for f in scoped if pr_scope.should_fetch_full_file_content(f)]
    contents: Dict[str, str] = {}
    if wanted:
        contents, content_limitations = reader.file_contents_with_limitations(wanted, head_sha)
        # A file too large to read whole is still reviewed through its patch, and is named
        # under "Not fully analysed" so the review never claims more than it read.
        limitations.extend(content_limitations)
        for item in content_limitations:
            log(f"{item['path']}: {item['message']}.")
    accounted = {str(item.get("path") or "") for item in limitations}
    missing = [path for path in wanted if path not in contents and path not in accounted]
    if missing:
        # A file that is absent for no stated reason is still fatal: a scan that silently
        # skipped it would report a clean result it did not earn.
        raise ActionError(
            "Required source content response is incomplete; these files could not be read at "
            "the head commit: " + ", ".join(missing[:10])
        )

    analysis_files = pr_scope.build_analysis_files(scoped, contents)
    log("Scanning.")
    findings, analysis_limitations = analysis.analyze(
        repository, pr_number, head_sha, analysis_files
    )
    limitations.extend(analysis_limitations)
    if limitations:
        annotate(
            "warning",
            f"{LIMITATION_ANNOTATION_HEADING}: "
            + "; ".join(limitation_line(normalize_limitation(item)) for item in limitations[:10])
            + (f"; and {len(limitations) - 10} more" if len(limitations) > 10 else ""),
        )
    counts = analysis.severity_counts(findings)
    log(
        f"{plural(len(findings), 'finding')}: {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
        f"{counts['info']} informational."
    )

    fix_sections: List[Dict[str, Any]] = []
    fixes_withheld = post_fixes and bool(findings) and not fix_publication_ready()
    if fixes_withheld:
        log("Fix publication withheld: independent release evidence is missing.")
    if post_fixes and findings and not fixes_withheld and not read_only:
        fix_sections = generate_fixes(
            reader=reader,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            findings=findings,
            contents=contents,
            model_configured=model_configured,
        )
        log(f"{plural(fix_count(fix_sections), 'fix suggestion')} produced.")

    patches_by_path = {f["path"]: f.get("patch") or "" for f in scoped}
    plan = plan_comments(findings, patches_by_path)
    inline_comments = plan["comments"]
    unanchored = plan["unanchored"]
    if unanchored:
        log(
            f"{plural(len(unanchored), 'finding')} on lines this pull request did not change; "
            "they are listed in the review body rather than on the diff."
        )

    # Every finding is reported; only the ones on lines this pull request added are counted.
    counted_counts = analysis.severity_counts(counted_findings(findings, patches_by_path))
    pre_existing_total = sum(1 for item in unanchored if item.get("reason") == PRE_EXISTING)
    if pre_existing_total:
        log(
            f"{plural(pre_existing_total, 'finding')} pre-existing in a touched file, not "
            "counted towards fail-on."
        )
    conclusion = fail_conclusion(fail_on, counts) if fail_on == "none" else fail_conclusion(
        fail_on, counted_counts
    )
    request = build_publish_request(
        token=token,
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha or head_sha,
        installation_id=installation_id,
        actor_login=os.environ.get("GITHUB_ACTOR", "github-actions") or "github-actions",
        counts=counts,
        findings=len(findings),
        fix_sections=fix_sections,
        inline_comments=inline_comments,
        model_configured=model_configured,
        conclusion=conclusion,
        unanchored_findings=unanchored,
        scope=scope,
        excluded_files=excluded_files,
        active_fingerprints=active_fingerprints(findings),
        # Asked of the token rather than assumed. `github-actions[bot]` is right only for the
        # default workflow token; a repository that passes an App installation token or a PAT
        # posts under a different login, and github-service recognises its own comment by that
        # login. Assuming it meant every re-run created a second comment instead of editing.
        bot_login=reader.viewer_login(),
        version_label=identity["label"],
        limitations=limitations,
    )

    read_only_report = {
        "findings": findings,
        "counts": counts,
        "counted": counted_counts,
        "plan": plan,
        "limitations": request["limitations"],
        "conclusion": conclusion,
        "fail_on": fail_on,
        "excluded": excluded_files,
    }
    if read_only:
        return report_read_only(read_only, read_only_report)

    log("Publishing.")
    if fixes_withheld:
        request["fixesWithheldReason"] = "independent_release_evidence_missing"
    results = run_publisher(request)
    if results.get("read_only"):
        return report_read_only(
            f"{READ_ONLY_REASON} ({results['read_only']}).", read_only_report
        )
    if results.get("check_read_only"):
        annotate(
            "warning",
            "The review was posted but the check run was not: the token may not create check "
            "runs. Grant `checks: write` to the job. " + str(results["check_read_only"]),
        )
    # One inline edit or the fix sections failing costs the reader a comment, not the review,
    # so it is a warning. The review or the check failing is a publish that did not happen.
    for warning in results.get("warnings") or []:
        annotate("warning", f"publish: {warning}")
    publish_errors = [str(error) for error in results.get("errors") or []]

    # Exactly one line about the threads, whatever happened, and a warning rather than a log line
    # when some of them could not be closed. Never more than one: a token that may not resolve
    # cannot resolve any of them, and ninety identical annotations would say nothing extra.
    threads = results.get("threads")
    summary_line = thread_summary_line(threads)
    if isinstance(threads, dict) and (int(threads.get("failed") or 0) > 0 or threads.get("unavailable")):
        annotate("warning", summary_line)
    else:
        log(summary_line)

    write_outputs(
        {
            "findings": len(findings),
            "critical": counted_counts["critical"],
            "high": counted_counts["high"],
            "fixes": fix_count(fix_sections),
            "conclusion": conclusion,
            "excluded": excluded_files,
        }
    )
    exclusion_line = repo_config.exclusion_summary(excluded_files)
    write_summary(
        f"### {CHECK_RUN_NAME}\n\n"
        f"{plural(len(findings), 'finding')}, {counts['critical']} critical, "
        f"{counts['high']} high, {plural(fix_count(fix_sections), 'fix suggestion')}.\n\n"
        + (f"{exclusion_line}.\n\n" if exclusion_line else "")
        + limitations_markdown(request["limitations"])
        + (
            "Fix suggestions were withheld because independent release evidence is missing.\n"
            if fixes_withheld else (
                "Fixes were generated with model assistance.\n"
                if model_configured
                else "No model key was configured, so only template fixes were produced and "
                "nothing left this runner.\n"
            )
        )
        # The job summary is where a maintainer looks when a run went wrong, so it carries the
        # digest as well as the label. The review body carries only the label, because a
        # sixty-four character hex string in a pull request comment is noise.
        + f"\nMitig8it {identity['label']}."
        + (f" Image `{identity['digest']}`.\n" if identity["digest"] else "\n")
    )

    if publish_errors:
        raise PublishError("publishing failed: " + "; ".join(publish_errors))

    if conclusion == "failure":
        annotate(
            "error",
            f"Mitig8it: {counted_counts['critical']} critical and {counted_counts['high']} high "
            f"findings on lines this pull request added exceed fail-on: {fail_on}.",
        )
        return 1
    return 0


def generate_fixes(
    *,
    reader: github_api.GitHubReader,
    repository: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    findings: Sequence[Dict[str, Any]],
    contents: Dict[str, str],
    model_configured: bool,
) -> List[Dict[str, Any]]:
    """A fix section for every finding a repair was verified for, and a reason for every other.

    Imported lazily so that a run which produced no findings never pays for loading the repair
    engine, and so a repository with no repairable finding still publishes its review when the
    engine cannot start. Every reported finding without a fix gets a `No automatic fix` line,
    the way the App's comment does: a finding with neither is a promise the review broke.
    """
    from . import remediation  # noqa: PLC0415

    sections, skipped, fallback = _repair_sections(
        remediation,
        reader=reader,
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        findings=findings,
        contents=contents,
        model_configured=model_configured,
    )
    return sections + remediation.no_fix_sections(findings, sections, skipped=skipped, fallback=fallback)


def _repair_sections(
    remediation,
    *,
    reader: github_api.GitHubReader,
    repository: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    findings: Sequence[Dict[str, Any]],
    contents: Dict[str, str],
    model_configured: bool,
):
    """`(fix sections, the engine's skipped list, the run's reason for anything else)`."""
    try:
        repairable = [
            finding
            for finding in remediation.supported_findings(findings)
            if not analysis.is_informational(finding)
            and str(finding.get("file_path") or "") in contents
        ]
    except RuntimeError as error:
        annotate("warning", f"repairs unavailable: {error}")
        return [], [], f"Repairs were unavailable in this run: {error}"
    if not repairable:
        return [], [], "The exact affected source file is absent from the snapshot."

    tree = reader.git_tree(head_sha)
    if tree.get("truncated"):
        annotate(
            "warning",
            "the repository tree at this commit is too large to verify a repair against, so no "
            "fixes were generated.",
        )
        return [], [], "The repository tree at this commit is too large to verify a repair against."

    blobs = [e for e in tree.get("tree") or [] if e.get("type") == "blob"]
    ranked = remediation.rank_findings(repairable)
    try:
        # A proof loads the whole module, so the unchanged local modules it requires travel with
        # the changed files; without them the load fails on both trees.
        files = remediation.with_local_imports(
            dict(contents),
            {str(e.get("path") or "") for e in blobs},
            lambda paths: reader.file_contents(paths, head_sha),
        )
        request = remediation.build_request(
            repository_full_name=repository,
            pull_request_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha or head_sha,
            findings=ranked,
            files=files,
            tree_entries=blobs,
            tree_truncated=bool(tree.get("truncated")),
            model_configured=model_configured,
        )
        response = remediation.repair(request, model_configured)
    except Exception as error:  # noqa: BLE001 - a failed repair must never fail the review
        annotate("warning", f"repair generation failed: {error}")
        return [], [], "Repair generation failed in this run."

    findings_by_id = {
        str(finding.get("fingerprint") or f"finding-{index}"): finding
        for index, finding in enumerate(ranked)
    }
    reason = getattr(response, "reason", None) or {}
    fallback = str(reason.get("message") or "") if isinstance(reason, dict) else ""
    return (
        remediation.fix_sections(response, findings_by_id),
        list(getattr(response, "skipped", None) or []),
        fallback or "No verified repair was produced.",
    )


if __name__ == "__main__":
    sys.exit(main())
