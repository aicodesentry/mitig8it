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
import sys
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import analysis, github_api, pr_scope, repo_config

CHECK_RUN_NAME = "Mitig8it Security Review"
FAIL_ON_CHOICES = ("none", "high", "critical")

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
    """A condition the run cannot continue past, reported without a traceback."""


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


def annotate(level: str, message: str) -> None:
    """A workflow annotation, so the message shows on the run summary and not only in the log."""
    single_line = message.replace("\n", "%0A")
    print(f"::{level}::{single_line}", flush=True)


def load_event() -> Dict[str, Any]:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not Path(path).is_file():
        raise ActionError("GITHUB_EVENT_PATH is not set; this action runs on pull_request events")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def pull_request_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        raise ActionError(
            "This action only runs on pull_request events. Add "
            "`on: pull_request` to the workflow."
        )
    return pull


def assert_least_privilege(reader: github_api.GitHubReader) -> Dict[str, bool]:
    """Refuse to run when the workflow granted write access to file contents."""
    permissions = reader.repository_permissions()
    if permissions.get("push"):
        raise ActionError(REFUSED_PERMISSION_MESSAGE)
    return permissions


def build_inline_comments(
    findings: Sequence[Dict[str, Any]],
    patches_by_path: Dict[str, str],
) -> List[Dict[str, Any]]:
    """One comment per finding that can be anchored to a line the author touched.

    A finding on a line the pull request did not change has nowhere to go: GitHub rejects the
    comment, and posting it against the nearest changed line would point the reader at code that
    is not the problem. Those findings stay in the summary count and out of the diff.
    """
    comments: List[Dict[str, Any]] = []
    for finding in findings:
        path = str(finding.get("file_path") or "")
        line = int(finding.get("line_start") or 0)
        if not path or line <= 0:
            continue
        if line not in pr_scope.reviewable_lines(patches_by_path.get(path, "")):
            continue
        comments.append(
            {
                "path": path,
                "line": line,
                "body": render_finding_comment(finding),
                "fingerprint": comment_fingerprint(finding),
                "severity": str(finding.get("severity") or "").lower(),
            }
        )

    def rank(comment: Dict[str, Any]) -> tuple:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return (
            severity_order.get(comment["severity"], 5),
            comment["path"],
            comment["line"],
        )

    comments.sort(key=rank)
    return comments[: pr_scope.INLINE_COMMENT_CAP]


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
    lines = [
        f"<!-- mitig8it-finding:{fingerprint} -->",
        f"**{title}**",
        "",
        f"Severity: {severity}",
    ]
    cwe = str(finding.get("cwe_id") or "")
    if cwe:
        lines.append(f"Weakness: {cwe}")
    description = str(finding.get("description") or "")
    if description:
        lines.extend(["", description])
    evidence = str(finding.get("evidence") or "")
    if evidence:
        lines.extend(["", evidence])
    remediation = str(finding.get("remediation") or "")
    if remediation:
        lines.extend(["", f"Remediation: {remediation}"])
    return "\n".join(lines)


def fail_conclusion(fail_on: str, counts: Dict[str, int]) -> str:
    """The check run conclusion, which is also what decides the job's exit code."""
    if fail_on == "critical" and counts.get("critical", 0) > 0:
        return "failure"
    if fail_on == "high" and (counts.get("critical", 0) + counts.get("high", 0)) > 0:
        return "failure"
    if fail_on == "none":
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
    excluded_files: int = 0,
    active_fingerprints: Sequence[str] = (),
    bot_login: str = "github-actions[bot]",
    action_id: Optional[str] = None,
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
        "manifest_digest": manifest_digest(action_id, head_sha, base_sha, fix_sections),
        "counts": counts,
        "findings": findings,
        "fixes": len(fix_sections),
        "modelConfigured": model_configured,
        "failConclusion": conclusion,
        "excludedFiles": int(excluded_files),
        # Every finding this run reported, not only the ones that could be anchored to a changed
        # line. A finding that exists but has nowhere to comment must not have its thread
        # resolved as though it had gone away.
        "active_fingerprints": sorted(set(active_fingerprints)),
        "inline_comments": list(inline_comments),
        "fix_sections": list(fix_sections),
    }


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
    if completed.returncode != 0:
        raise ActionError(f"publishing failed: {completed.stderr.strip() or 'unknown error'}")
    try:
        return json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv
    try:
        return _run()
    except ActionError as error:
        annotate("error", str(error))
        return 1


def _run() -> int:
    token = input_value("github-token") or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise ActionError("no github-token was provided")

    fail_on = input_value("fail-on", "none").strip().lower()
    if fail_on not in FAIL_ON_CHOICES:
        raise ActionError(f"fail-on must be one of {', '.join(FAIL_ON_CHOICES)}")
    post_fixes = boolean_input("post-fixes", True)
    max_files = max(1, int(input_value("max-files", "200")))

    model_key = input_value("model-api-key")
    model_configured = bool(model_key)
    if not model_configured:
        # Belt and braces: the analysis service treats triage as on by default, so the action
        # turns it off rather than relying on the absence of a key.
        os.environ["LLM_TRIAGE_ENABLED"] = "false"

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    event = load_event()
    pull = pull_request_from_event(event)
    pr_number = int(pull.get("number") or 0)
    head_sha = str((pull.get("head") or {}).get("sha") or "")
    base_sha = str((pull.get("base") or {}).get("sha") or "")
    if not pr_number or not head_sha:
        raise ActionError("the event payload carried no pull request number or head sha")

    reader = github_api.GitHubReader(token=token, repository=repository, api_url=api_url)

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
    cap_limitation = pr_scope.changed_file_limitation(raw_files, exclusions)
    if cap_limitation:
        log(cap_limitation["message"] + "; the rest of the change was not reviewed.")
    if len(scoped) > max_files:
        raise ActionError(
            f"this pull request changes {len(scoped)} files, above the max-files input of "
            f"{max_files}. Raise the input or split the change."
        )
    log(f"{len(scoped)} file(s) in scope.")

    wanted = [f["path"] for f in scoped if pr_scope.should_fetch_full_file_content(f)]
    contents = reader.file_contents(wanted, head_sha) if wanted else {}
    missing = [path for path in wanted if path not in contents]
    if missing:
        # Production fails closed here for the same reason: a scan that silently skipped a file
        # would report a clean result it did not earn.
        raise ActionError(
            "Required source content response is incomplete; these files could not be read at "
            f"the head commit (they may exceed {pr_scope.MAX_FILE_CONTENT_BYTES} bytes): "
            + ", ".join(missing[:10])
        )

    analysis_files = pr_scope.build_analysis_files(scoped, contents)
    log("Scanning.")
    findings = analysis.analyze(repository, pr_number, head_sha, analysis_files)
    counts = analysis.severity_counts(findings)
    log(
        f"{len(findings)} finding(s): {counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low, {counts['info']} informational."
    )

    fix_sections: List[Dict[str, Any]] = []
    if post_fixes and findings:
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
        log(f"{len(fix_sections)} fix suggestion(s) produced.")

    patches_by_path = {f["path"]: f.get("patch") or "" for f in scoped}
    inline_comments = build_inline_comments(findings, patches_by_path)

    conclusion = fail_conclusion(fail_on, counts)
    request = build_publish_request(
        token=token,
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha or head_sha,
        installation_id=int(((event.get("repository") or {}).get("id")) or 1),
        actor_login=os.environ.get("GITHUB_ACTOR", "github-actions") or "github-actions",
        counts=counts,
        findings=len(findings),
        fix_sections=fix_sections,
        inline_comments=inline_comments,
        model_configured=model_configured,
        conclusion=conclusion,
        excluded_files=excluded_files,
        active_fingerprints=[comment_fingerprint(finding) for finding in findings],
        # Asked of the token rather than assumed. `github-actions[bot]` is right only for the
        # default workflow token; a repository that passes an App installation token or a PAT
        # posts under a different login, and github-service recognises its own comment by that
        # login. Assuming it meant every re-run created a second comment instead of editing.
        bot_login=reader.viewer_login(),
    )

    log("Publishing.")
    results = run_publisher(request)
    errors = results.get("errors") or []
    for error in errors:
        annotate("warning", f"publish: {error}")

    write_outputs(
        {
            "findings": len(findings),
            "critical": counts["critical"],
            "high": counts["high"],
            "fixes": len(fix_sections),
            "conclusion": conclusion,
            "excluded": excluded_files,
        }
    )
    exclusion_line = repo_config.exclusion_summary(excluded_files)
    write_summary(
        f"### {CHECK_RUN_NAME}\n\n"
        f"{len(findings)} finding(s), {counts['critical']} critical, {counts['high']} high, "
        f"{len(fix_sections)} fix suggestion(s).\n\n"
        + (f"{exclusion_line}.\n\n" if exclusion_line else "")
        + (
            "Fixes were generated with model assistance.\n"
            if model_configured
            else "No model key was configured, so only template fixes were produced and "
            "nothing left this runner.\n"
        )
    )

    if conclusion == "failure":
        annotate(
            "error",
            f"Mitig8it: {counts['critical']} critical and {counts['high']} high findings "
            f"exceed fail-on: {fail_on}.",
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
    """Attempt a repair for every finding the engine has a family and a language for.

    Imported lazily so that a run which produced no findings never pays for loading the repair
    engine, and so a repository with no repairable finding still publishes its review when the
    engine cannot start.
    """
    from . import remediation  # noqa: PLC0415

    try:
        repairable = [
            finding
            for finding in remediation.supported_findings(findings)
            if not analysis.is_informational(finding)
            and str(finding.get("file_path") or "") in contents
        ]
    except RuntimeError as error:
        annotate("warning", f"repairs unavailable: {error}")
        return []
    if not repairable:
        return []

    tree = reader.git_tree(head_sha)
    if tree.get("truncated"):
        annotate(
            "warning",
            "the repository tree at this commit is too large to verify a repair against, so no "
            "fixes were generated.",
        )
        return []

    ranked = remediation.rank_findings(repairable)
    try:
        request = remediation.build_request(
            repository_full_name=repository,
            pull_request_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha or head_sha,
            findings=ranked,
            files={path: text for path, text in contents.items()},
            tree_entries=[e for e in tree.get("tree") or [] if e.get("type") == "blob"],
            tree_truncated=bool(tree.get("truncated")),
            model_configured=model_configured,
        )
        response = remediation.repair(request, model_configured)
    except Exception as error:  # noqa: BLE001 - a failed repair must never fail the review
        annotate("warning", f"repair generation failed: {error}")
        return []

    findings_by_id = {
        str(finding.get("fingerprint") or f"finding-{index}"): finding
        for index, finding in enumerate(ranked)
    }
    return remediation.fix_sections(response, findings_by_id)


if __name__ == "__main__":
    sys.exit(main())
