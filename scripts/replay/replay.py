#!/usr/bin/env python3
"""Replay a public repository through the real pipeline, as pull requests or as a tree.

    scripts/replay/replay.py --repo expressjs/express --prs 15 --out results/expressjs-express.json
    scripts/replay/replay.py --snapshot --repo OWASP/NodeGoat --ref <sha> --out results/nodegoat.json

In pull request mode the harness reproduces the production payload (the same file
filters, the same 200-file cap, the same head-sha content fetch, the same reviewable
line spans) for each merged pull request. In snapshot mode it does the same for every
analysable file of one repository tree at a pinned commit, which is how a corpus that
actually contains vulnerabilities is measured. Either way the analysis service runs
in-process under a wall clock, and the remediation engine's template path runs for every
finding in a supported repair family. GitHub is only ever read, and every response and
tarball is cached on disk.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from corpus import SnapshotCache, SnapshotError, read_snapshot_file, walk_analysable_files  # noqa: E402
from ghcache import GitHubError, GitHubReader  # noqa: E402
from prodfilters import (  # noqa: E402
    ANALYSIS_FILE_CAP,
    CONTENT_PATH_CAP,
    PR_FILE_CAP,
    reviewable_line_spans,
    scoped_files,
    should_fetch_content,
)

DEFAULT_TIMEOUT_SECONDS = 300

# A snapshot is a whole repository, so it is sent in batches. The analysis service
# rejects a payload of more than ANALYSIS_FILE_CAP files, and one scanner process over
# megabytes of source is where a replay hangs, so a batch is bounded by both.
SNAPSHOT_BATCH_MAX_FILES = 120
SNAPSHOT_BATCH_MAX_BYTES = 1_500_000
SNAPSHOT_TIMEOUT_SECONDS = 1800


def build_payload(reader: GitHubReader, repo: str, pull: dict[str, Any]) -> dict[str, Any]:
    number = int(pull["number"])
    head_sha = pull.get("merge_commit_sha") or (pull.get("head") or {}).get("sha") or ""
    base_sha = (pull.get("base") or {}).get("sha") or head_sha
    limitations: list[str] = []

    raw_files = reader.pull_request_files(repo, number)
    scoped = scoped_files(raw_files)
    if len(scoped) > PR_FILE_CAP:
        # Production answers 422 here and never calls the analysis service.
        return {
            "repo": repo, "number": number, "head_sha": head_sha, "base_sha": base_sha,
            "files": [], "limitations": [f"pr_exceeds_{PR_FILE_CAP}_file_cap:{len(scoped)}"],
            "rejected": True,
        }
    if len(raw_files) > len(scoped):
        limitations.append(f"files_filtered_out:{len(raw_files) - len(scoped)}")
    if len(scoped) > ANALYSIS_FILE_CAP:
        limitations.append("analysis_service_300_file_cap_would_reject")

    files: list[dict[str, Any]] = []
    content_candidates = [item for item in scoped if should_fetch_content(item.get("filename", ""))]
    if len(content_candidates) > CONTENT_PATH_CAP:
        limitations.append(f"content_paths_truncated_to_{CONTENT_PATH_CAP}:{len(content_candidates)}")
    wanted = {item["filename"] for item in content_candidates[:CONTENT_PATH_CAP]}

    for item in scoped:
        path = item.get("filename", "")
        entry: dict[str, Any] = {
            "path": path,
            "patch": item.get("patch") or "",
            "additions": int(item.get("additions") or 0),
            "deletions": int(item.get("deletions") or 0),
            "status": item.get("status") or "modified",
            "reviewable_line_spans": reviewable_line_spans(item.get("patch") or ""),
        }
        if not item.get("patch"):
            # GitHub omits the patch for binary blobs and for very large diffs.
            limitations.append("file_without_patch")
        if path in wanted and head_sha:
            fetched = reader.file_content(repo, head_sha, path)
            if "content" in fetched:
                entry["content"] = fetched["content"]
                if fetched.get("non_utf8"):
                    limitations.append("content_not_utf8_replaced")
            else:
                limitations.append(f"content_skipped:{fetched['skipped']}")
        files.append(entry)

    return {
        "repo": repo, "number": number, "head_sha": head_sha, "base_sha": base_sha,
        "files": files, "limitations": limitations, "rejected": False,
    }


def run_pull_request(payload: dict[str, Any], timeout: int, python: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="replay_") as tmp:
        payload_path = Path(tmp) / "payload.json"
        out_path = Path(tmp) / "result.json"
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                [python, str(HERE / "worker.py"), str(payload_path), str(out_path)],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return _failure(payload, "timeout", f"exceeded {timeout}s wall clock",
                            int((time.perf_counter() - started) * 1000))
        elapsed = int((time.perf_counter() - started) * 1000)
        if completed.returncode != 0 or not out_path.exists():
            return _failure(
                payload,
                "worker_crash",
                (completed.stderr or completed.stdout or "")[-4000:],
                elapsed,
                returncode=completed.returncode,
            )
        record = json.loads(out_path.read_text(encoding="utf-8"))
        record["limitations"] = list(record.get("limitations", [])) + list(payload.get("limitations", []))
        record["wall_ms"] = elapsed
        record["worker_stderr_tail"] = (completed.stderr or "")[-1000:] if completed.stderr else ""
        return record


def _failure(payload: dict[str, Any], kind: str, detail: str, elapsed: int, returncode: int | None = None) -> dict[str, Any]:
    return {
        "repo": payload["repo"], "number": payload["number"], "head_sha": payload.get("head_sha", ""),
        "files": len(payload.get("files", [])),
        "files_with_content": sum(1 for item in payload.get("files", []) if item.get("content")),
        "bytes_patch": sum(len(item.get("patch", "").encode("utf-8")) for item in payload.get("files", [])),
        "bytes_content": sum(len(item.get("content", "").encode("utf-8")) for item in payload.get("files", [])),
        "analysis": None, "findings": [], "remediation": None,
        "limitations": payload.get("limitations", []),
        "fatal": {"kind": kind, "detail": detail, "returncode": returncode},
        "duration_ms": elapsed, "wall_ms": elapsed,
    }


# --- snapshot mode ---------------------------------------------------------------------------


def snapshot_batches(
    root: Path,
    max_files: int = SNAPSHOT_BATCH_MAX_FILES,
    max_bytes: int = SNAPSHOT_BATCH_MAX_BYTES,
) -> tuple[list[list[dict[str, Any]]], list[str], int]:
    """Every analysable file of the tree, in batches the analysis service will accept.

    Returns the batches, the limitations the fetch itself produced, and how many files
    were looked at before the production filters were applied.
    """
    batches: list[list[dict[str, Any]]] = []
    limitations: list[str] = []
    current: list[dict[str, Any]] = []
    current_bytes = 0
    considered = 0

    for path in walk_analysable_files(root):
        considered += 1
        relative = path.relative_to(root).as_posix()
        entry = read_snapshot_file(path, relative)
        if "skipped" in entry:
            limitations.append(f"content_skipped:{entry['skipped']}")
            continue
        if entry.pop("non_utf8", False):
            limitations.append("content_not_utf8_replaced")
        size = len(entry["content"].encode("utf-8"))
        if current and (len(current) >= max_files or current_bytes + size > max_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(entry)
        current_bytes += size

    if current:
        batches.append(current)
    if any(len(batch) > ANALYSIS_FILE_CAP for batch in batches):
        limitations.append("analysis_service_300_file_cap_would_reject")
    return batches, limitations, considered


def run_snapshot(
    repo: str,
    ref: str,
    cache: SnapshotCache,
    timeout: int,
    python: str,
    run_remediation: bool,
) -> dict[str, Any]:
    root = cache.tree(repo, ref)
    batches, fetch_limitations, considered = snapshot_batches(root)
    print(f"{repo}@{ref[:10]}: {considered} candidate files, {len(batches)} batches", flush=True)

    records: list[dict[str, Any]] = []
    for index, batch in enumerate(batches, start=1):
        payload = {
            "repo": repo,
            "number": index,
            "head_sha": ref,
            "base_sha": ref,
            "files": batch,
            "limitations": fetch_limitations if index == 1 else [],
            "run_remediation": run_remediation,
        }
        record = run_pull_request(payload, timeout, python)
        record["snapshot_batch"] = index
        records.append(record)
        summary = (
            f"  batch {index}/{len(batches)}: files={record.get('files')} "
            f"findings={len(record.get('findings') or [])} {record.get('wall_ms')}ms"
        )
        if record.get("fatal"):
            summary += f" FATAL={record['fatal']['kind']}"
        print(summary, flush=True)

    return {
        "repo": repo,
        "mode": "snapshot",
        "ref": ref,
        "candidate_files": considered,
        "analysed_files": sum(len(batch) for batch in batches),
        "batches": len(batches),
        "snapshot_downloads": cache.downloads,
        "snapshot_cache_hits": cache.cache_hits,
        "tier3": "skipped: no model key, LLM_TRIAGE_ENABLED=false",
        "remediation_path": (
            "template only; the model path is refused and counted as agent_needed"
            if run_remediation
            else "not run"
        ),
        "records": records,
    }


# --- pairs mode ------------------------------------------------------------------------------

# A pair's two sandbox runs materialize the snapshot twice, so one repository's pairs are given
# a wall clock of their own rather than the snapshot batch's.
PAIRS_TIMEOUT_SECONDS = 3600


# The root manifests a pair's snapshot has to carry. `walk_analysable_files` answers the
# scanner's question, which is "what can be analysed", and `package.json` is not an analysable
# extension; a repair's question is different. The engine reads a manifest to decide that a
# database driver is a real dependency and, with `policy.install_dependencies`, to decide that
# an install will populate `node_modules`, and it read neither of those here until this was
# added: the worker's own `PAIR_ROOT_FILES` listed names that never arrived. In the service the
# retriever carries them, so a measurement without them measures a snapshot production never
# sends.
PAIRS_ROOT_MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")
PAIRS_MANIFEST_MAX_BYTES = 200_000


def _root_manifests(root: Path) -> list[dict[str, Any]]:
    """The tree's root manifests, read whatever their extension."""
    found: list[dict[str, Any]] = []
    for name in PAIRS_ROOT_MANIFESTS:
        path = root / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > PAIRS_MANIFEST_MAX_BYTES:
            continue
        found.append({"path": name, "content": path.read_text(encoding="utf-8", errors="replace"), "patch": ""})
    return found


def _pairs_payload(result: dict[str, Any], cache: SnapshotCache, with_dependencies: bool = False) -> dict[str, Any]:
    """One repository's findings, joined back to the tree they were found in.

    A snapshot result records its findings but not the source they came from, so the content is
    read back out of the same pinned tree the run analysed. The ref is a full commit sha, so
    what is read here is byte-identical to what produced the findings.
    """
    repo, ref = result["repo"], result["ref"]
    root = cache.tree(repo, ref)
    findings: list[dict[str, Any]] = []
    for record in result.get("records") or []:
        findings.extend(record.get("findings") or [])

    # Every analysable file of the tree, not just the ones a finding names: a proof loads the
    # module under test, and that module imports its neighbours. The worker then spends the
    # remediation service's own snapshot budget per finding, nearest the finding first.
    files: list[dict[str, Any]] = []
    for path in walk_analysable_files(root):
        relative = path.relative_to(root).as_posix()
        entry = read_snapshot_file(path, relative)
        if "skipped" in entry:
            continue
        entry.pop("non_utf8", None)
        files.append({"path": relative, "content": entry["content"], "patch": ""})
    files = _root_manifests(root) + files
    payload = {
        "mode": "pairs", "repo": repo, "number": 0, "head_sha": ref, "base_sha": ref,
        "files": files, "findings": findings, "limitations": [],
    }
    if with_dependencies:
        # The install runs over the whole pinned tree, not the budgeted slice a pair sees: it is
        # the repository's own manifests and lockfiles that `npm ci` and `pip install` read, and
        # the workspace is then pointed at what came out. The worker does the installing, because
        # it is the process that has the remediation service on its path and the measurement has
        # to install exactly what `policy.install_dependencies` would.
        payload["install_dependencies"] = True
        payload["dependency_tree"] = str(root)
    return payload


def run_pairs(results: list[Path], cache: SnapshotCache, timeout: int, python: str,
              with_dependencies: bool = False) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for path in results:
        result = json.loads(path.read_text(encoding="utf-8"))
        if result.get("mode") != "snapshot":
            print(f"  {path.name}: not a snapshot run, skipped", flush=True)
            continue
        payload = _pairs_payload(result, cache, with_dependencies)
        print(f"{result['repo']}@{result['ref'][:10]}: {len(payload['findings'])} findings over "
              f"{len(payload['files'])} files", flush=True)
        record = run_pull_request(payload, timeout, python)
        records.append(record)
        counts = ((record.get("pairs") or {}).get("counts")) or {}
        install = ((record.get("pairs") or {}).get("install")) or {}
        if with_dependencies:
            print(f"  install: {'ok' if install.get('dependencies_installed') else install.get('reason_code')} "
                  f"{install.get('duration_ms', 0)}ms {install.get('bytes_installed', 0)} bytes "
                  f"ecosystems={','.join(install.get('ecosystems') or []) or 'none'}", flush=True)
        print(f"  supported={counts.get('supported', 0)} patch={counts.get('patch', 0)} "
              f"proof={counts.get('proof', 0)} both={counts.get('both', 0)} "
              f"verified={counts.get('verified', 0)} {record.get('wall_ms')}ms", flush=True)
    totals = {key: 0 for key in ("supported", "patch", "proof", "both", "verified")}
    for record in records:
        for key, value in (((record.get("pairs") or {}).get("counts")) or {}).items():
            totals[key] = totals.get(key, 0) + int(value)
    return {"mode": "pairs", "with_dependencies": with_dependencies, "totals": totals, "records": records}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", help="owner/name of a public repository")
    parser.add_argument("--prs", type=int, default=15, help="how many recent merged pull requests to replay")
    parser.add_argument("--out", required=True, help="path of the per-repository JSON result file")
    parser.add_argument("--cache", default=str(HERE / ".cache"), help="directory for cached GitHub responses")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="per-PR wall clock, seconds")
    parser.add_argument("--python", default=sys.executable, help="interpreter used for the worker process")
    parser.add_argument("--refresh", action="store_true", help="ignore the cache and re-read GitHub")
    parser.add_argument("--only-pr", type=int, action="append", help="replay only these pull request numbers")
    parser.add_argument("--snapshot", action="store_true",
                        help="analyse a whole repository tree at --ref instead of pull requests")
    parser.add_argument("--ref", help="snapshot mode: the full 40-character commit sha to pin")
    parser.add_argument("--no-remediation", action="store_true",
                        help="skip the remediation stage (analysis only)")
    parser.add_argument("--include-quarantined", action="store_true",
                        help="report findings from quarantined rules too, so they can be re-measured")
    parser.add_argument("--pairs", action="store_true",
                        help="measure both repair halves over the findings of earlier snapshot runs, "
                             "and run every complete pair's proof on the original and the patched tree")
    parser.add_argument("--results", nargs="+", default=[],
                        help="pairs mode: the snapshot result files to measure")
    parser.add_argument("--with-dependencies", action="store_true",
                        help="pairs mode: install each repository's declared dependencies into its "
                             "pinned tree and let the sandbox workspace see them, the way "
                             "policy.install_dependencies does in the service")
    args = parser.parse_args()

    if args.include_quarantined:
        os.environ["REPLAY_INCLUDE_QUARANTINED"] = "1"

    if args.pairs:
        if not args.results:
            print("--pairs requires --results", file=sys.stderr)
            return 2
        cache = SnapshotCache(Path(args.cache) / "snapshots", refresh=args.refresh)
        timeout = args.timeout if args.timeout != DEFAULT_TIMEOUT_SECONDS else PAIRS_TIMEOUT_SECONDS
        try:
            result = run_pairs([Path(item) for item in args.results], cache, timeout, args.python,
                               args.with_dependencies)
        except SnapshotError as exc:
            print(f"pairs: snapshot unavailable: {exc}", file=sys.stderr)
            return 2
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"pairs: wrote {out_path} {result['totals']}", flush=True)
        return 0

    if not args.repo:
        print("--repo is required outside --pairs mode", file=sys.stderr)
        return 2

    if args.snapshot:
        if not args.ref:
            print("--snapshot requires --ref", file=sys.stderr)
            return 2
        cache = SnapshotCache(Path(args.cache) / "snapshots", refresh=args.refresh)
        timeout = args.timeout if args.timeout != DEFAULT_TIMEOUT_SECONDS else SNAPSHOT_TIMEOUT_SECONDS
        try:
            result = run_snapshot(
                args.repo, args.ref, cache, timeout, args.python, not args.no_remediation
            )
        except SnapshotError as exc:
            print(f"{args.repo}: snapshot failed: {exc}", file=sys.stderr)
            return 2
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"{args.repo}: wrote {out_path}", flush=True)
        return 0

    reader = GitHubReader(Path(args.cache), refresh=args.refresh)
    try:
        pulls = reader.merged_pull_requests(args.repo, args.prs)
    except GitHubError as exc:
        print(f"{args.repo}: could not list pull requests: {exc}", file=sys.stderr)
        return 2
    if args.only_pr:
        wanted = set(args.only_pr)
        pulls = [pull for pull in pulls if int(pull["number"]) in wanted]

    records: list[dict[str, Any]] = []
    for pull in pulls:
        number = int(pull["number"])
        try:
            payload = build_payload(reader, args.repo, pull)
        except GitHubError as exc:
            records.append({"repo": args.repo, "number": number, "files": 0, "findings": [],
                            "analysis": None, "remediation": None, "limitations": [],
                            "fatal": {"kind": "github_read_failed", "detail": str(exc)[:500]},
                            "duration_ms": 0, "wall_ms": 0})
            print(f"  PR #{number}: github read failed: {exc}", flush=True)
            continue
        if payload.get("rejected"):
            records.append({"repo": args.repo, "number": number, "files": 0, "files_with_content": 0,
                            "bytes_patch": 0, "bytes_content": 0, "findings": [],
                            "analysis": None, "remediation": None,
                            "limitations": payload["limitations"], "duration_ms": 0, "wall_ms": 0})
            print(f"  PR #{number}: {payload['limitations'][0]}", flush=True)
            continue
        record = run_pull_request(payload, args.timeout, args.python)
        records.append(record)
        summary = (
            f"  PR #{number}: files={record.get('files')} findings={len(record.get('findings') or [])} "
            f"{record.get('wall_ms')}ms"
        )
        if record.get("fatal"):
            summary += f" FATAL={record['fatal']['kind']}"
        print(summary, flush=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "repo": args.repo,
        "requested_prs": args.prs,
        "replayed_prs": len(records),
        "github_calls": reader.calls,
        "github_cache_hits": reader.cache_hits,
        "tier3": "skipped: no model key, LLM_TRIAGE_ENABLED=false",
        "remediation_path": "template only; the model path is refused and counted as agent_needed",
        "records": records,
    }, indent=2), encoding="utf-8")
    print(f"{args.repo}: wrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
