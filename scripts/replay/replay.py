#!/usr/bin/env python3
"""Replay merged pull requests of a public repository through the real pipeline.

    scripts/replay/replay.py --repo expressjs/express --prs 15 --out results/expressjs-express.json

For each merged pull request the harness reproduces the production payload (the same
file filters, the same 200-file cap, the same head-sha content fetch, the same
reviewable line spans), runs the analysis service in-process under a wall clock, and
then runs the remediation engine's template path for every finding in a supported
repair family. GitHub is only ever read, and every response is cached on disk.
"""
from __future__ import annotations

import argparse
import json
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="owner/name of a public repository")
    parser.add_argument("--prs", type=int, default=15, help="how many recent merged pull requests to replay")
    parser.add_argument("--out", required=True, help="path of the per-repository JSON result file")
    parser.add_argument("--cache", default=str(HERE / ".cache"), help="directory for cached GitHub responses")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="per-PR wall clock, seconds")
    parser.add_argument("--python", default=sys.executable, help="interpreter used for the worker process")
    parser.add_argument("--refresh", action="store_true", help="ignore the cache and re-read GitHub")
    parser.add_argument("--only-pr", type=int, action="append", help="replay only these pull request numbers")
    args = parser.parse_args()

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
