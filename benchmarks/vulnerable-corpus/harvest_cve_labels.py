#!/usr/bin/env python3
"""Propose corpus labels from published advisories that name their fixing commit.

An intentionally vulnerable application tells you where its vulnerabilities are, but it
is written to be found. A CVE fix commit is the other half of the corpus: real code, in a
real package, that a real person had to repair. The fix diff is the ground truth, because
the lines it deletes are the vulnerable lines, and the commit's parent is a tree that
still contains them.

    benchmarks/vulnerable-corpus/harvest_cve_labels.py --cwe 89 --ecosystem npm --out /tmp/c.json

What comes out is a *candidate* list, not labels. Every candidate has to be read before it
is written into `labels.json`: a fix commit routinely deletes a test, a changelog entry and
the vulnerable line in one go, and only the third is a label. The fields this prints for
each candidate are the ones that decision needs.

Nothing here writes to GitHub; every call is `gh api --method GET`.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parents[1] / "scripts" / "replay"
if str(REPLAY) not in sys.path:
    sys.path.insert(0, str(REPLAY))

from ghcache import GitHubError, GitHubReader  # noqa: E402
from prodfilters import should_fetch_content  # noqa: E402

COMMIT_URL = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")

# What a corpus label is allowed to be about. A fix for a class no rule covers teaches
# nothing about this rule set's recall.
DEFAULT_CWES = ["78", "89", "22", "94", "79", "918", "502", "798", "327"]


def advisories(reader: GitHubReader, ecosystem: str, cwe: str, limit: int, direction: str) -> list[dict[str, Any]]:
    body = reader.get(
        f"/advisories?ecosystem={ecosystem}&cwes={cwe}&type=reviewed"
        f"&per_page={min(limit, 100)}&sort=published&direction={direction}"
    )
    return body if isinstance(body, list) else []


def removed_ranges(patch: str) -> list[tuple[int, int]]:
    """The old-side line ranges of the lines this patch deletes.

    These are the lines the fix removed, at the line numbers the *parent* commit has them,
    which is the tree the corpus analyses.
    """
    ranges: list[tuple[int, int]] = []
    old_line = 0
    start: int | None = None
    end: int | None = None

    def flush() -> None:
        nonlocal start, end
        if start is not None and end is not None:
            ranges.append((start, end))
        start = None
        end = None

    for raw in str(patch or "").split("\n"):
        if raw.startswith("@@"):
            flush()
            match = HUNK.match(raw)
            if match:
                old_line = int(match.group(1))
            continue
        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        if raw.startswith("+"):
            continue
        if raw.startswith("-"):
            if start is None:
                start = old_line
            end = old_line
            old_line += 1
            continue
        flush()
        if not raw.startswith("\\"):
            old_line += 1
    flush()
    return ranges


def candidate(reader: GitHubReader, advisory: dict[str, Any], repo: str, sha: str) -> dict[str, Any] | None:
    try:
        commit = reader.get(f"repos/{repo}/commits/{sha}")
        repository = reader.get(f"repos/{repo}")
    except GitHubError as exc:
        return {"repo": repo, "fix_sha": sha, "error": str(exc)[:200]}

    parents = commit.get("parents") or []
    if len(parents) != 1:
        # A merge commit's diff is against one parent only; the vulnerable tree is ambiguous.
        return None

    files = []
    for item in commit.get("files") or []:
        path = item.get("previous_filename") or item.get("filename") or ""
        if not should_fetch_content(path):
            continue
        ranges = removed_ranges(item.get("patch") or "")
        if not ranges:
            continue
        files.append({
            "path": path,
            "removed_ranges": [list(pair) for pair in ranges],
            "removed_lines": sum(end - start + 1 for start, end in ranges),
        })
    if not files:
        return None

    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "cwe_ids": [item.get("cwe_id") for item in (advisory.get("cwes") or [])],
        "summary": str(advisory.get("summary") or "")[:200],
        "severity": advisory.get("severity"),
        "packages": [
            (item.get("package") or {}).get("name")
            for item in (advisory.get("vulnerabilities") or [])
        ],
        "repo": repo,
        "fix_sha": commit.get("sha"),
        "parent_sha": parents[0].get("sha"),
        "repo_size_kb": repository.get("size"),
        "repo_license": ((repository.get("license") or {}).get("spdx_id") or "NONE"),
        "commit_files_total": len(commit.get("files") or []),
        "files": sorted(files, key=lambda item: item["removed_lines"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cwe", action="append", help="CWE number, repeatable (default: the nine in scope)")
    parser.add_argument("--ecosystem", action="append", help="npm or pip, repeatable (default: both)")
    parser.add_argument("--limit", type=int, default=40, help="advisories to read per (ecosystem, CWE)")
    parser.add_argument("--max-commit-files", type=int, default=12,
                        help="skip a fix commit that touches more files than this")
    parser.add_argument("--direction", choices=("asc", "desc"), default="desc",
                        help="publication order; `asc` reaches the older advisories, whose fixes "
                             "delete a sink more often than they tighten a sanitizer")
    parser.add_argument("--cache", default=str(REPLAY / ".cache"), help="directory for cached GitHub responses")
    parser.add_argument("--out", required=True, help="path of the candidate JSON file")
    args = parser.parse_args()

    reader = GitHubReader(Path(args.cache))
    cwes = args.cwe or DEFAULT_CWES
    ecosystems = args.ecosystem or ["npm", "pip"]

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ecosystem in ecosystems:
        for cwe in cwes:
            for advisory in advisories(reader, ecosystem, cwe, args.limit, args.direction):
                for reference in advisory.get("references") or []:
                    match = COMMIT_URL.match(str(reference))
                    if not match:
                        continue
                    repo, sha = match.group(1), match.group(2)
                    key = f"{repo}@{sha}"
                    if key in seen:
                        continue
                    seen.add(key)
                    entry = candidate(reader, advisory, repo, sha)
                    if not entry or entry.get("error"):
                        continue
                    if entry["commit_files_total"] > args.max_commit_files:
                        continue
                    entry["ecosystem"] = ecosystem
                    entry["queried_cwe"] = f"CWE-{cwe}"
                    candidates.append(entry)
            print(f"{ecosystem} CWE-{cwe}: {len(candidates)} candidates so far", flush=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    print(f"wrote {len(candidates)} candidates to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
