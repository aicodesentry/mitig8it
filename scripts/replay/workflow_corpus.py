"""The workflow corpus of docs/validation/workflow-tampering-2026-09.md, refetched and scanned.

Fetches the `.github/workflows` directory of the eleven clean replay repositories (at the last
commit on their default branch on or before 27 September 2026) and of the 23 vulnerable-corpus
repositories (at the refs in benchmarks/vulnerable-corpus/labels.json), adds this repository's
own workflows from a git ref, and runs every tier 2 rule over each repository through the
service's real `run_opengrep_with_limitations`. Prints one JSON object per workflow finding and
a per-rule count on stderr.

Nothing is written to GitHub: every call is `gh api --method GET`. Fetched files are cached under
`--cache`, so a second run reads no network.

    PY=~/.pyenv/versions/3.11.6/bin/python
    $PY scripts/replay/workflow_corpus.py --cache /tmp/workflow-corpus --self-ref origin/main \\
        > /tmp/workflow-findings.json
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LABELS = ROOT / "benchmarks" / "vulnerable-corpus" / "labels.json"
ANALYSIS_SRC = ROOT / "services" / "analysis-service" / "src"
CLEAN = (
    "encode/django-rest-framework", "expressjs/express", "fastify/fastify", "pallets/flask",
    "prettier/prettier", "psf/requests", "python/cpython", "sequelize/sequelize",
    "sindresorhus/got", "tiangolo/fastapi", "vercel/next.js",
)
CLEAN_UNTIL = "2026-09-27T23:59:59Z"
SELF = "nebullii/mitig8it"


def gh(path: str, raw: bool = False):
    command = ["gh", "api", "--method", "GET", path]
    if raw:
        command[4:4] = ["-H", "Accept: application/vnd.github.raw"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return None
    return result.stdout if raw else json.loads(result.stdout)


def refs() -> dict[str, str]:
    pinned: dict[str, str] = {}
    for repo in CLEAN:
        commits = gh(f"repos/{repo}/commits?until={CLEAN_UNTIL}&per_page=1")
        pinned[repo] = commits[0]["sha"]
    for entry in json.loads(LABELS.read_text())["repositories"]:
        pinned[entry["repo"]] = entry["ref"]
    return pinned


def fetch(cache: Path, repo: str, ref: str) -> Path:
    target = cache / repo.replace("/", "__")
    marker = target / ".ref"
    if marker.is_file() and marker.read_text() == ref:
        return target
    listing = gh(f"repos/{repo}/contents/.github/workflows?ref={ref}")
    for item in listing if isinstance(listing, list) else []:
        if item["type"] == "file" and item["name"].endswith((".yml", ".yaml")):
            body = gh(f"repos/{repo}/contents/{item['path']}?ref={ref}", raw=True)
            if body is not None:
                destination = target / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(body)
    target.mkdir(parents=True, exist_ok=True)
    marker.write_text(ref)
    return target


def fetch_self(cache: Path, ref: str) -> Path:
    target = cache / SELF.replace("/", "__")
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", ref, ".github/workflows"], capture_output=True, check=True
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(target, filter="data")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", required=True, help="directory the workflow files are fetched into")
    parser.add_argument("--self-ref", default="HEAD", help="git ref of this repository's own workflows")
    args = parser.parse_args()
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(ANALYSIS_SRC))
    from opengrep_runner import run_opengrep_with_limitations  # noqa: PLC0415

    trees = [(repo, fetch(cache, repo, ref), ref) for repo, ref in refs().items()]
    trees.append((SELF, fetch_self(cache, args.self_ref), args.self_ref))

    findings, files = [], 0
    for repo, tree, ref in trees:
        documents = [
            {"path": f".github/workflows/{path.name}", "content": path.read_text()}
            for path in sorted((tree / ".github" / "workflows").glob("*"))
            if path.suffix in (".yml", ".yaml")
        ]
        files += len(documents)
        print(f"{repo} {ref[:12]} {len(documents)} files", file=sys.stderr)
        if not documents:
            continue
        # The runner reports its batches on stdout, which is where the findings go.
        with contextlib.redirect_stdout(sys.stderr):
            found, limitations = run_opengrep_with_limitations(documents)
        for limitation in limitations:
            print(f"limitation {repo}: {limitation}", file=sys.stderr)
        for finding in found:
            if ".gha-" not in str(finding.get("rule_id")):
                continue
            findings.append({
                "repo": repo,
                "ref": ref,
                "rule_id": finding["rule_id"],
                "path": finding["file_path"],
                "line": finding["line_start"],
                "snippet": (finding.get("code_snippet") or "").split("\n")[0].strip()[:200],
                "fingerprint": finding.get("fingerprint"),
            })

    print(f"{files} workflow files", file=sys.stderr)
    for rule_id, count in sorted(collections.Counter(item["rule_id"] for item in findings).items()):
        print(f"{count:4d} {rule_id}", file=sys.stderr)
    json.dump(findings, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
