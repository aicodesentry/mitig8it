#!/usr/bin/env python3
"""Recall floor over a committed subset of the vulnerable corpus, for CI that has no corpus cache.

    scripts/replay/fixture_subset.py build --snapshots scripts/replay/.cache/snapshots
    scripts/replay/fixture_subset.py check
    scripts/replay/fixture_subset.py update

`ratchet.py` measures the 23 pinned corpus trees, which means downloading them. That suits a
scheduled job and a pull request that touches the rules; it does not suit a check that has to
run on every pull request and be required. This is the part that can be: every labelled file
whose label the recall baseline holds as hit, copied into
`benchmarks/vulnerable-corpus/fixture-subset/` with the licence of the repository it came from.

`build` makes the subset from a local snapshot cache. It takes only repositories whose licence
in `labels.json` is permissive, copies each file at the pinned ref, copies the
nearest licence file above it, and with `--gitleaks` overwrites every secret gitleaks reports
with `x` of the same length, because a committed private key fails this repository's own secret
scan and GitHub's push protection whether or not it is a fixture. The redactions are listed in
`manifest.json`, and `sha256` is of the file as committed.

`check` scans the subset the way a snapshot run scans a tree (`replay.snapshot_batches`, then
`worker.run_analysis`, quarantined rules included, both tiers' time limits lifted), joins the
findings to the labels with `score.join`, and compares with `expected.json` using the ratchet's
own `compare`. Exit 0 when nothing regressed, 1 when a label regressed or the hit count fell
below the floor, 2 when the run is not a measurement (the scanner is missing, a tier failed, a
ceiling was reached, or the manifest and the files on disk disagree).

`update` writes `expected.json` from a complete run. The floor is the hit count it records.

A label can be hit in the full tree and missed here when the detection depends on another file
of the repository; `expected.json` is measured on the subset itself, so such a label is simply
recorded as not hit and the full-corpus ratchet still holds it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ANALYSIS_SRC = REPO_ROOT / "services" / "analysis-service" / "src"
for entry in (str(HERE), str(ANALYSIS_SRC)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import ratchet  # noqa: E402
import score  # noqa: E402

CORPUS = REPO_ROOT / "benchmarks" / "vulnerable-corpus"
SUBSET = CORPUS / "fixture-subset"
TREES = SUBSET / "trees"
LICENCES = SUBSET / "licences"
MANIFEST = SUBSET / "manifest.json"
EXPECTED = SUBSET / "expected.json"

PERMISSIVE_LICENCES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD"}
LICENCE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING", "UNLICENSE", "NOTICE", "NOTICE.md", "NOTICE.txt")
LIFTED_SECONDS = "86400"
SUBSET_PULL_NUMBER = 1

EXIT_OK = ratchet.EXIT_OK
EXIT_REGRESSED = ratchet.EXIT_REGRESSED
EXIT_UNUSABLE = ratchet.EXIT_UNUSABLE


def repo_dir(repo: str) -> str:
    return repo.replace("/", "__")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- build --------------------------------------------------------------------------------------


def snapshot_root(snapshots: Path, repo: str, ref: str) -> Path:
    """The extracted tree under the replay cache: `<owner__name>/<ref>/<one directory>`."""
    base = snapshots / repo_dir(repo) / ref
    trees = [child for child in sorted(base.iterdir()) if child.is_dir()] if base.is_dir() else []
    if len(trees) != 1:
        raise SystemExit(f"{repo}@{ref}: expected one extracted tree under {base}, found {len(trees)}")
    return trees[0]


def nearest_licences(root: Path, relative: str) -> list[Path]:
    """Every licence or notice file in the closest directory above the file that has one."""
    directory = (root / relative).parent
    while True:
        found = [directory / name for name in LICENCE_NAMES if (directory / name).is_file()]
        if found or directory == root:
            return found
        directory = directory.parent


def gitleaks_secrets(paths: list[Path]) -> dict[Path, list[dict[str, Any]]]:
    """What gitleaks reports in each file, scanned as plain files outside any repository."""
    found: dict[Path, list[dict[str, Any]]] = {}
    with tempfile.TemporaryDirectory(prefix="subset_gitleaks_") as tmp:
        staging = Path(tmp) / "src"
        staging.mkdir()
        index: dict[str, Path] = {}
        for number, path in enumerate(paths):
            name = f"{number:04d}_{path.name}"
            shutil.copyfile(path, staging / name)
            index[name] = path
        report = Path(tmp) / "report.json"
        subprocess.run(
            ["gitleaks", "dir", str(staging), "--report-format", "json", "--report-path", str(report),
             "--no-banner", "--exit-code", "0"],
            check=True, capture_output=True,
        )
        for item in json.loads(report.read_text(encoding="utf-8") or "[]"):
            name = Path(str(item.get("File") or "")).name
            if name in index:
                found.setdefault(index[name], []).append(item)
    return found


def redact(text: str, secrets: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Each reported secret replaced by `x` of the same length, so no line or column moves."""
    applied: list[dict[str, Any]] = []
    for item in sorted(secrets, key=lambda entry: (int(entry.get("StartLine") or 0), str(entry.get("RuleID") or ""))):
        secret = str(item.get("Secret") or "")
        if not secret or secret not in text:
            raise SystemExit(f"gitleaks reported a secret that is not in the file verbatim (rule {item.get('RuleID')})")
        text = text.replace(secret, "".join("\n" if char == "\n" else "x" for char in secret))
        applied.append({"line": int(item.get("StartLine") or 0), "gitleaks_rule": str(item.get("RuleID") or "")})
    return text, applied


def command_build(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    licence_of = {item["repo"]: item.get("licence", "") for item in document["repositories"]}
    baseline = ratchet.load_baseline(Path(args.baseline))
    snapshots = Path(args.snapshots)

    wanted: dict[tuple[str, str, str], list[str]] = {}
    refused_licence: set[str] = set()
    for label in document["labels"]:
        if not (baseline.get(label["id"]) or {}).get("hit"):
            continue
        if licence_of.get(label["repo"]) not in PERMISSIVE_LICENCES:
            refused_licence.add(label["repo"])
            continue
        wanted.setdefault((label["repo"], label["ref"], label["path"]), []).append(label["id"])

    sources = {key: snapshot_root(snapshots, key[0], key[1]) / key[2] for key in wanted}
    secrets = gitleaks_secrets(list(sources.values())) if args.gitleaks else {}

    if SUBSET.exists():
        shutil.rmtree(SUBSET)
    files: list[dict[str, Any]] = []
    licences: dict[str, list[str]] = {}
    for (repo, ref, path), label_ids in sorted(wanted.items()):
        source = sources[(repo, ref, path)]
        data = source.read_bytes()
        redacted: list[dict[str, Any]] = []
        if source in secrets:
            # A committed private key fails this repository's own secret scan and GitHub's push
            # protection whether or not it is a fixture. The secret is overwritten in place, so
            # every other line, and every label's line numbers, stay exactly as pinned.
            text, redacted = redact(data.decode("utf-8"), secrets[source])
            data = text.encode("utf-8")
        target = TREES / repo_dir(repo) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        root = snapshot_root(snapshots, repo, ref)
        for licence in nearest_licences(root, path):
            relative = licence.relative_to(root).as_posix()
            if relative in licences.get(repo, []):
                continue
            copy = LICENCES / repo_dir(repo) / relative
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(licence, copy)
            licences.setdefault(repo, []).append(relative)
        entry = {"repo": repo, "ref": ref, "path": path, "sha256": sha256(data), "labels": sorted(label_ids)}
        if redacted:
            entry["redacted"] = redacted
        files.append(entry)

    missing_licence = sorted({item["repo"] for item in files} - set(licences))
    if missing_licence:
        raise SystemExit(f"no licence file found above the labelled files of {', '.join(missing_licence)}")

    manifest = {
        "version": 1,
        "description": (
            "Files of the vulnerable corpus copied at their pinned ref, each under the "
            "licence of the repository it came from (licences/). Every file carries at least one "
            "label the recall baseline holds as hit. Secrets gitleaks reports are overwritten with x "
            "of the same length and listed under redacted. Generated by scripts/replay/fixture_subset.py "
            "build; do not edit by hand."
        ),
        "repositories": [
            {"repo": repo, "licence": licence_of[repo], "licence_files": sorted(paths)}
            for repo, paths in sorted(licences.items())
        ],
        "files": files,
        "not_permissive": sorted(refused_licence),
    }
    SUBSET.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    labels = sum(len(item["labels"]) for item in files)
    redactions = sum(len(item.get("redacted") or []) for item in files)
    print(f"wrote {MANIFEST}: {len(files)} files, {labels} labels, {redactions} secrets redacted")
    return EXIT_OK


# --- measuring ----------------------------------------------------------------------------------


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_problems(manifest: dict[str, Any], trees: Path = TREES, licences: Path = LICENCES) -> list[str]:
    """Every way the files on disk differ from what the manifest says was copied."""
    problems: list[str] = []
    licensed = {item["repo"] for item in manifest["repositories"] if item.get("licence_files")}
    for item in manifest["repositories"]:
        for relative in item.get("licence_files") or []:
            if not (licences / repo_dir(item["repo"]) / relative).is_file():
                problems.append(f"{item['repo']}: licence file {relative} is missing")
    listed: set[Path] = set()
    for item in manifest["files"]:
        target = trees / repo_dir(item["repo"]) / item["path"]
        listed.add(target)
        if item["repo"] not in licensed:
            problems.append(f"{item['repo']}/{item['path']}: no licence recorded for its repository")
        if not target.is_file():
            problems.append(f"{item['repo']}/{item['path']}: missing")
        elif sha256(target.read_bytes()) != item["sha256"]:
            problems.append(f"{item['repo']}/{item['path']}: differs from the pinned file")
    if trees.is_dir():
        for path in sorted(trees.rglob("*")):
            if path.is_file() and path not in listed:
                problems.append(f"{path.relative_to(trees).as_posix()}: on disk but not in the manifest")
    return problems


def subset_labels(manifest: dict[str, Any], labels_path: Path) -> list[dict[str, Any]]:
    ids = {label_id for item in manifest["files"] for label_id in item["labels"]}
    return [label for label in score.load_labels(str(labels_path)) if label["id"] in ids]


def measure(manifest: dict[str, Any], trees: Path = TREES) -> list[dict[str, Any]]:
    """One snapshot-shaped result document per repository, analysed in this process."""
    # What `ratchet.py measure` lifts for the full corpus, for the same reason: what a time
    # limit removes depends on the machine, and a missing finding here has to mean a rule.
    for name in ("TIER1_BUDGET_SECONDS", "TIER1_FILE_BUDGET_SECONDS",
                 "OPENGREP_RULE_TIMEOUT_SECONDS", "OPENGREP_PROCESS_TIMEOUT_SECONDS"):
        os.environ[name] = LIFTED_SECONDS
    os.environ["REPLAY_INCLUDE_QUARANTINED"] = "1"
    os.environ["LLM_TRIAGE_ENABLED"] = "false"

    import replay  # noqa: PLC0415
    import worker  # noqa: PLC0415

    documents: list[dict[str, Any]] = []
    refs = {item["repo"]: item["ref"] for item in manifest["files"]}
    for repo in sorted(refs):
        batches, _, _ = replay.snapshot_batches(trees / repo_dir(repo))
        records = []
        for index, batch in enumerate(batches, start=1):
            payload = {"repo": repo, "number": SUBSET_PULL_NUMBER, "head_sha": refs[repo], "files": batch}
            record = worker.run_analysis(payload)
            records.append({"snapshot_batch": index, "analysis": record, "findings": record["findings"]})
        documents.append({"repo": repo, "mode": "snapshot", "ref": refs[repo], "records": records})
    return documents


def run_state(documents: list[dict[str, Any]], labels: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    repositories = sorted({(label["repo"], label["ref"]) for label in labels})
    problems = ratchet.measurement_problems(documents, repositories)
    findings: list[dict[str, Any]] = []
    for document in documents:
        for record in document["records"]:
            for finding in record.get("findings") or []:
                findings.append({**finding, "_repo": document["repo"], "_ref": document["ref"], "_source_file": "subset"})
    _, label_state = score.join(findings, labels, {}, score.quarantined_rule_set())
    return ratchet.label_status(label_state), problems


def load_expected(path: Path = EXPECTED) -> tuple[dict[str, dict[str, Any]], int]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return dict(document["labels"]), int(document["summary"]["hit"])


def dump_expected(status: dict[str, dict[str, Any]]) -> str:
    text = ratchet.dump_baseline(status)
    return text.replace(
        "Recall ratchet baseline: for every label in labels.json,",
        "Recall floor over the committed fixture subset: for every label in fixture-subset/manifest.json,",
        1,
    ).replace("scripts/replay/ratchet.py update", "scripts/replay/fixture_subset.py update", 1)


def scanner_problem() -> str | None:
    from opengrep_runner import scanner_available  # noqa: PLC0415

    if not scanner_available():
        return "the scanner is not on PATH, so tier 2 would find nothing"
    return None


def evaluate(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    manifest = load_manifest(Path(args.manifest))
    problems = manifest_problems(manifest)
    labels = subset_labels(manifest, Path(args.labels))
    missing_scanner = scanner_problem()
    if missing_scanner:
        return {}, labels, problems + [missing_scanner]
    status, run_problems = run_state(measure(manifest), labels)
    return status, labels, problems + run_problems


def floor_message(hit: int, floor: int) -> str | None:
    if hit < floor:
        return f"{hit} labels hit, below the floor of {floor}"
    return None


def command_check(args: argparse.Namespace) -> int:
    status, labels, problems = evaluate(args)
    expected, floor = load_expected(Path(args.expected))
    if not status:
        print("recall floor: not measured", *[f"  {problem}" for problem in problems], "result: UNUSABLE", sep="\n")
        return EXIT_UNUSABLE
    comparison = ratchet.compare(expected, status)
    text = ratchet.render(comparison, expected, status, labels, problems)
    text = text.replace("recall ratchet:", "recall floor (committed subset):", 1)
    print(text.replace(ratchet.REFRESH_HINT, "scripts/replay/fixture_subset.py update"))
    below = floor_message(sum(1 for entry in status.values() if entry.get("hit")), floor)
    if below:
        print(f"FLOOR: {below}")
    code = ratchet.exit_status(comparison, problems)
    if code == EXIT_OK and below:
        code = EXIT_REGRESSED
    return code


def command_update(args: argparse.Namespace) -> int:
    status, _, problems = evaluate(args)
    if problems:
        print(f"update: refusing to write from an incomplete measurement ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_UNUSABLE
    Path(args.expected).write_text(dump_expected(status), encoding="utf-8")
    total, hit, posting = ratchet._counts(status)
    print(f"wrote {args.expected}: {hit}/{total} labels hit, {posting} by a posting rule")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="copy the subset out of a local snapshot cache")
    build.add_argument("--snapshots", required=True, help="the replay cache's snapshots directory")
    build.add_argument("--labels", default=str(ratchet.DEFAULT_LABELS))
    build.add_argument("--baseline", default=str(ratchet.DEFAULT_BASELINE))
    build.add_argument("--gitleaks", action="store_true", help="leave out every file gitleaks flags")
    build.set_defaults(run=command_build)

    for name, run, text in (
        ("check", command_check, "scan the subset and compare with expected.json"),
        ("update", command_update, "scan the subset and rewrite expected.json"),
    ):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("--labels", default=str(ratchet.DEFAULT_LABELS))
        sub.add_argument("--manifest", default=str(MANIFEST))
        sub.add_argument("--expected", default=str(EXPECTED))
        sub.set_defaults(run=run)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
