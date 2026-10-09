#!/usr/bin/env python3
"""Recall ratchet: a labelled vulnerability that is detected today cannot silently stop being detected.

    scripts/replay/ratchet.py measure --results results/
    scripts/replay/ratchet.py check results/
    scripts/replay/ratchet.py update results/

The precision benchmarks hold every hand-judged false positive and one true positive per rule
family, so a rule change that loses nine of a rule's ten real detections passes them. This is
the other half. `benchmarks/vulnerable-corpus/recall-baseline.json` records, for every label
in `labels.json`, whether a finding of an expected class lands on the labelled lines and
whether one of those findings comes from a rule that is allowed to post. `check` joins a fresh
snapshot run to the labels with `score.join`, the same join the published recall number is
made by, and compares.

Two things fail the check, and they are reported separately because they are different
losses:

* a label the baseline records as hit that no finding hits now;
* a label the baseline records as hit by a posting rule that only a quarantined rule hits now,
  which is what quarantining a rule, or narrowing the posting one beside it, looks like here.

A label that is newly hit, or newly hit by a posting rule, is reported as an improvement and
does not fail. It is not protected until the baseline is refreshed with `update`, which is
also how a deliberate loss is accepted: the baseline's diff then shows the label in review.

Exit status: 0 when nothing regressed, 1 when a label regressed, 2 when the comparison cannot
be trusted (a repository was not measured, a batch died, or the baseline and `labels.json`
name different labels). A run that lost a batch to a timeout looks exactly like a rule that
stopped matching, so it is refused rather than reported as a regression.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import score  # noqa: E402

CORPUS = REPO_ROOT / "benchmarks" / "vulnerable-corpus"
DEFAULT_LABELS = CORPUS / "labels.json"
DEFAULT_BASELINE = CORPUS / "recall-baseline.json"
BASELINE_VERSION = 1

EXIT_OK = 0
EXIT_REGRESSED = 1
EXIT_UNUSABLE = 2

REFRESH_HINT = "make recall-baseline, or scripts/replay/ratchet.py update <results>"


# --- the state of one run -----------------------------------------------------------------------


def label_status(label_state: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """What the ratchet holds per label, out of `score.join`'s label state.

    `hit` is the scorer's own definition: a finding of an expected class overlapping the
    labelled lines. `posting_hit` is the same with quarantined rules left out, which is what
    a reviewer is shown. The rule ids are carried so a failure can say what used to match.
    """
    status: dict[str, dict[str, Any]] = {}
    for label_id, state in label_state.items():
        posting = sorted({row["rule_id"] for row in state["hits"] if row["posting"] == "post"})
        quarantined = sorted({row["rule_id"] for row in state["hits"] if row["posting"] != "post"})
        status[label_id] = {
            "hit": bool(posting or quarantined),
            "posting_hit": bool(posting),
            "posting_rules": posting,
            "quarantined_rules": quarantined,
        }
    return status


def measurement_problems(
    documents: list[dict[str, Any]],
    repositories: Iterable[tuple[str, str]],
) -> list[str]:
    """Every reason this run is not a measurement of the whole corpus.

    A missing repository and a batch that died both remove findings, and removed findings are
    what a regression is made of.
    """
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for document in documents:
        by_repo.setdefault(str(document.get("repo") or ""), []).append(document)

    problems: list[str] = []
    for repo, ref in repositories:
        runs = by_repo.get(repo, [])
        if not runs:
            problems.append(f"{repo}: no result file")
            continue
        if len(runs) > 1:
            problems.append(f"{repo}: {len(runs)} result files, expected one")
        for document in runs:
            if document.get("mode") != "snapshot":
                problems.append(f"{repo}: not a snapshot run")
            if document.get("ref") != ref:
                problems.append(f"{repo}: measured at {document.get('ref')}, labels pin {ref}")
            records = document.get("records") or []
            if not records:
                problems.append(f"{repo}: no batch was analysed")
            for record in records:
                batch = record.get("snapshot_batch", record.get("number"))
                fatal = record.get("fatal")
                if fatal:
                    problems.append(f"{repo}: batch {batch} died ({fatal.get('kind')})")
                    continue
                analysis = record.get("analysis") or {}
                for tier in ("tier1", "tier2"):
                    stage = analysis.get(tier) or {}
                    if stage.get("ok") is not True:
                        reason = stage.get("error_type") or "no result"
                        problems.append(f"{repo}: batch {batch} {tier} failed ({reason})")
    return problems


def scanner_limitations(documents: list[dict[str, Any]]) -> dict[tuple[str, str], list[str]]:
    """Per (repo, path), the kinds of limitation tier 2 reported for that file.

    A per-file scanner timeout is tolerated by the service and recorded rather than raised, so
    the run is complete and a label in that file is still missed. Naming it beside the label
    is the difference between reading a rule diff and re-running the job.
    """
    found: dict[tuple[str, str], list[str]] = {}
    for document in documents:
        repo = str(document.get("repo") or "")
        for record in document.get("records") or []:
            tier2 = (record.get("analysis") or {}).get("tier2") or {}
            for limitation in tier2.get("analysis_limitations") or []:
                kinds = found.setdefault((repo, str(limitation.get("path") or "")), [])
                kind = str(limitation.get("type") or limitation.get("kind") or "limitation")
                if kind not in kinds:
                    kinds.append(kind)
    return found


# --- the comparison -----------------------------------------------------------------------------


@dataclass
class Comparison:
    lost: list[str] = field(default_factory=list)          # hit before, no finding now
    demoted: list[str] = field(default_factory=list)       # posting hit before, quarantined only now
    gained: list[str] = field(default_factory=list)        # missed before, hit now
    promoted: list[str] = field(default_factory=list)      # quarantined only before, posting now
    unbaselined: list[str] = field(default_factory=list)   # in labels.json, not in the baseline
    stale: list[str] = field(default_factory=list)         # in the baseline, not in labels.json

    @property
    def regressed(self) -> bool:
        return bool(self.lost or self.demoted)

    @property
    def out_of_step(self) -> bool:
        return bool(self.unbaselined or self.stale)

    @property
    def improved(self) -> bool:
        return bool(self.gained or self.promoted)


def compare(baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> Comparison:
    """Compare two label states. Only `hit` and `posting_hit` decide anything."""
    result = Comparison()
    for label_id in sorted(set(baseline) | set(current)):
        before = baseline.get(label_id)
        now = current.get(label_id)
        if before is None:
            result.unbaselined.append(label_id)
            continue
        if now is None:
            result.stale.append(label_id)
            continue
        was_hit, was_posting = bool(before.get("hit")), bool(before.get("posting_hit"))
        is_hit, is_posting = bool(now.get("hit")), bool(now.get("posting_hit"))
        if was_hit and not is_hit:
            result.lost.append(label_id)
        elif was_posting and not is_posting:
            result.demoted.append(label_id)
        elif not was_hit and is_hit:
            result.gained.append(label_id)
        elif is_posting and not was_posting:
            result.promoted.append(label_id)
    return result


def _rules(entry: dict[str, Any] | None) -> str:
    entry = entry or {}
    names = list(entry.get("posting_rules") or []) + [
        f"{rule} (quarantined)" for rule in entry.get("quarantined_rules") or []
    ]
    return ", ".join(names) or "nothing"


def _counts(status: dict[str, dict[str, Any]]) -> tuple[int, int, int]:
    return (
        len(status),
        sum(1 for entry in status.values() if entry.get("hit")),
        sum(1 for entry in status.values() if entry.get("posting_hit")),
    )


def render(
    comparison: Comparison,
    baseline: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    labels: list[dict[str, Any]],
    problems: list[str],
    limitations: dict[tuple[str, str], list[str]] | None = None,
) -> str:
    by_id = {label["id"]: label for label in labels}
    limitations = limitations or {}

    def where(label_id: str) -> str:
        label = by_id.get(label_id)
        if label is None:
            return ""
        text = f" {label['repo']} {label['path']}:{label['line_range'][0]}-{label['line_range'][1]}"
        kinds = limitations.get((label["repo"], label["path"]))
        if kinds:
            text += f" [scanner limitation on this file: {', '.join(kinds)}]"
        return text

    total, hit, posting = _counts(current)
    base_total, base_hit, base_posting = _counts(baseline)
    lines = [
        f"recall ratchet: {hit}/{total} labels hit, {posting} by a posting rule "
        f"(baseline {base_hit}/{base_total}, {base_posting})",
    ]
    if problems:
        lines.append("")
        lines.append(f"INCOMPLETE MEASUREMENT ({len(problems)}): the comparison below cannot be trusted")
        lines += [f"  {problem}" for problem in problems]
    if comparison.lost:
        lines.append("")
        lines.append(f"REGRESSION, no longer hit ({len(comparison.lost)}):")
        lines += [
            f"  {label_id}{where(label_id)}: was hit by {_rules(baseline.get(label_id))}"
            for label_id in comparison.lost
        ]
    if comparison.demoted:
        lines.append("")
        lines.append(f"REGRESSION, now hit only by a quarantined rule ({len(comparison.demoted)}):")
        lines += [
            f"  {label_id}{where(label_id)}: was hit by {_rules(baseline.get(label_id))}, "
            f"now by {_rules(current.get(label_id))}"
            for label_id in comparison.demoted
        ]
    if comparison.unbaselined:
        lines.append("")
        lines.append(f"NOT IN THE BASELINE ({len(comparison.unbaselined)}): labels.json has labels the baseline does not")
        lines += [f"  {label_id}" for label_id in comparison.unbaselined]
    if comparison.stale:
        lines.append("")
        lines.append(f"NOT IN labels.json ({len(comparison.stale)}): the baseline has labels that no longer exist")
        lines += [f"  {label_id}" for label_id in comparison.stale]
    if comparison.gained:
        lines.append("")
        lines.append(f"improvement, newly hit ({len(comparison.gained)}):")
        lines += [
            f"  {label_id}{where(label_id)}: now hit by {_rules(current.get(label_id))}"
            for label_id in comparison.gained
        ]
    if comparison.promoted:
        lines.append("")
        lines.append(f"improvement, now hit by a posting rule ({len(comparison.promoted)}):")
        lines += [
            f"  {label_id}{where(label_id)}: now hit by {_rules(current.get(label_id))}"
            for label_id in comparison.promoted
        ]

    lines.append("")
    if problems or comparison.out_of_step:
        lines.append("result: UNUSABLE")
        if comparison.out_of_step:
            lines.append(f"The baseline and labels.json must name the same labels. Refresh it: {REFRESH_HINT}")
    elif comparison.regressed:
        lines.append("result: FAIL")
        lines.append(
            "A label that was detected is not detected now. Fix the rule, or if the loss is "
            f"intended, refresh the baseline so the diff shows it: {REFRESH_HINT}"
        )
    else:
        lines.append("result: PASS")
        if comparison.improved:
            lines.append(f"The improvements are not protected until the baseline is refreshed: {REFRESH_HINT}")
    return "\n".join(lines)


def exit_status(comparison: Comparison, problems: list[str]) -> int:
    if problems or comparison.out_of_step:
        return EXIT_UNUSABLE
    return EXIT_REGRESSED if comparison.regressed else EXIT_OK


# --- the baseline file --------------------------------------------------------------------------


def load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("version") != BASELINE_VERSION:
        raise SystemExit(f"{path}: baseline version {document.get('version')!r}, expected {BASELINE_VERSION}")
    return dict(document["labels"])


def dump_baseline(status: dict[str, dict[str, Any]]) -> str:
    """One label per line and sorted, so a refresh is a diff a reviewer can read."""
    total, hit, posting = _counts(status)
    head = {
        "version": BASELINE_VERSION,
        "description": (
            "Recall ratchet baseline: for every label in labels.json, whether a finding of an "
            "expected class lands on the labelled lines (hit) and whether one comes from a rule "
            "that is allowed to post (posting_hit). Generated by scripts/replay/ratchet.py update; "
            "do not edit by hand. The rule ids are what matched when it was written and decide "
            "nothing."
        ),
        "summary": {"labels": total, "hit": hit, "posting_hit": posting},
    }
    lines = [json.dumps(head, indent=2)[:-2] + ",", '  "labels": {']
    entries = [
        f"    {json.dumps(label_id)}: {json.dumps(status[label_id], sort_keys=True)}"
        for label_id in sorted(status)
    ]
    lines.append(",\n".join(entries))
    lines += ["  }", "}", ""]
    return "\n".join(lines)


# --- commands -----------------------------------------------------------------------------------


def result_files(arguments: Iterable[str]) -> list[str]:
    """Result files, with a directory standing for every `.json` directly inside it."""
    files: list[str] = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            files += sorted(str(child) for child in path.glob("*.json"))
        else:
            files.append(str(path))
    return files


def corpus_repositories(labels_path: Path) -> list[tuple[str, str]]:
    document = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    pinned = {(label["repo"], label["ref"]) for label in document["labels"]}
    return sorted(pinned)


def current_state(
    files: list[str], labels_path: Path
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[str], dict[tuple[str, str], list[str]]]:
    labels = score.load_labels(str(labels_path))
    documents = [json.loads(Path(path).read_text(encoding="utf-8")) for path in files]
    problems = measurement_problems(documents, corpus_repositories(labels_path))
    findings = score.load_results(
        path for path, document in zip(files, documents) if document.get("mode") == "snapshot"
    )
    _, label_state = score.join(findings, labels, {}, score.quarantined_rule_set())
    return label_status(label_state), labels, problems, scanner_limitations(documents)


def command_measure(args: argparse.Namespace) -> int:
    """One snapshot run per repository, each in its own process, into `--results`."""
    out_dir = Path(args.results)
    out_dir.mkdir(parents=True, exist_ok=True)
    failed: list[str] = []
    for repo, ref in corpus_repositories(Path(args.labels)):
        if args.repo and repo not in args.repo:
            continue
        out = out_dir / f"{repo.replace('/', '__')}.json"
        # A result left over from an earlier run would be scored as this one's.
        out.unlink(missing_ok=True)
        command = [
            args.python, str(HERE / "replay.py"), "--snapshot", "--include-quarantined",
            "--no-remediation", "--repo", repo, "--ref", ref, "--out", str(out),
            "--cache", args.cache, "--timeout", str(args.timeout),
        ]
        if subprocess.run(command, check=False).returncode != 0 or not out.exists():
            failed.append(repo)
    if failed:
        print(f"measure: {len(failed)} repositories produced no result: {', '.join(failed)}", file=sys.stderr)
        return EXIT_UNUSABLE
    return EXIT_OK


def command_check(args: argparse.Namespace) -> int:
    current, labels, problems, limitations = current_state(result_files(args.results), Path(args.labels))
    baseline = load_baseline(Path(args.baseline))
    comparison = compare(baseline, current)
    print(render(comparison, baseline, current, labels, problems, limitations))
    return exit_status(comparison, problems)


def command_update(args: argparse.Namespace) -> int:
    current, labels, problems, limitations = current_state(result_files(args.results), Path(args.labels))
    baseline_path = Path(args.baseline)
    baseline = load_baseline(baseline_path) if baseline_path.exists() else {}
    if problems:
        print(f"update: refusing to write a baseline from an incomplete measurement ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_UNUSABLE
    if baseline:
        # Shown before the file changes, so a refresh that accepts a loss says so in the log
        # as well as in the diff.
        print(render(compare(baseline, current), baseline, current, labels, [], limitations))
        print()
    baseline_path.write_text(dump_baseline(current), encoding="utf-8")
    total, hit, posting = _counts(current)
    print(f"wrote {baseline_path}: {hit}/{total} labels hit, {posting} by a posting rule")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    measure = commands.add_parser("measure", help="run the snapshot measurement over every corpus repository")
    measure.add_argument("--results", required=True, help="directory the per-repository result files are written to")
    measure.add_argument("--labels", default=str(DEFAULT_LABELS))
    measure.add_argument("--cache", default=str(HERE / ".cache"), help="the replay cache; snapshots go under it")
    measure.add_argument("--timeout", type=int, default=600, help="per-batch wall clock, seconds")
    measure.add_argument("--python", default=sys.executable, help="interpreter for replay.py and its workers")
    measure.add_argument("--repo", action="append", help="measure only this repository (repeatable)")
    measure.set_defaults(run=command_measure)

    for name, run, text in (
        ("check", command_check, "compare a run with the baseline; nonzero when a label regressed"),
        ("update", command_update, "write the baseline from a complete run"),
    ):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("results", nargs="+", help="snapshot result files, or a directory of them")
        sub.add_argument("--labels", default=str(DEFAULT_LABELS))
        sub.add_argument("--baseline", default=str(DEFAULT_BASELINE))
        sub.set_defaults(run=run)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
