#!/usr/bin/env python3
"""Join snapshot findings to the vulnerable-corpus labels and report precision and recall.

    scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
        --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md

A label is a line range in a file at a pinned ref that is known to contain a vulnerability,
and the classes a correct scanner could report for it. A finding is joined to a label when
the repository, the ref and the path agree and the line ranges overlap.

That join answers recall directly: a label no finding overlaps is a vulnerability the rule
set missed. It does not answer precision, because these repositories contain far more
vulnerabilities than anybody has labelled, so an unlabelled finding is unknown rather than
wrong. Precision is therefore computed over the *adjudicated* findings only: the ones a
label confirms, plus the ones someone read by hand. `--emit-queue` writes the reading list
and `--adjudications` reads the verdicts back.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ANALYSIS_SRC = REPO_ROOT / "services" / "analysis-service" / "src"
if str(ANALYSIS_SRC) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_SRC))

from taxonomy import CANONICAL_INTERNAL_TYPES, canonicalize_internal_type  # noqa: E402

DEFAULT_SAMPLE = 40
DEFAULT_SEED = 20260924
# A label is a hand-written line range and a finding is a scanner's line range; they agree
# about the statement without agreeing about its first line. Two lines of slack is the
# width of a wrapped call, and no two labels in this corpus are that close together.
LINE_SLACK = 2

LANGUAGE_BY_EXTENSION = {
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".py": "Python",
}


def language_of(path: str) -> str:
    suffix = "." + str(path).rsplit(".", 1)[-1].lower() if "." in str(path) else ""
    return LANGUAGE_BY_EXTENSION.get(suffix, "other")


def finding_class(finding: dict[str, Any]) -> str:
    """The class a finding claims, in the label vocabulary.

    A rule that declares a canonical `internal_type` has answered this. A rule that passes
    its own check id, which every pre-existing tier 2 rule in `javascript.yml` and
    `python.yml` still does, has not: for those the CWE decides, through the service's own
    canonicaliser with the declared type withheld.
    """
    declared = finding.get("internal_type")
    if declared in CANONICAL_INTERNAL_TYPES:
        return str(declared)
    return canonicalize_internal_type(
        rule_id=finding.get("rule_id"),
        category=finding.get("category"),
        explicit=None,
        cwe_id=finding.get("cwe_id"),
        title=finding.get("title"),
        description=finding.get("description"),
        file_path=finding.get("file_path"),
        code_snippet=finding.get("code_snippet"),
    )


def overlaps(first: tuple[int, int], second: tuple[int, int], slack: int = LINE_SLACK) -> bool:
    return first[0] - slack <= second[1] and second[0] - slack <= first[1]


# --- loading ----------------------------------------------------------------------------------


def load_results(paths: Iterable[str]) -> list[dict[str, Any]]:
    """Every finding of every snapshot run, tagged with the run it came from."""
    findings: list[dict[str, Any]] = []
    for path in paths:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        repo = document.get("repo", "")
        ref = document.get("ref", "")
        if document.get("mode") != "snapshot":
            raise SystemExit(f"{path}: not a snapshot run; score.py joins labels to trees, not to pull requests")
        for record in document.get("records") or []:
            for finding in record.get("findings") or []:
                entry = dict(finding)
                entry["_repo"] = repo
                entry["_ref"] = ref
                entry["_source_file"] = str(path)
                findings.append(entry)
    return findings


def load_labels(path: str) -> list[dict[str, Any]]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    labels = document["labels"] if isinstance(document, dict) else document
    for index, label in enumerate(labels):
        for required in ("repo", "ref", "path", "line_range", "cwe", "rule_classes_expected"):
            if required not in label:
                raise SystemExit(f"label {index} ({label.get('id')}) has no {required!r}")
        unknown = set(label["rule_classes_expected"]) - set(CANONICAL_INTERNAL_TYPES)
        if unknown:
            raise SystemExit(f"label {label.get('id')} expects unknown classes {sorted(unknown)}")
    return labels


def load_adjudications(path: str | None) -> dict[str, dict[str, Any]]:
    if not path or not Path(path).exists():
        return {}
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = document["adjudications"] if isinstance(document, dict) else document
    if isinstance(entries, list):
        return {str(item["fingerprint"]): item for item in entries}
    return {str(key): value for key, value in entries.items()}


# --- joining ----------------------------------------------------------------------------------


def join(
    findings: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    adjudications: dict[str, dict[str, Any]],
    quarantined: set[str],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Give every finding a verdict and every label the findings that hit it."""
    by_location: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    label_state: dict[str, dict[str, Any]] = {}
    for label in labels:
        key = (label["repo"], label["ref"], label["path"])
        by_location[key].append(label)
        label_state[label["id"]] = {"label": label, "hits": [], "location_hits": []}

    # A tier 1 rule reports one finding per file, so a file with three weak hashes in it
    # produces one comment on the first. Joining by line range calls the other two missed,
    # which is right for the reviewer and misleading about the rule, so the two are
    # separated: a label is "hit" only on an overlap, and "in file" when the expected class
    # was reported somewhere else in the same file.
    classes_by_file: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for finding in findings:
        classes_by_file[
            (finding["_repo"], finding["_ref"], str(finding.get("file_path") or ""))
        ].add(finding_class(finding))
    for state in label_state.values():
        label = state["label"]
        reported = classes_by_file.get((label["repo"], label["ref"], label["path"]), set())
        state["in_file"] = bool(reported & set(label["rule_classes_expected"]))

    scored: list[dict[str, Any]] = []
    for finding in findings:
        key = (finding["_repo"], finding["_ref"], str(finding.get("file_path") or ""))
        span = (
            int(finding.get("line_start") or 1),
            int(finding.get("line_end") or finding.get("line_start") or 1),
        )
        claimed = finding_class(finding)
        matched_class: dict[str, Any] | None = None
        matched_location: dict[str, Any] | None = None
        for label in by_location.get(key, []):
            if not overlaps(span, (int(label["line_range"][0]), int(label["line_range"][1]))):
                continue
            if claimed in label["rule_classes_expected"]:
                matched_class = matched_class or label
            matched_location = matched_location or label

        fingerprint = str(finding.get("fingerprint") or "")
        adjudication = adjudications.get(fingerprint)
        entry = {
            "fingerprint": fingerprint,
            "rule_id": str(finding.get("rule_id") or ""),
            "tier": 2 if str(finding.get("rule_id") or "").startswith("opengrep.") else 1,
            "posting": "quarantine" if str(finding.get("rule_id") or "") in quarantined else "post",
            "cwe": str(finding.get("cwe_id") or ""),
            "claimed_class": claimed,
            "repo": finding["_repo"],
            "path": str(finding.get("file_path") or ""),
            "language": language_of(finding.get("file_path") or ""),
            "line_start": span[0],
            "line_end": span[1],
            "snippet": str(finding.get("code_snippet") or "")[:200],
            "in_test_code": bool(finding.get("in_test_code")),
            "label_id": (matched_class or matched_location or {}).get("id"),
        }

        if matched_class is not None:
            entry["verdict"] = "true"
            entry["verdict_source"] = "label"
            label_state[matched_class["id"]]["hits"].append(entry)
        elif adjudication is not None:
            entry["verdict"] = str(adjudication.get("verdict", "")).lower()
            entry["verdict_source"] = "hand-read"
            entry["note"] = str(adjudication.get("note", ""))
        else:
            entry["verdict"] = "unread"
            entry["verdict_source"] = "class_mismatch" if matched_location else "unlabelled"
        if matched_location is not None:
            label_state[matched_location["id"]]["location_hits"].append(entry)
        scored.append(entry)

    return scored, label_state


# --- reporting --------------------------------------------------------------------------------


def _precision(rows: list[dict[str, Any]]) -> tuple[int, int, float | None]:
    true_count = sum(1 for row in rows if row["verdict"] == "true")
    false_count = sum(1 for row in rows if row["verdict"] == "false")
    total = true_count + false_count
    return true_count, false_count, (true_count / total if total else None)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def group_table(title: str, scored: list[dict[str, Any]], key: str, header: str) -> list[str]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in scored:
        groups[str(row[key])].append(row)
    lines = [f"### {title}", "", f"| {header} | Findings | Labelled true | Hand true | Hand false | Unread | Precision |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name in sorted(groups, key=lambda item: (-len(groups[item]), item)):
        rows = groups[name]
        labelled = sum(1 for row in rows if row["verdict_source"] == "label")
        hand_true = sum(1 for row in rows if row["verdict"] == "true" and row["verdict_source"] == "hand-read")
        hand_false = sum(1 for row in rows if row["verdict"] == "false")
        unread = sum(1 for row in rows if row["verdict"] == "unread")
        _, _, precision = _precision(rows)
        lines.append(
            f"| `{name}` | {len(rows)} | {labelled} | {hand_true} | {hand_false} | {unread} | {_fmt(precision)} |"
        )
    lines.append("")
    return lines


def recall_table(title: str, label_state: dict[str, dict[str, Any]], key) -> list[str]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for state in label_state.values():
        groups[str(key(state["label"]))].append(state)
    lines = [f"### {title}", "",
             "| Group | Labels | Hit | In file | Located only | Missed | Recall |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name in sorted(groups):
        states = groups[name]
        hit = sum(1 for state in states if state["hits"])
        in_file = sum(1 for state in states if not state["hits"] and state.get("in_file"))
        located = sum(
            1 for state in states
            if not state["hits"] and not state.get("in_file") and state["location_hits"]
        )
        missed = len(states) - hit - in_file - located
        lines.append(
            f"| `{name}` | {len(states)} | {hit} | {in_file} | {located} | {missed} | "
            f"{hit / len(states):.2f} |"
        )
    lines.append("")
    return lines


def render(
    scored: list[dict[str, Any]],
    label_state: dict[str, dict[str, Any]],
    labels: list[dict[str, Any]],
) -> str:
    posting = [row for row in scored if row["posting"] == "post"]
    quarantined = [row for row in scored if row["posting"] == "quarantine"]
    hit = sum(1 for state in label_state.values() if state["hits"])
    in_file = sum(1 for state in label_state.values() if not state["hits"] and state.get("in_file"))
    located = sum(
        1 for state in label_state.values()
        if not state["hits"] and not state.get("in_file") and state["location_hits"]
    )

    lines = [
        "# Vulnerable corpus score", "",
        f"{len(labels)} labels, {len(scored)} findings.", "",
        "## Headline", "",
        "| | Findings | Labelled true | Hand true | Hand false | Precision |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, rows in (("What posts today", posting), ("Quarantined rules", quarantined), ("Everything", scored)):
        labelled = sum(1 for row in rows if row["verdict_source"] == "label")
        hand_true = sum(1 for row in rows if row["verdict"] == "true" and row["verdict_source"] == "hand-read")
        hand_false = sum(1 for row in rows if row["verdict"] == "false")
        _, _, precision = _precision(rows)
        lines.append(f"| {name} | {len(rows)} | {labelled} | {hand_true} | {hand_false} | {_fmt(precision)} |")
    lines += [
        "",
        f"Recall: {hit}/{len(labels)} labelled vulnerabilities produced a finding of the expected class "
        f"on the labelled lines ({hit / len(labels):.2f}). A further {in_file} had the expected class "
        f"reported elsewhere in the same file, and {located} were reported on the labelled lines under "
        "a different class.",
        "",
    ]

    lines += ["## Precision", ""]
    lines += group_table("By rule", scored, "rule_id", "Rule")
    lines += group_table("By class", scored, "claimed_class", "Class")
    lines += group_table("By language", scored, "language", "Language")
    lines += ["## Recall", ""]
    lines += recall_table("By expected class", label_state, lambda label: label["rule_classes_expected"][0])
    lines += recall_table("By CWE", label_state, lambda label: label["cwe"])
    lines += recall_table("By repository", label_state, lambda label: label["repo"])

    missed = [state for state in label_state.values() if not state["hits"]]
    if missed:
        lines += ["### Labels with no finding of the expected class on the labelled lines", "",
                  "| Label | Repository | Path | Lines | Expected | Reported instead | In file |",
                  "| --- | --- | --- | ---: | --- | --- | --- |"]
        for state in sorted(missed, key=lambda item: item["label"]["id"]):
            label = state["label"]
            instead = ", ".join(sorted({row["claimed_class"] for row in state["location_hits"]})) or "nothing"
            lines.append(
                f"| `{label['id']}` | {label['repo']} | `{label['path']}` | "
                f"{label['line_range'][0]}-{label['line_range'][1]} | "
                f"{', '.join(label['rule_classes_expected'])} | {instead} | "
                f"{'yes' if state.get('in_file') else 'no'} |"
            )
        lines.append("")
    return "\n".join(lines)


def emit_queue(scored: list[dict[str, Any]], path: str, sample: int, seed: int) -> int:
    """The reading list: every class mismatch, plus a seeded random sample of the unlabelled."""
    mismatches = [row for row in scored if row["verdict"] == "unread" and row["verdict_source"] == "class_mismatch"]
    unlabelled = [row for row in scored if row["verdict"] == "unread" and row["verdict_source"] == "unlabelled"]
    rng = random.Random(seed)
    chosen = sorted(unlabelled, key=lambda row: row["fingerprint"])
    rng.shuffle(chosen)
    queue = mismatches + chosen[:sample]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({
        "seed": seed,
        "sample": sample,
        "unlabelled_total": len(unlabelled),
        "class_mismatch_total": len(mismatches),
        "queue": queue,
    }, indent=2), encoding="utf-8")
    return len(queue)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", help="snapshot result JSON files")
    parser.add_argument("--labels", required=True, help="benchmarks/vulnerable-corpus/labels.json")
    parser.add_argument("--adjudications", help="hand-read verdicts, keyed by fingerprint")
    parser.add_argument("--emit-queue", help="write the hand-reading list here and stop")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE, help="unlabelled findings to sample")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="sampling seed, so the sample is repeatable")
    parser.add_argument("--json-out", help="also write the scored findings as JSON")
    parser.add_argument("--out", help="write the markdown report here instead of stdout")
    args = parser.parse_args()

    findings = load_results(args.results)
    labels = load_labels(args.labels)
    adjudications = load_adjudications(args.adjudications)

    sys.path.insert(0, str(ANALYSIS_SRC))
    # The same two sources `main.QUARANTINED_RULE_IDS` unions, read without importing the
    # FastAPI app: the YAML metadata for tier 2 and the rule objects for tier 1.
    from opengrep_runner import quarantined_rule_ids  # noqa: PLC0415
    from security_rules import POSTING_QUARANTINE, SECURITY_RULES  # noqa: PLC0415

    quarantined = set(quarantined_rule_ids()) | {
        rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE
    }
    scored, label_state = join(findings, labels, adjudications, quarantined)

    if args.emit_queue:
        count = emit_queue(scored, args.emit_queue, args.sample, args.seed)
        print(f"wrote {count} findings to read to {args.emit_queue}")
        return 0

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(
            {"findings": scored, "labels": [
                {"id": key, "hits": len(state["hits"]), "location_hits": len(state["location_hits"])}
                for key, state in label_state.items()
            ]}, indent=2), encoding="utf-8")

    report = render(scored, label_state, labels)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
