#!/usr/bin/env python3
"""Model-proposed verdicts for corpus findings no label or human has judged, kept apart from the human file.

    # propose verdicts for unjudged findings (and, with --calibrate, re-judge the 71 human ones)
    adjudicate.py propose results/*.json [--calibrate | --calibration-only] [--limit N]
    # agreement with the human verdicts: Cohen's kappa and a confusion table
    adjudicate.py report
    # a person copies model verdicts they have read into the human file
    adjudicate.py accept <fingerprint>... --reviewer NAME

`adjudications.json` is hand-read and stays that way: this script never writes it except under
`accept`, which needs `--reviewer` and copies only the entries named. Every model verdict goes
to `adjudications-model.json` with `source: model`, the provider and model id, and the prompt
version, so a reader can tell which verdicts a person stands behind.

The model is asked, through the analysis service's `call_llm`, for three things: a verdict
(`true`, `false` or `unsure`), a quote copied from the flagged line, and one sentence. The quote
is checked against the line in the pinned tree. A verdict whose quote is not on the line is kept
with `quote_on_line: false` and is neither counted in the agreement nor accepted, because a
model that cannot point at the code it judged has not shown it read it.

`--calibrate` also sends the 71 findings of the original hand-read sample (every
`class_mismatch` and the seeded `unlabelled` sample of 40) that still appear in the results.
`report` compares the model with the human verdicts on those and prints Cohen's kappa over the
pairs where the model said `true` or `false`, the confusion table, and how many it declined.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
REPLAY = REPO_ROOT / "scripts" / "replay"
ANALYSIS_SRC = REPO_ROOT / "services" / "analysis-service" / "src"
for entry in (str(REPLAY), str(ANALYSIS_SRC)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import score  # noqa: E402

LABELS = HERE / "labels.json"
HUMAN = HERE / "adjudications.json"
MODEL = HERE / "adjudications-model.json"
DEFAULT_SNAPSHOTS = REPLAY / ".cache" / "snapshots"

PROMPT_VERSION = "adjudicate-v1"
CALIBRATION_SAMPLES = ("class_mismatch", "unlabelled")
VERDICTS = ("true", "false", "unsure")
CONTEXT_LINES = 15
TIMEOUT_SECONDS = 60

SYSTEM_PROMPT = """You review one finding from a static security scanner against the code it points at.

A finding is true when it names a defect a reviewer would act on in a security review of that
line. A speculative runtime failure in code that cannot reach the claimed state is false. Say
unsure only when the code shown cannot settle it.

Answer with one JSON object and nothing else:
{"verdict": "true" | "false" | "unsure",
 "quote": "<text copied exactly from the flagged line or lines, at least a few characters>",
 "reason": "<one sentence>"}"""

Caller = Callable[..., Any]


# --- inputs -------------------------------------------------------------------------------------


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_model_file(path: Path = MODEL) -> dict[str, Any]:
    if not Path(path).exists():
        return {
            "version": 1,
            "description": (
                "Model-proposed verdicts on vulnerable-corpus findings, written by "
                "benchmarks/vulnerable-corpus/adjudicate.py. Not hand-read: a verdict here counts "
                "for nothing until a person accepts it into adjudications.json with --reviewer. "
                "Entries with calibration: true re-judge findings a person already judged, so the "
                "two can be compared."
            ),
            "adjudications": [],
        }
    return load_json(path)


def dump_model_file(document: dict[str, Any], path: Path = MODEL) -> None:
    document["adjudications"] = sorted(document["adjudications"], key=lambda item: item["fingerprint"])
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def tree_lines(snapshots: Path, repo: str, ref: str, path: str) -> list[str] | None:
    base = snapshots / repo.replace("/", "__") / ref
    if not base.is_dir():
        return None
    for tree in sorted(child for child in base.iterdir() if child.is_dir()):
        target = tree / path
        if target.is_file():
            return target.read_text(encoding="utf-8", errors="replace").splitlines()
    return None


def candidates(
    findings: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    human: list[dict[str, Any]],
    model: list[dict[str, Any]],
    calibrate: bool,
) -> list[tuple[dict[str, Any], bool]]:
    """(finding, is_calibration) for every finding the model should be asked about, in a fixed order."""
    by_human = {item["fingerprint"]: item for item in human}
    asked = {item["fingerprint"] for item in model}
    calibration = {item["fingerprint"] for item in human if item.get("sampled_as") in CALIBRATION_SAMPLES}
    scored, _ = score.join(findings, labels, {}, set())
    by_fingerprint = {str(finding.get("fingerprint") or ""): finding for finding in findings}

    chosen: list[tuple[dict[str, Any], bool]] = []
    seen: set[str] = set()
    for row in sorted(scored, key=lambda item: (item["repo"], item["path"], item["line_start"], item["rule_id"], item["fingerprint"])):
        fingerprint = row["fingerprint"]
        if not fingerprint or fingerprint in seen or fingerprint in asked:
            continue
        seen.add(fingerprint)
        if row["verdict_source"] == "label":
            continue
        if fingerprint in by_human:
            if calibrate and fingerprint in calibration:
                chosen.append((by_fingerprint[fingerprint], True))
            continue
        chosen.append((by_fingerprint[fingerprint], False))
    return chosen


# --- asking -------------------------------------------------------------------------------------


def where(finding: dict[str, Any]) -> str:
    return f"{finding['_repo']} {finding.get('file_path')}:{finding.get('line_start')}"


def flagged_span(finding: dict[str, Any]) -> tuple[int, int]:
    start = int(finding.get("line_start") or 1)
    end = int(finding.get("line_end") or start)
    return start, max(start, end)


def user_prompt(finding: dict[str, Any], lines: list[str] | None) -> str:
    start, end = flagged_span(finding)
    head = [
        f"Rule: {finding.get('rule_id')}",
        f"Claimed weakness: {finding.get('internal_type')} ({finding.get('cwe_id')})",
        f"Scanner message: {finding.get('title')}",
        f"File: {finding.get('file_path')}",
        f"Flagged lines: {start}-{end}",
        "",
    ]
    if lines is None:
        return "\n".join(head + ["Only the snippet is available:", str(finding.get("code_snippet") or "")])
    first = max(1, start - CONTEXT_LINES)
    last = min(len(lines), end + CONTEXT_LINES)
    body = [
        f"{'>' if start <= number <= end else ' '} {number:5d} | {lines[number - 1]}"
        for number in range(first, last + 1)
    ]
    return "\n".join(head + ["Code (flagged lines marked with >):"] + body)


def parse_answer(text: str) -> dict[str, Any] | None:
    match = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not match:
        return None
    try:
        answer = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    verdict = str(answer.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        return None
    return {"verdict": verdict, "quote": str(answer.get("quote") or ""), "reason": str(answer.get("reason") or "").strip()}


def quote_on_line(quote: str, finding: dict[str, Any], lines: list[str] | None) -> bool:
    """The quote, whitespace-normalised, is inside the flagged lines (or the snippet when there is no tree)."""
    def squash(text: str) -> str:
        return " ".join(text.split())

    needle = squash(quote)
    if len(needle) < 3:
        return False
    if lines is None:
        return needle in squash(str(finding.get("code_snippet") or ""))
    start, end = flagged_span(finding)
    return needle in squash("\n".join(lines[start - 1:end]))


def ask(finding: dict[str, Any], lines: list[str] | None, caller: Caller, calibration: bool) -> dict[str, Any]:
    response = caller(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt(finding, lines),
        timeout_seconds=TIMEOUT_SECONDS,
        temperature=0,
        max_output_tokens=400,
    )
    answer = parse_answer(response.text)
    entry: dict[str, Any] = {
        "fingerprint": str(finding.get("fingerprint") or ""),
        "rule_id": str(finding.get("rule_id") or ""),
        "where": where(finding),
        "source": "model",
        "model": f"{response.provider}/{response.model}",
        "prompt_version": PROMPT_VERSION,
        "calibration": calibration,
        "context": "tree" if lines is not None else "snippet_only",
    }
    if answer is None:
        entry.update({"verdict": "unparsed", "quote": "", "reason": "", "quote_on_line": False})
        return entry
    entry.update(answer)
    entry["quote_on_line"] = quote_on_line(answer["quote"], finding, lines)
    return entry


def command_propose(args: argparse.Namespace, caller: Caller | None = None) -> int:
    if caller is None:
        from llm_client import call_llm, is_llm_configured  # noqa: PLC0415

        if not is_llm_configured():
            print("propose: no model is configured (LLM_PROVIDER and its key); nothing was asked", file=sys.stderr)
            return 2
        caller = call_llm
    findings = score.load_results(args.results)
    labels = score.load_labels(str(args.labels))
    human = load_json(Path(args.human))["adjudications"]
    model_document = load_model_file(Path(args.model))
    chosen = candidates(findings, labels, human, model_document["adjudications"], args.calibrate or args.calibration_only)
    if args.calibration_only:
        chosen = [(finding, calibration) for finding, calibration in chosen if calibration]
    if args.limit is not None:
        chosen = chosen[: args.limit]
    snapshots = Path(args.snapshots)
    for number, (finding, calibration) in enumerate(chosen, start=1):
        lines = tree_lines(snapshots, finding["_repo"], finding["_ref"], str(finding.get("file_path") or ""))
        entry = ask(finding, lines, caller, calibration)
        model_document["adjudications"].append(entry)
        print(f"{number}/{len(chosen)} {entry['where']} {entry['rule_id']}: {entry['verdict']}"
              f"{'' if entry['quote_on_line'] else ' (quote not on the line)'}")
        # Written after every answer, so an interrupted run keeps what it paid for.
        dump_model_file(model_document, Path(args.model))
    return 0


# --- agreement ----------------------------------------------------------------------------------


def cohen_kappa(pairs: Iterable[tuple[str, str]]) -> float | None:
    pairs = list(pairs)
    if not pairs:
        return None
    categories = sorted({value for pair in pairs for value in pair})
    total = len(pairs)
    observed = sum(1 for human, model in pairs if human == model) / total
    expected = sum(
        (sum(1 for human, _ in pairs if human == category) / total)
        * (sum(1 for _, model in pairs if model == category) / total)
        for category in categories
    )
    if expected == 1:
        return 1.0 if observed == 1 else None
    return (observed - expected) / (1 - expected)


def agreement(human: list[dict[str, Any]], model: list[dict[str, Any]]) -> dict[str, Any]:
    by_human = {item["fingerprint"]: str(item["verdict"]).lower() for item in human if item.get("sampled_as") in CALIBRATION_SAMPLES}
    table: dict[tuple[str, str], int] = {}
    pairs: list[tuple[str, str]] = []
    for entry in model:
        human_verdict = by_human.get(entry["fingerprint"])
        if human_verdict is None:
            continue
        model_verdict = entry["verdict"] if entry.get("quote_on_line") else "quote not on line"
        if entry["verdict"] == "unparsed":
            model_verdict = "unparsed"
        table[(human_verdict, model_verdict)] = table.get((human_verdict, model_verdict), 0) + 1
        if model_verdict in ("true", "false"):
            pairs.append((human_verdict, model_verdict))
    compared = sum(table.values())
    return {
        "human_calibration_verdicts": len(by_human),
        "model_judged": compared,
        "decisive_pairs": len(pairs),
        "agreed": sum(1 for human_verdict, model_verdict in pairs if human_verdict == model_verdict),
        "kappa": cohen_kappa(pairs),
        "table": table,
        "models": sorted({entry["model"] for entry in model if entry["fingerprint"] in by_human}),
    }


def render_agreement(result: dict[str, Any]) -> str:
    columns = ["true", "false", "unsure", "quote not on line", "unparsed"]
    lines = [
        f"calibration: {result['model_judged']} of {result['human_calibration_verdicts']} hand-read verdicts "
        f"have a model verdict ({', '.join(result['models']) or 'no model'})",
        f"decisive pairs: {result['decisive_pairs']}, agreed: {result['agreed']}",
        "Cohen's kappa (true/false pairs only): "
        + ("n/a" if result["kappa"] is None else f"{result['kappa']:.3f}"),
        "",
        "| human \\ model | " + " | ".join(columns) + " |",
        "| --- | " + " | ".join("---:" for _ in columns) + " |",
    ]
    for human_verdict in ("true", "false"):
        cells = [str(result["table"].get((human_verdict, column), 0)) for column in columns]
        lines.append(f"| {human_verdict} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def command_report(args: argparse.Namespace) -> int:
    human = load_json(Path(args.human))["adjudications"]
    model = load_model_file(Path(args.model))["adjudications"]
    print(render_agreement(agreement(human, model)))
    uncalibrated = [entry for entry in model if not entry.get("calibration")]
    counts: dict[str, int] = {}
    for entry in uncalibrated:
        key = entry["verdict"] if entry.get("quote_on_line") or entry["verdict"] == "unparsed" else "quote not on line"
        counts[key] = counts.get(key, 0) + 1
    print()
    print(f"proposals awaiting a reviewer: {len(uncalibrated)} "
          + ", ".join(f"{key} {value}" for key, value in sorted(counts.items())))
    return 0


# --- accepting ----------------------------------------------------------------------------------


def resolve(identifier: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [entry for entry in entries if entry["fingerprint"].startswith(identifier)]
    if len(identifier) < 8 or len(matches) != 1:
        raise SystemExit(f"accept: {identifier!r} names {len(matches)} model entries; give at least 8 characters of one fingerprint")
    return matches[0]


def command_accept(args: argparse.Namespace) -> int:
    reviewer = (args.reviewer or "").strip()
    if not reviewer:
        raise SystemExit("accept: --reviewer is required; a verdict in the human file needs a person behind it")
    human_path = Path(args.human)
    human_document = load_json(human_path)
    model = load_model_file(Path(args.model))["adjudications"]
    present = {item["fingerprint"] for item in human_document["adjudications"]}
    accepted: list[dict[str, Any]] = []
    for identifier in args.ids:
        entry = resolve(identifier, model)
        if entry.get("calibration"):
            raise SystemExit(f"accept: {entry['fingerprint'][:12]} is a calibration entry; a person already judged it")
        if entry["fingerprint"] in present:
            raise SystemExit(f"accept: {entry['fingerprint'][:12]} is already in {human_path.name}")
        if entry["verdict"] not in ("true", "false"):
            raise SystemExit(f"accept: {entry['fingerprint'][:12]} has verdict {entry['verdict']!r}; only true or false can be accepted")
        if not entry.get("quote_on_line"):
            raise SystemExit(f"accept: {entry['fingerprint'][:12]} quotes text that is not on the flagged line")
        accepted.append({
            "fingerprint": entry["fingerprint"],
            "verdict": entry["verdict"],
            "note": entry["reason"],
            "rule_id": entry["rule_id"],
            "where": entry["where"],
            "sampled_as": "model_proposed",
            "source": "model",
            "model": entry["model"],
            "accepted_by": reviewer,
        })
        present.add(entry["fingerprint"])
    human_document["adjudications"].extend(accepted)
    human_path.write_text(json.dumps(human_document, indent=2) + "\n", encoding="utf-8")
    print(f"accepted {len(accepted)} into {human_path.name}, reviewer {reviewer}")
    return 0


def main(argv: list[str] | None = None, caller: Caller | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    propose = commands.add_parser("propose", help="ask the model about unjudged findings")
    propose.add_argument("results", nargs="+", help="snapshot result files")
    propose.add_argument("--calibrate", action="store_true", help="also re-judge the 71 hand-read sample findings")
    propose.add_argument("--calibration-only", action="store_true", help="re-judge the hand-read sample and nothing else")
    propose.add_argument("--limit", type=int, help="ask about at most this many findings")
    propose.add_argument("--snapshots", default=str(DEFAULT_SNAPSHOTS))

    report = commands.add_parser("report", help="kappa and confusion table against the hand-read sample")

    accept = commands.add_parser("accept", help="copy model verdicts a person has read into the human file")
    accept.add_argument("ids", nargs="+", help="fingerprints, or unique prefixes of at least 8 characters")
    accept.add_argument("--reviewer", required=True, help="who read them")

    for sub in (propose, report, accept):
        sub.add_argument("--labels", default=str(LABELS))
        sub.add_argument("--human", default=str(HUMAN))
        sub.add_argument("--model", default=str(MODEL))

    args = parser.parse_args(argv)
    if args.command == "propose":
        return command_propose(args, caller)
    if args.command == "report":
        return command_report(args)
    return command_accept(args)


if __name__ == "__main__":
    raise SystemExit(main())
