#!/usr/bin/env python3
"""Print one table for everything `make bench` just ran.

It reads the artefacts the benchmark targets wrote into `benchmarks/results/`: the pytest output
of the two precision gates, and the JSON reports of the remediation corpus under each adapter.
It computes nothing of its own; every number here is read back out of a report.

Run it on its own with `make bench-summary`, after a `make bench`.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"

COUNT = re.compile(r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)")


def pytest_counts(path: Path) -> dict[str, int] | None:
    """Read the counts off a pytest short summary line."""
    if not path.exists():
        return None
    counts: dict[str, int] = {}
    for line in reversed(path.read_text(errors="replace").splitlines()):
        found = COUNT.findall(line)
        if found:
            for number, label in found:
                counts[label.rstrip("s")] = counts.get(label.rstrip("s"), 0) + int(number)
            return counts
    return None


def cases_in(path: Path) -> int | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if "cases" in data:
        return len(data["cases"])
    return len(data.get("false_positives", [])) + len(data.get("true_positives", []))


def rate(value) -> str:
    return "-" if value is None else f"{value:.2f}"


def gate_row(name: str, output: Path, cases_file: Path) -> list[str]:
    counts = pytest_counts(output)
    if counts is None:
        return [name, "-", "-", "-", "-", "-", "-", "-", "not run"]
    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0) + counts.get("error", 0)
    total = passed + failed
    declared = cases_in(cases_file)
    note = "-" if declared is None else f"from {declared} adjudicated findings"
    return [
        name,
        str(total),
        str(passed),
        str(failed),
        rate(passed / total if total else None),
        "-",
        "-",
        "-",
        note,
    ]


def corpus_row(name: str, report: Path) -> list[str]:
    if not report.exists():
        return [name, "-", "-", "-", "-", "-", "-", "-", "not run"]
    summary = json.loads(report.read_text())["summary"]
    total = summary["total_cases"]
    failures = len(summary["failures"])
    unexpected = len(summary["unexpected_failures"])
    note = (
        f"{summary['verified_repairs']} verified, {summary['abstentions']} abstained"
        if not unexpected
        else f"{unexpected} unexpected failures"
    )
    return [
        name,
        str(total),
        str(total - failures),
        str(failures),
        rate((total - failures) / total if total else None),
        rate(summary["precision"]),
        rate(summary["coverage"]),
        rate(summary["safe_abstention"]),
        note,
    ]


def main() -> int:
    header = [
        "Benchmark",
        "Cases",
        "Pass",
        "Fail",
        "Pass rate",
        "Precision",
        "Coverage",
        "Abstention",
        "Note",
    ]
    rows = [
        gate_row(
            "tier 1 precision gate",
            RESULTS / "tier1-precision.txt",
            ROOT / "benchmarks" / "tier1-precision" / "cases.json",
        ),
        gate_row(
            "tier 2 precision gate",
            RESULTS / "tier2-precision.txt",
            ROOT / "benchmarks" / "tier2-precision" / "cases.json",
        ),
        corpus_row(
            "remediation corpus, reference",
            RESULTS / "remediation-reference.json",
        ),
        corpus_row(
            "remediation corpus, engine-local",
            RESULTS / "remediation-engine-local.json",
        ),
    ]

    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
    line = "  ".join("-" * width for width in widths)

    print()
    print(f"make bench, {date.today().isoformat()}")
    print()
    print("  ".join(cell.ljust(width) for cell, width in zip(header, widths)))
    print(line)
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)))
    print()
    print("Precision, coverage and abstention are the remediation corpus's own definitions:")
    print("  precision   independently correct repairs / repairs the engine verified")
    print("  coverage    independently correct repairs / supported fixtures")
    print("  abstention  negative and adversarial fixtures correctly refused / all of them")
    print("The reference adapter replays the checked-in repairs, so it measures fixture integrity")
    print("rather than the agent. The engine-local adapter runs the real pipeline against a")
    print("scripted provider, so it measures pipeline integrity rather than repair quality.")
    print("Neither is a measurement of a model. See benchmarks/remediation/README.md.")
    print()

    missing = [row[0] for row in rows if row[-1] == "not run"]
    if missing:
        print(f"Missing reports: {', '.join(missing)}. Run make bench.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
