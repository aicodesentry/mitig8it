#!/usr/bin/env python3
"""Aggregate replay result files into the markdown tables used by the validation report.

    scripts/replay/summarize.py results/*.json --out docs/validation/real-repo-replay.md

Without --out the tables go to stdout. `--detail` adds the rule, limitation, exception
and template-reason breakdowns that the triage pass works from.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def summarize_repo(document: dict[str, Any]) -> dict[str, Any]:
    records = document.get("records", [])
    tiers: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    limitations: Counter[str] = Counter()
    exceptions: Counter[str] = Counter()
    template_reasons: Counter[str] = Counter()
    remediation_outcomes: Counter[str] = Counter()
    durations: list[int] = []
    findings_total = 0
    files_total = 0
    bytes_total = 0
    candidates = 0
    verified = 0
    agent_needed = 0
    supported = 0
    fatal: Counter[str] = Counter()

    for record in records:
        files_total += int(record.get("files") or 0)
        bytes_total += int(record.get("bytes_patch") or 0) + int(record.get("bytes_content") or 0)
        if record.get("wall_ms"):
            durations.append(int(record["wall_ms"]))
        for item in record.get("limitations") or []:
            limitations[str(item).split(":")[0]] += 1
        if record.get("fatal"):
            fatal[str(record["fatal"].get("kind"))] += 1
            exceptions[f"pr:{record['fatal'].get('kind')}"] += 1

        analysis = record.get("analysis") or {}
        for tier in ("tier1", "tier2"):
            stage = analysis.get(tier) or {}
            if stage.get("ok") is False:
                exceptions[f"{tier}:{stage.get('error_type')}:{_short(stage.get('error'))}"] += 1

        for finding in record.get("findings") or []:
            findings_total += 1
            rule_id = str(finding.get("rule_id") or "")
            tiers["tier2" if rule_id.startswith("opengrep.") else "tier1"] += 1
            rules[rule_id] += 1

        stage = record.get("remediation_stage") or {}
        if stage.get("ok") is False:
            exceptions[f"remediation:{stage.get('error_type')}:{_short(stage.get('error'))}"] += 1

        remediation = record.get("remediation") or {}
        supported += int(remediation.get("supported_family_findings") or 0)
        candidates += int(remediation.get("candidates_produced") or 0)
        verified += int(remediation.get("verified") or 0)
        agent_needed += int(remediation.get("agent_needed") or 0)
        for item in remediation.get("limitations") or []:
            limitations[str(item).split(":")[0]] += 1
        for item in remediation.get("exceptions") or []:
            exceptions[f"remediation:{item.get('error_type')}:{_short(item.get('error'))}"] += 1
        for attempt in remediation.get("attempted") or []:
            remediation_outcomes[str(attempt.get("outcome"))] += 1
            for reason in (attempt.get("templates") or {}).values():
                template_reasons[str(reason)] += 1

    return {
        "repo": document.get("repo"),
        "prs": len(records),
        "files": files_total,
        "bytes": bytes_total,
        "findings": findings_total,
        "tier1": tiers.get("tier1", 0),
        "tier2": tiers.get("tier2", 0),
        "limitations": sum(limitations.values()),
        "limitation_kinds": limitations,
        "exceptions": sum(exceptions.values()),
        "exception_kinds": exceptions,
        "fatal": fatal,
        "supported_family_findings": supported,
        "candidates": candidates,
        "verified": verified,
        "agent_needed": agent_needed,
        "rules": rules,
        "template_reasons": template_reasons,
        "remediation_outcomes": remediation_outcomes,
        "p50_ms": percentile(durations, 0.5),
        "p95_ms": percentile(durations, 0.95),
    }


def _short(text: Any) -> str:
    return str(text or "").splitlines()[0][:60] if text else ""


def render(summaries: list[dict[str, Any]], detail: bool, baseline: dict[str, int] | None = None) -> str:
    exceptions_header = "Exceptions (before/after)" if baseline is not None else "Exceptions"
    lines = [
        f"| Repo | PRs | Files | Findings (T1/T2) | Limitations | {exceptions_header} | Supported family | Candidates | Verified | Agent needed | p50 ms | p95 ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    totals = Counter()
    baseline_total = 0
    for item in summaries:
        if baseline is None:
            exceptions = str(item["exceptions"])
        else:
            before = baseline.get(str(item["repo"]), 0)
            baseline_total += before
            exceptions = f"{before} / {item['exceptions']}"
        lines.append(
            f"| {item['repo']} | {item['prs']} | {item['files']} | "
            f"{item['findings']} ({item['tier1']}/{item['tier2']}) | {item['limitations']} | "
            f"{exceptions} | {item['supported_family_findings']} | {item['candidates']} | "
            f"{item['verified']} | {item['agent_needed']} | {item['p50_ms']} | {item['p95_ms']} |"
        )
        for key in ("prs", "files", "findings", "tier1", "tier2", "limitations", "exceptions",
                    "supported_family_findings", "candidates", "verified", "agent_needed"):
            totals[key] += item[key]
    total_exceptions = (
        str(totals["exceptions"]) if baseline is None else f"{baseline_total} / {totals['exceptions']}"
    )
    lines.append(
        f"| **total** | {totals['prs']} | {totals['files']} | "
        f"{totals['findings']} ({totals['tier1']}/{totals['tier2']}) | {totals['limitations']} | "
        f"{total_exceptions} | {totals['supported_family_findings']} | {totals['candidates']} | "
        f"{totals['verified']} | {totals['agent_needed']} | | |"
    )

    if not detail:
        return "\n".join(lines)

    merged_rules: Counter[str] = Counter()
    merged_limitations: Counter[str] = Counter()
    merged_exceptions: Counter[str] = Counter()
    merged_templates: Counter[str] = Counter()
    merged_outcomes: Counter[str] = Counter()
    for item in summaries:
        merged_rules.update(item["rules"])
        merged_limitations.update(item["limitation_kinds"])
        merged_exceptions.update(item["exception_kinds"])
        merged_templates.update(item["template_reasons"])
        merged_outcomes.update(item["remediation_outcomes"])

    for title, counter in (
        ("Findings by rule", merged_rules),
        ("Limitations", merged_limitations),
        ("Exceptions", merged_exceptions),
        ("Template outcomes", merged_templates),
        ("Remediation states", merged_outcomes),
    ):
        lines.extend(["", f"### {title}", "", "| Key | Count |", "| --- | ---: |"])
        for key, count in counter.most_common():
            lines.append(f"| `{key}` | {count} |")
        if not counter:
            lines.append("| (none) | 0 |")

    return "\n".join(lines)


def _cell(text: Any) -> str:
    """One table cell: no pipes, no newlines, bounded."""
    return str(text if text is not None else "").replace("|", "/").replace("\n", " ")[:160] or "-"


def _tree_outcome(variant: dict[str, Any]) -> str:
    """What the proof did on one tree, as a table reads it."""
    if not variant:
        return "not run"
    if variant.get("completed") is not True:
        return f"did not run ({variant.get('reason_code') or 'unknown'})"
    return str(variant.get("status") or "unknown")


def pair_rows(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for document in documents
        for record in document.get("records") or []
        for row in ((record.get("pairs") or {}).get("rows") or [])
    ]


def render_pairs(documents: list[dict[str, Any]]) -> str:
    """The per-pair table: every finding that has both halves, and what its proof did on each tree.

    A pair verifies only when its proof fails on the original tree and passes on the patched one,
    so both outcomes are reported rather than one verdict.
    """
    rows = [row for row in pair_rows(documents) if row.get("pair")]
    lines = [
        "| Repository | Path | Family | Original | Patched | Verifier reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(rows, key=lambda item: (item["repo"], item["path"], item.get("line_start") or 0)):
        pair = row["pair"]
        lines.append(
            f"| `{_cell(row['repo'])}` | `{_cell(row['path'])}:{_cell(row.get('line_start'))}` "
            f"| `{_cell(row['family'])}` | {_cell(_tree_outcome(pair.get('original') or {}))} "
            f"| {_cell(_tree_outcome(pair.get('patched') or {}))} "
            f"| {'verified' if pair.get('verified') else '`' + _cell(pair.get('verifier_reason')) + '`'} |"
        )
    totals: Counter[str] = Counter()
    for document in documents:
        for record in document.get("records") or []:
            for key, value in (((record.get("pairs") or {}).get("counts")) or {}).items():
                totals[key] += int(value)
    reach = [
        "",
        "| | Count |",
        "| --- | ---: |",
        f"| Supported-family findings whose file the snapshot carries | {totals['supported']} |",
        f"| Findings the template builds a patch for | {totals['patch']} |",
        f"| Findings the service writes a proof for | {totals['proof']} |",
        f"| Findings with both halves | {totals['both']} |",
        f"| Pairs that verify end to end | {totals['verified']} |",
    ]
    return "\n".join(lines + reach + render_installs(documents) + render_proof_reasons(documents))


def render_installs(documents: list[dict[str, Any]]) -> list[str]:
    """One row per repository whose dependencies a `--with-dependencies` run installed."""
    installs = [
        (record.get("repo") or "", (record.get("pairs") or {}).get("install") or {})
        for document in documents
        for record in document.get("records") or []
        if ((record.get("pairs") or {}).get("install") or {}).get("reason_code") != "no_dependency_manifest"
        or ((record.get("pairs") or {}).get("install") or {}).get("ecosystems")
    ]
    installs = [(repo, install) for repo, install in installs if install and "dependencies_installed" in install]
    if not any(install.get("ecosystems") or install.get("reason_code") for _, install in installs):
        return []
    lines = [
        "",
        "### The install, per repository",
        "",
        "| Repository | Ecosystems | Install | Lockfile | Duration | On disk |",
        "| --- | --- | --- | --- | ---: | ---: |",
    ]
    for repo, install in sorted(installs):
        lockfiles = install.get("lockfiles") or []
        foreign = install.get("foreign_lockfiles") or []
        situation = ", ".join(f"`{item}`" for item in lockfiles) or "none carried"
        if foreign:
            situation += " (repository also carries " + ", ".join(f"`{item}`" for item in foreign) + ")"
        outcome = "installed" if install.get("dependencies_installed") else f"`{install.get('reason_code')}`"
        lines.append(
            f"| `{_cell(repo)}` | {', '.join(install.get('ecosystems') or []) or 'none'} | {outcome} "
            f"| {situation} | {round(int(install.get('duration_ms') or 0) / 1000)}s "
            f"| {round(int(install.get('bytes_installed') or 0) / 1_000_000)} MB |"
        )
    return lines


def render_proof_reasons(documents: list[dict[str, Any]]) -> list[str]:
    """Why the findings that got no proof got none, counted."""
    reasons: Counter[str] = Counter()
    for row in pair_rows(documents):
        if row.get("skipped"):
            reasons[str(row["skipped"])] += 1
        elif isinstance(row.get("proof"), str) and row["proof"].startswith("no:"):
            reasons[row["proof"][3:]] += 1
    if not reasons:
        return []
    lines = ["", "### Why a finding got no proof", "", "| Reason | Count |", "| --- | ---: |"]
    lines += [f"| `{_cell(reason)}` | {count} |" for reason, count in reasons.most_common()]
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="+", help="per-repository JSON result files")
    parser.add_argument("--out", help="write the markdown here instead of stdout")
    parser.add_argument("--detail", action="store_true", help="also break down rules, limitations and exceptions")
    parser.add_argument("--pairs", action="store_true",
                        help="render the per-pair table from a `replay.py --pairs` result file instead")
    parser.add_argument("--baseline", nargs="*", default=None,
                        help="result files from an earlier run; the table then shows exceptions before and after")
    args = parser.parse_args()

    if args.pairs:
        documents = [json.loads(Path(path).read_text(encoding="utf-8")) for path in sorted(args.results)]
        text = render_pairs(documents)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + "\n", encoding="utf-8")
            print(f"wrote {out}")
        else:
            print(text)
        return 0

    summaries = []
    for path in sorted(args.results):
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        summaries.append(summarize_repo(document))

    baseline = None
    if args.baseline is not None:
        baseline = {}
        for path in sorted(args.baseline):
            item = summarize_repo(json.loads(Path(path).read_text(encoding="utf-8")))
            baseline[str(item["repo"])] = item["exceptions"]

    text = render(summaries, args.detail, baseline)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
