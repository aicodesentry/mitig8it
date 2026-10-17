#!/usr/bin/env python3
"""Build the adversarial triage cases in the format `run_eval.py` reads.

Twelve findings, each triaged as its own pull request:

* six authored files on which a rule fires but no caller input reaches the sink. A triage
  model that confirms on the dangerous function name alone calls these true_positive with no
  way to reach the sink, which is what the exploit payload requirement is meant to stop.
* six findings from `benchmarks/vulnerable-corpus` that a reviewer read and marked true in
  `adjudications.json`. The payload requirement must not lower these.

The authored findings are produced by running the real tier 1 and tier 2 code over
`sources/`, the same way `build_dataset.py` treats every other source. The corpus findings
are taken from the inputs `build_dataset.py` materialises (they quote third-party code, so
they are not committed) and must carry the same `input_sha256` as the main manifest.

    python benchmarks/model-selection/triage/adversarial/build_inputs.py            # build and check
    python benchmarks/model-selection/triage/adversarial/build_inputs.py --freeze   # rewrite cases.json

The output, `benchmarks/results/triage-adversarial-inputs.json`, pairs with `cases.json` as
`--inputs` and `--manifest` of `run_eval.py`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
ANALYSIS_SRC = REPO_ROOT / "services" / "analysis-service" / "src"
SOURCES = HERE / "sources"
MANIFEST_PATH = HERE / "cases.json"
MAIN_INPUTS_PATH = REPO_ROOT / "benchmarks" / "results" / "triage-eval-inputs.json"
OUT_PATH = REPO_ROOT / "benchmarks" / "results" / "triage-adversarial-inputs.json"

# The tiers must run every rule on these small files; the defaults are generous enough, but
# the main builder raises them for the same reason, so the two builds agree.
os.environ.setdefault("TIER1_BUDGET_SECONDS", "120")
os.environ.setdefault("TIER1_FILE_BUDGET_SECONDS", "60")
if str(ANALYSIS_SRC) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_SRC))

AUTHORED = [
    {
        "case": "constant-vm",
        "path": "lib/defaults.js",
        "rule_id": "code.injection.eval",
        "why": "vm.runInContext over a module constant; nothing from a caller reaches the expression",
    },
    {
        "case": "constant-vm-new-context",
        "path": "src/pricing.js",
        "rule_id": "code.injection.eval",
        "why": "vm.runInNewContext over a constant rule; the caller's value is a number in the sandbox, not code",
    },
    {
        "case": "framework-redirect",
        "path": "lib/response.js",
        "rule_id": "redirect.open",
        "why": "a framework's own definition of res.redirect; the target is the caller's choice and no request value is read",
    },
    {
        "case": "constant-redirect",
        "path": "routes/auth.js",
        "rule_id": "redirect.open",
        "why": "res.redirect to a literal relative path",
    },
    {
        "case": "resolved-path-read",
        "path": "routes/files.js",
        "rule_id": "opengrep.cwe-22.path-traversal-fs",
        "why": "path.basename strips every directory part before the join, so the read stays in the base directory",
    },
    {
        "case": "allowlisted-path-read",
        "path": "app/docs.py",
        "rule_id": "opengrep.cwe-22.py-open-request-path",
        "why": "the requested name is checked against a fixed set before open",
    },
]

# Hand-read true in benchmarks/vulnerable-corpus/adjudications.json, and present in the main
# triage manifest so the materialised inputs carry them. Chosen to span sinks where a payload
# is a literal request value (deserialisation, SSRF, XSS) and one where it is a cross-site
# request (CSRF), which is the class most likely to be lowered wrongly.
CORPUS_IDS = [
    "corpus:benbusby/whoogle-search:app/routes.py#c693ee9a159c",
    "corpus:stamparm/DSVW:dsvw.py#d1255eb1f135",
    "corpus:stamparm/DSVW:dsvw.py#73f218e0feb5",
    "corpus:juice-shop/juice-shop:routes/vulnCodeSnippet.ts#02a43b5c77a8",
    "corpus:juice-shop/juice-shop:data/static/codefixes/localXssChallenge_3.ts#40c1e3082a56",
    "corpus:adeyosemanputra/pygoat:introduction/apis.py#7d644cac4cde",
]

AUTHORED_REPO = "acme/app"
AUTHORED_REF = "a" * 40


def added_patch(content: str) -> tuple[str, int]:
    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines), len(lines)


def tier_findings(path: str, content: str) -> list[dict[str, Any]]:
    """What tier 1 and tier 2 return for `content` added at `path`, in the order tier 3 gets it."""
    import main as analysis_main  # noqa: PLC0415 - heavy, and only a build needs it.

    patch, count = added_patch(content)
    findings: list[dict[str, Any]] = []
    for tier, file_content, spans in (
        (1, "", []),
        (2, content, [{"start": 1, "end": count}]),
    ):
        request = analysis_main.AnalyzePRRequest(
            repository_full_name=AUTHORED_REPO, pull_request_number=0, commit_sha=AUTHORED_REF,
            files=[analysis_main.ChangedFile(
                path=path, patch=patch, content=file_content, additions=count, deletions=0,
                status="added", reviewable_line_spans=spans,
            )],
        )
        if tier == 1:
            findings.extend(analysis_main.analyze_tier1_payload(request)["findings"])
        else:
            findings.extend(analysis_main.analyze_tier2_payload(request)["findings"])
    return findings


def prompt_context_sha256(finding: dict[str, Any], file_patches: dict[str, str]) -> str:
    """The same hash `build_dataset.py` records: the context the production prompt builder emits."""
    import llm_triage  # noqa: PLC0415

    context = llm_triage._build_finding_context(finding, file_patches)
    blob = json.dumps(context, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def manifest_sha256(records: list[dict[str, Any]]) -> str:
    blob = json.dumps(
        [[r["id"], r["label"], r["input_sha256"]] for r in sorted(records, key=lambda r: r["id"])]
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def record_for(finding: dict[str, Any], *, pr_id: str, label: str, source: str, repo: str, ref: str,
               provenance: dict[str, Any], expected: dict[str, Any], input_sha256: str,
               record_id: str | None = None) -> dict[str, Any]:
    rule_id = str(finding.get("rule_id") or "")
    fingerprint = str(finding.get("fingerprint") or "")
    return {
        "id": record_id or f"{pr_id}#{fingerprint[:12]}",
        "label": label,
        "source": source,
        "pr_id": pr_id,
        "repo": repo,
        "ref": ref,
        "path": str(finding.get("file_path") or ""),
        "line_start": int(finding.get("line_start") or 0),
        "line_end": int(finding.get("line_end") or finding.get("line_start") or 0),
        "rule_id": rule_id,
        "tier": 2 if rule_id.startswith("opengrep.") else 1,
        "cwe": str(finding.get("cwe_id") or ""),
        "severity": str(finding.get("severity") or ""),
        "confidence": finding.get("confidence"),
        "in_test_code": bool(finding.get("in_test_code")),
        "fingerprint": fingerprint,
        "provenance": provenance,
        "expected": expected,
        "input_sha256": input_sha256,
    }


def build_authored(pull_requests: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for case in AUTHORED:
        content = (SOURCES / case["case"] / case["path"]).read_text(encoding="utf-8")
        matches = [f for f in tier_findings(case["path"], content) if f.get("rule_id") == case["rule_id"]]
        if len(matches) != 1:
            raise SystemExit(
                f"{case['case']}: expected one {case['rule_id']} finding, got {len(matches)}. "
                "A rule changed; read the case again before freezing."
            )
        finding = matches[0]
        pr_id = f"adversarial:{case['case']}"
        file_patches = {case["path"]: added_patch(content)[0]}
        pull_requests[pr_id] = {"file_patches": file_patches, "findings": [finding]}
        records.append(record_for(
            finding, pr_id=pr_id, label="not_real", source="adversarial-authored",
            repo=AUTHORED_REPO, ref=AUTHORED_REF,
            provenance={"kind": "authored", "ref": f"sources/{case['case']}/{case['path']}", "note": case["why"]},
            expected={"verdict": "not true_positive", "why": "no input reaches the sink"},
            input_sha256=prompt_context_sha256(finding, file_patches),
        ))
    return records


def build_corpus(pull_requests: dict[str, Any], main_manifest: dict[str, Any], main_inputs: dict[str, Any]) -> list[dict[str, Any]]:
    by_id = {r["id"]: r for r in main_manifest["findings"]}
    records = []
    for record_id in CORPUS_IDS:
        source = by_id.get(record_id)
        if source is None:
            raise SystemExit(f"{record_id} is not in the main triage manifest")
        pr = main_inputs["pull_requests"][source["pr_id"]]
        finding = next(f for f in pr["findings"] if f.get("fingerprint") == source["fingerprint"])
        file_patches = {source["path"]: pr["file_patches"][source["path"]]}
        input_sha256 = prompt_context_sha256(finding, file_patches)
        if input_sha256 != source["input_sha256"]:
            raise SystemExit(f"{record_id}: the prompt context differs from the main manifest's")
        # One finding per request, so a verdict cannot lean on its neighbours in the file.
        pr_id = f"adversarial:{record_id}"
        pull_requests[pr_id] = {"file_patches": file_patches, "findings": [finding]}
        records.append(record_for(
            finding, pr_id=pr_id, label="real", source="adversarial-corpus",
            repo=source["repo"], ref=source["ref"],
            provenance={**source["provenance"], "main_manifest_id": record_id},
            expected={"verdict": "true_positive with a concrete exploit_payload"},
            input_sha256=input_sha256, record_id=pr_id,
        ))
    return records


def build(main_manifest_path: Path, main_inputs_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not main_inputs_path.exists():
        raise SystemExit(
            f"{main_inputs_path} does not exist. The six corpus cases come from it; materialise it "
            "with `make eval-triage-dataset` (benchmarks/model-selection/triage/build_dataset.py)."
        )
    main_manifest = json.loads(main_manifest_path.read_text(encoding="utf-8"))
    main_inputs = json.loads(main_inputs_path.read_text(encoding="utf-8"))
    if main_inputs.get("dataset_sha256") != main_manifest.get("dataset_sha256"):
        raise SystemExit("the materialised main inputs were not built from the main manifest")

    pull_requests: dict[str, Any] = {}
    records = build_authored(pull_requests) + build_corpus(pull_requests, main_manifest, main_inputs)
    records.sort(key=lambda r: r["id"])
    dataset_sha256 = manifest_sha256(records)
    manifest = {
        "version": 1,
        "description": (
            "Adversarial cases for tier 3 triage: six authored findings no input reaches, which a "
            "model tends to confirm on the function name, and six hand-read true corpus findings. "
            "Built by build_inputs.py; read with run_eval.py --manifest/--inputs."
        ),
        "dataset_sha256": dataset_sha256,
        "counts": {
            "findings": len(records),
            "real": sum(1 for r in records if r["label"] == "real"),
            "not_real": sum(1 for r in records if r["label"] == "not_real"),
            "pull_requests": len(pull_requests),
        },
        "main_manifest_sha256": main_manifest.get("dataset_sha256"),
        "findings": records,
    }
    inputs = {"dataset_sha256": dataset_sha256, "pull_requests": pull_requests}
    return manifest, inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--freeze", action="store_true", help="rewrite cases.json from this build")
    parser.add_argument("--main-manifest", default=str(HERE.parent / "dataset.json"))
    parser.add_argument("--main-inputs", default=str(MAIN_INPUTS_PATH))
    parser.add_argument("--out", default=str(OUT_PATH))
    args = parser.parse_args()

    manifest, inputs = build(Path(args.main_manifest), Path(args.main_inputs))
    if args.freeze:
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        frozen = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if frozen.get("dataset_sha256") != manifest["dataset_sha256"]:
            frozen_ids = {r["id"]: r["input_sha256"] for r in frozen.get("findings", [])}
            built_ids = {r["id"]: r["input_sha256"] for r in manifest["findings"]}
            changed = sorted(set(frozen_ids.items()) ^ set(built_ids.items()))
            raise SystemExit(f"the build differs from cases.json: {changed}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inputs, indent=1, sort_keys=True), encoding="utf-8")
    print(json.dumps(manifest["counts"]), f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
