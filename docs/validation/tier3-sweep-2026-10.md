# Tier 3 sweep, October 2026

17 October 2026. This document records a detector that is built, wired and off. Nothing in it is
a measurement of the sweep yet: no model key was available where it was built, so the numbers
below are the ones that motivated it and the command that would produce its own.

## Why

Tier 3 triage re-judges what tiers 1 and 2 already found. It can remove a finding and cannot add
one, so recall is capped by the rules: 100 of 171 labelled vulnerabilities (0.58) on the
September vulnerable corpus after its follow-ups
([vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md)). The misses that document names
are shapes a pattern cannot reach without data flow it does not have: a command string built on
one line and run on the next, HTML assembled by interpolation, a `pathlib` join.

The repository's own model benchmark (`benchmarks/eval.py`, local result
`benchmarks/results/gpt-4o_results.json`, gitignored) scored gpt-4o at recall 1.00 and precision
0.75 on 42 samples (24 true positives, 8 false positives, 0 false negatives). That is a
whole-snippet verdict, vulnerable or safe, on short synthetic samples. It does not say the model
can point at the right line in a real diff, which is what a review comment needs, and it is not
evidence about any one class. It says the profile is high recall at moderate precision, which is
the profile a per-class posting gate can manage.

## What was built

`services/analysis-service/src/llm_sweep.py`.

**Input.** The changed hunks (`file_patches`) and the repository profile, the same two things
triage receives on `/analyze/pr/tier3`.

**What the model sees.** Each sweepable file rendered with new-file line numbers, added lines
marked `+`, context unmarked. Sweepable means what tier 2 reads (code and template extensions,
workflows under `.github/workflows/`) less prose. A fixed menu of classes:
`taxonomy.CANONICAL_INTERNAL_TYPES`, nothing else.

**What it must return.** A JSON array of objects with `internal_type`, `file_path`, `line`,
`quote`, `severity`, `confidence`, `rationale` and `exploit_payload` (a concrete input and the
entrypoint that delivers it).

**What is rejected,** each with its reason logged and counted in
`codesentry_llm_sweep_rejections_total{reason}` and in the response's `sweep.rejected`:

| Reason | Meaning |
| --- | --- |
| `off_menu_class` | `internal_type` is not a canonical class |
| `unknown_file` | the path is not one of the files sent in that call |
| `line_not_an_integer` | `line` is not a whole number |
| `line_not_changed` | `line` is a context line or outside the hunk |
| `quote_missing` / `quote_mismatch` | the quote is under three characters, or is not verbatim on that line |
| `invalid_severity` / `invalid_confidence` | outside the allowed values |
| `no_rationale` / `no_exploit_payload` | the model did not say why or how |
| `duplicate` | same file, line and class already accepted |
| `request_cap` / `file_cap` | over `LLM_SWEEP_MAX_FINDINGS` or `LLM_SWEEP_MAX_FINDINGS_PER_FILE` |

**What an accepted item becomes.** A finding in the shape `pattern_findings` and
`opengrep_runner` emit: `rule_id` `llm.sweep.<internal_type>`, the taxonomy's CWE for the class,
`fingerprint` from `make_fingerprint`, `evidence_strength: "model"`, `is_taint_based: false`,
`analysis_scope: "model-sweep"`, `detector_tier: "tier3-sweep"`. The quote, rationale and
payload are kept in `evidence_details`. No remediation text and `auto_fix_eligible: false`: the
model was not asked for a fix.

**Folding.** `finding_quality.detector_kind` reads the `llm.` prefix as its own kind, `model`.
A sweep finding on the same line and class as a rule finding is folded by the existing
`cluster_findings` as a supporting detection. The rule's finding always survives as primary and
as review anchor, whatever severity the model chose: the rule's line is where a pattern matched,
the model's is where a model pointed. The result is one comment with two detectors on it.

**Where it runs.** In `triage_findings_payload` (the `/analyze/pr/tier3` handler and its gRPC
twin) after triage, whether or not the rules found anything, because a pull request with no rule
finding is where the sweep can add recall. Also in the combined `/analyze/pr` endpoint, without a
repository profile. Sweep findings are not triaged: it is the same model judging its own answer.
A failure of the sweep never fails the analysis; the response's `sweep.status` says `disabled`,
`ok`, `partial` or `failed`.

## Gating

| Control | Default | Effect |
| --- | --- | --- |
| `LLM_SWEEP_ENABLED` | `false` | Off: no call, `sweep.status: "disabled"`. On only with provider credentials as well. `LLM_TRIAGE_ENABLED` does not switch it on. |
| `services/analysis-service/src/llm_sweep_posting.yml` | every class `quarantine` | Per-class posting state, as data. A class posts only when `posting: post` and `precision_evidence` names the measurement. A missing class, a missing file or an unreadable file quarantines. |
| `LLM_SWEEP_CALL_TOKEN_BUDGET` | 12000 | Estimated input tokens per call. Files are packed first fit, in file order; a file over it alone is skipped and reported as a limitation, never truncated. |
| `LLM_SWEEP_TOKEN_BUDGET` | 48000 | Estimated input tokens per request over every call. |
| `LLM_SWEEP_MAX_CALLS` | 6 | Calls per request. |
| `LLM_SWEEP_MAX_FINDINGS` | 20 | Accepted findings per request. |
| `LLM_SWEEP_MAX_FINDINGS_PER_FILE` | 5 | Accepted findings per file. |
| `LLM_SWEEP_TIMEOUT_SECONDS` | 45 | Per call. |

Every sweep rule id whose class is not cleared is unioned into `main.QUARANTINED_RULE_IDS`, so
the one posting filter tiers 1 and 2 use is the one the sweep uses. Today that is every class, so
with the flag on the sweep runs, is counted in `quarantined_findings` by rule id, and posts
nothing.

## How to measure it

The replay harness takes `--sweep-provider`. The sweep then runs in the worker after tiers 1 and
2 over the same patches (in snapshot mode, whole files as additions), with the posting policy
not applied, and its findings are written to `sweep_findings` in each record, apart from the
rules' `findings`. Remediation never sees them. `score.py` joins them to the labels separately
and adds a "Tier 3 sweep" section: rule recall, sweep recall, labels only the sweep hit, recall
together, and sweep precision by class over adjudicated findings. The rule tables above it are
unchanged by the flag. `--emit-queue` writes the sweep's reading list to a second file,
`<name>.sweep.json`, so the rules' seeded sample does not move.

Provider modes: `live` (configured provider), `record:DIR` (live, saving each response keyed by
the SHA-256 of the system and user prompt), `recorded:DIR` (replays saved responses, no key; a
missing response is a failed call, not an empty answer) and `fake` (answers `[]` to every call;
proves the plumbing, measures nothing).

The service's per-request budgets are a cost envelope for one pull request. A snapshot batch is
hundreds of whole files, so the worker raises `LLM_SWEEP_MAX_CALLS`, `LLM_SWEEP_TOKEN_BUDGET` and
`LLM_SWEEP_MAX_FINDINGS` unless they are already set. Per-call and per-file limits stay.

The exact command, per corpus repository (the refs are in `benchmarks/vulnerable-corpus/README.md`
and `labels.json`):

```sh
PY=~/.pyenv/versions/3.11.6/bin/python
export LLM_PROVIDER=openai LLM_MODEL=gpt-4o OPENAI_API_KEY=...   # the run that records

$PY scripts/replay/replay.py --snapshot --include-quarantined --no-remediation \
    --sweep-provider record:benchmarks/vulnerable-corpus/sweep-recordings \
    --repo OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
    --out results/nodegoat.json

# anyone can then re-run the same measurement with no key
$PY scripts/replay/replay.py --snapshot --include-quarantined --no-remediation \
    --sweep-provider recorded:benchmarks/vulnerable-corpus/sweep-recordings \
    --repo OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
    --out results/nodegoat.json

$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --emit-queue /tmp/queue.json
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md
```

A class moves to `posting: post` in `llm_sweep_posting.yml` only with `precision_evidence`
pointing at the run that measured it, and the clean pull request replay
([real-repo-replay-2026-09.md](real-repo-replay-2026-09.md)) re-run with the flag on to see what
it would add to a reviewer's inbox.

## What is measured

Only behaviour, in tests, with a fake `call_llm`:
`services/analysis-service/src/tests/test_llm_sweep.py` (valid output becomes findings in the
pipeline shape; off-menu class, mismatched quote, unchanged line and the other reasons are
rejected and logged; a sweep finding folds into a rule finding on its line and never replaces it;
the flag off makes no call; budgets, caps and the posting policy) and
`services/analysis-service/src/tests/test_replay_sweep.py` (recorded and fake providers in the
worker, and the scorer keeping sweep hits apart from rule hits).

## What is not measured

* **Recall and precision of the sweep.** No model key was available. The section above is the
  command, not its result.
* **Whether the model can locate.** The gpt-4o benchmark is a whole-sample verdict on synthetic
  snippets. The line and quote checks here will reject an answer that is right about the file
  and wrong about the line, and how often that happens is unknown.
* **Snapshot against pull request.** In snapshot mode every line is an added line, so the model
  sees whole files with nothing marked as context. A pull request shows it a few changed lines
  and their surroundings; recall on the corpus is likely an upper bound on recall in review.
* **Cost.** Token counts are recorded per run (`sweep.input_tokens`, `sweep.output_tokens`,
  `codesentry_llm_sweep_tokens_total`); no run has produced one. The budget estimate is four
  characters per token, not a tokenizer.
* **Determinism.** Calls use temperature 0. A provider is still free to answer differently on a
  re-run, which is what `record:` and `recorded:` exist for.
* **The dismiss rate.** A sweep finding that posts carries no remediation and no proof, so it
  cannot meet the product's one-click-fix bar on its own. Whether a reviewer reads a fixless
  model finding as signal or noise is a question for the first class that clears quarantine.
