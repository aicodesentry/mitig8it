# Deterministic scans and a recall gate, October 2026

Branch `feat/deterministic-scan-and-recall-gate`, 2026-10-17. Two questions from the September
action trial ("What is still wrong", items 1 and 2 of `action-trial-2026-09.md`): why the same
code produced different findings on two runs, and why a labelled true positive went missing.
Then a gate so a lost label cannot go unnoticed again.

## What this builds on

* **PR 517** (`fix/pin-the-labelled-lines-a-trial-lost`, open) re-checked pygoat
  `introduction/views.py:963` through `analyze_pull_request_payload`, found the SSRF finding
  present, and added `test_corpus_labelled_lines_still_report.py`, which pins the case as a
  padded shape. It concluded the loss did not reproduce. This branch finds the cause (below):
  the loss depends on how long tier 1 takes on the real 48 kB file, which a padded shape does
  not exercise. PR 517's test stays useful as a presence check and is not duplicated here.
* **`feat/recall-ratchet`** (local, not pushed, five commits) has the recall ratchet
  (`scripts/replay/ratchet.py`, `recall-baseline.json`, 105 of 171 labels hit, 97 by a posting
  rule), a path-filtered `recall-ratchet.yml`, `replay.py --no-tier1-budget`, and the refusal of
  a run that hit a ceiling. It is the better base for this work, so this branch is those five
  commits on current `main` followed by this work. It should merge first or together.

## Sources of run-to-run variation on identical input

| Source | What varied | Now |
| --- | --- | --- |
| Tier 1 per-file cap (2 s) on a large file with head content | Which of the 35 rules ran, so which findings existed | **Removed as a cause**: a file's reviewable entries are built once instead of once per rule. Still surfaced as a `budget` limitation if it ever bites |
| Tier 1 request budget (20 s) | How many files were reached | Unchanged in production, surfaced as a `budget` limitation, lifted in measurement (`--no-tier1-budget`, ratchet branch) |
| Scanner per-rule timeout (30 s) and batch timeout (120 s) | Which rule on which file the scanner dropped | Read from `OPENGREP_RULE_TIMEOUT_SECONDS` and `OPENGREP_PROCESS_TIMEOUT_SECONDS`, same defaults; lifted by `replay.py --no-scanner-timeouts`, which `ratchet.py measure` now passes. A per-file timeout was already a `not_analyzed` limitation; a batch timeout fails closed |
| Supporting detections of a cluster | Arrival order, so the evidence sentence and `merged_rule_ids` | Sorted; the survivor stays first |
| Final finding order | Ties on severity, confidence, file and line kept arrival order | Line end, rule id and fingerprint added to the key |
| Tier 2 output order | The scanner's print order, which decides cluster survivors on ties | Sorted by file, line, rule id, fingerprint before classification; limitations sorted by the whole entry before the per-(path, kind) dedupe |
| Limitations from the two tier threads | Appended to one list in completion order | One list per tier, joined tier 1 first |
| The Action | Dropped `analysis_limitations` entirely, so a capped file was silent | `analysis.analyze_with_limitations`; `run.py` logs one `Not fully analysed (kind), path: message` line each |
| Wall clock in the response | None found: no timestamp in the analysis response; `time` is used only for the budgets and the duration metric | Nothing to change; the end-to-end test strips timestamp-like keys anyway |
| Fingerprints | `make_fingerprint(rule_id, path, line_start, snippet)`; no set or dict iteration feeds it | Nothing to change. Sets in the service are membership tests only; rule files load in sorted order |

Not addressed here: the fix-marker digest that changed between runs on
`pygoat/settings.py:25` (trial item 2's first instability, remediation evidence, outside the
analysis service), the per-file log of whether head content was used (the Action now logs
limitations, not the comment stripper's fallback), and tier 3, which calls a model and is off
in every measurement.

## The cause of the lost true positive

Tier 1 ran `parse_patch_entries(patch, path, content)` once per rule, and with head content
that runs the comment stripper over the whole file twice. pygoat `introduction/views.py` is
48 kB. Measured on this machine (Apple silicon, Python 3.11.6) in the trial's shape (a trailing
comment on each of the nine labelled lines, head content supplied):

| | Tier 1 time | Rules run | Findings on the file |
| --- | ---: | --- | --- |
| Budget lifted, before | 7.65 s, 8.01 s, 11.69 s | 35 of 35 | 158, 214, **291** cookie, 460, **963** SSRF, **1026** `auth.weak_password_hash` + `crypto.weak.hash`, 1026 null deref |
| Production 2 s cap, before | 2.06 s, 2.17 s, 2.23 s | 9, 8, 6 of 35 | 158 and 1026 `crypto.weak.hash`; then 1026 only; then 1026 only |
| Production 2 s cap, after | 0.10 s, 0.09 s, 0.07 s | 35 of 35 | All eight of the first row |

The SSRF rule is 26th in `SECURITY_RULES` and the cookie rule 23rd. A cap that stops after
6 to 9 rules loses both, and the count it stops at moves with load, which is all three trial
instabilities on that file: the lost `views.py:963`, the `views.py:291` comment deleted on a
README-only commit, and `auth.weak_password_hash` leaving `views.py:1026`. The trial ran on
GitHub's runners, whose speed I did not measure; the trial logs cannot confirm the cap fired
there because the Action dropped the limitation that would have said so, which is now fixed.

Fix: `_parse_patch_entries_cached`, an `lru_cache` of 32 on `(patch, path, content)`, with
copies handed to each caller. Test: `tests/test_tier1_file_cap_on_a_large_file.py`, over the
committed corpus file with no budget lifted, asserts no limitation and the 963, 291 and 1026
findings, that ten calls strip once, and that callers cannot alter each other's entries.

## The determinism test

`tests/test_determinism_end_to_end.py`: one request of 175 new files (every positive tier 2
benchmark case and every tier 1 true positive), analysed twice through
`analyze_pull_request_payload`, once with tier 1 delayed 0.5 s so tier 2 finishes first and
once the other way round, both tiers' limits lifted. It asserts both tiers produced findings,
at least 30 findings, no budget or timeout limitation, and byte-identical serialized responses
with key order intact. A second assertion over the same scans checks that every merged finding
lists its supporting rules sorted with the survivor first. 49 s locally after the entry cache.

What it can and cannot show. Against the service code before this branch, the sort assertion
fails on a real scan (`secret.*` listed before `opengrep.*`); the byte-identity assertion
passed on both, because on this fixture the scanner printed in a stable order and the tiers
were already merged by tier. The order fixes are pinned by the unit tests in
`tests/test_determinism_units.py`, which feed reversed scanner output and reversed thread
completion directly.

## The recall gate

Two layers, because the full corpus cannot be fetched on every pull request.

**Required: the committed subset.** `benchmarks/vulnerable-corpus/fixture-subset/` holds the 59
labelled files whose 105 labels the baseline holds as hit, from 20 repositories (MIT,
Apache-2.0, Unlicense), each with its licence file, 640 kB. Eight secrets that gitleaks
reports in three files (nodegoat `config/env/development.js`, pygoat `introduction/views.py`,
juice-shop `lib/insecurity.ts`) are overwritten with `x` of the same length so line numbers
hold and the repository's own secret scan passes; `gitleaks dir` over the subset reports no
leaks. `scripts/replay/fixture_subset.py check` scans it in process, both tiers' limits
lifted, and compares with `expected.json` using `ratchet.compare`. Measured: **105 of 105
hit, 97 by a posting rule**, identical to the full-corpus baseline, so no label in this corpus
depends on a file outside the subset. It runs as the `recall-floor` job in `ci.yml`, with no
path filter, and is in `Required CI`'s `needs`. About 2 min 45 s locally.

Checked that it fails: with SSRF findings removed from the worker's output, `check` exits 1,
names `juice-ssrf-profileimageurl-fetch` and `pygoat-ssrf-lab2` (`views.py:963`), and reports
`103 labels hit, below the floor of 105`.

`tests/test_recall_floor_subset.py` (no scan, under a second) fails when a committed file
differs from its manifest hash, a stray file appears, a licence is missing, `expected.json`
and the manifest disagree, or the subset stops carrying a permissive label the full baseline
holds as hit.

**Scheduled: the full corpus.** `recall-ratchet.yml` keeps its pull request trigger and manual
dispatch and gains a Monday 06:17 UTC schedule. `ratchet.py measure` now also lifts the
scanner's timeouts.

Reversal to note: `benchmarks/vulnerable-corpus/README.md` said no source tree is committed,
for supply and licence reasons. The brief asked for a committed subset; the README now says
what is committed and why. Whether to keep it is a call for the repository owner.

## Model-proposed adjudication

`benchmarks/vulnerable-corpus/adjudicate.py propose` sends findings no label and no person has
judged to `call_llm` for a verdict, a quote and one sentence, and writes
`adjudications-model.json` (`source: model`, `provider/model`, `prompt_version`). A quote not
found on the flagged lines of the pinned tree is kept with `quote_on_line: false` and never
counted or accepted. `--calibrate` also re-asks the hand-read sample and `--calibration-only` asks nothing else; `report` prints Cohen's kappa
over true/false pairs and a confusion table; `accept <fingerprint>... --reviewer NAME` is the
only path into `adjudications.json`, refuses calibration, `unsure`, off-line quotes and
duplicates, and preserves the file's formatting byte for byte. Fifteen fake-provider tests in
`tests/test_corpus_adjudicate.py`.

Over the ratchet branch's latest full results, `propose --calibrate` would ask about 2301
unjudged findings and 61 calibration findings (of the 71 in the sample, the rest no longer
appear or are now label-confirmed).

## Not measured

* **Kappa.** No model key exists locally, so no model was asked and there is no agreement
  number. To measure it, with a key configured for tier 3:

  ```sh
  make recall-measure
  python benchmarks/vulnerable-corpus/adjudicate.py propose scripts/replay/.cache/recall-results/*.json --calibration-only
  python benchmarks/vulnerable-corpus/adjudicate.py report
  ```
* **The runner.** The tier 1 timings are from one laptop. Whether the cap fired on GitHub's
  runners during the trial is inferred, not observed. A re-run of the trial on this branch
  would show it: pygoat should keep `views.py:963` and `views.py:291` and log no
  `Not fully analysed (budget)` line.
* **The full corpus on this branch.** The full ratchet was not re-run here; the subset matches
  the baseline label for label, and the entry cache only changes how long tier 1 takes.
* **The CI jobs.** `recall-floor` and the ratchet schedule have not run on GitHub yet.

## Commands

```sh
PY=~/.pyenv/versions/3.11.6/bin/python
export PATH="$HOME/.pyenv/versions/3.11.6/bin:$PATH"   # the scanner
cd services/analysis-service/src
$PY -m pytest -q tests/test_determinism_end_to_end.py tests/test_determinism_units.py \
    tests/test_tier1_file_cap_on_a_large_file.py tests/test_recall_floor_subset.py \
    tests/test_recall_ratchet.py tests/test_corpus_adjudicate.py
cd -
$PY scripts/replay/fixture_subset.py check
```
