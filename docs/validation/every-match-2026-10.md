# A tier 1 rule reports every line it matches

Written 2026-10-17, on branch `fix/tier1-report-every-match`.

## What was wrong

`pattern_findings` in `services/analysis-service/src/main.py` emitted at most one finding per
rule per file, at the first match. On the vulnerable corpus
([vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md), Recall) 18 labels had the
expected class reported in the right file but not on the labelled line, and nine of those 18
were this cap. The clearest case is `enrocrypt/hashing.py`: eight digest helpers, the CVE at the
eighth, and `crypto.weak.hash` reporting the first at line 16.

The cap was there so a file with fifty weak hashes would not produce fifty comments. That is a
question about rendering, and it was being answered by not detecting.

## What changed

**Detection.** A rule now reports every reviewable line it matches in a file, one finding per
line. `find_pattern_match_entries` in `finding_quality.py` returns every match, and keeps the
rule the single-match version applied: when any added line matches, only added lines are
reported, and context lines are reported only when no added line matched. The patch is parsed
once per file rather than once per rule. Path traversal reads are each judged against their own
containment guard, so a guarded read above an unguarded one no longer hides the second.

**Ceiling.** `TIER1_MAX_MATCHES_PER_RULE_PER_FILE` is 25. Past it the run records a `match_cap`
limitation in `analysis_limitations`, the same list that carries the budget and partial-parse
limitations, with the message `<rule> reported 25 of N matches in <path>`. A quarantined rule
records no such limitation, because nothing it finds reaches a reviewer. In the App the message is
appended verbatim to the check summary and the review body; two rules over the ceiling in one
file are two sentences. In the Action, which used to discard `analysis_limitations` entirely,
each limitation is now a log line, which is also where the Action states its 200-file cap.

**One comment per line.** `cluster_findings` folds findings from different detectors that
describe one flaw, within a two-line window. With every match reported, eight weak hashes on
consecutive lines chained through that window into one cluster and one comment. A cluster now
never holds one rule on two different lines, and a finding joins the nearest eligible cluster
rather than the first. A tier 2 finding on the same line as its tier 1 twin still folds into it;
one anchored a line off still meets its twin and only its twin. Fingerprints are
`rule|path|line|snippet`, so they are distinct per line and unchanged across runs.

**Review body.** Both products list findings on unchanged lines in a table. Findings that share a
rule and a file now share one row, which names the line count and links each line, for example
`introduction/views.py, 3 lines: 12, 40, 70`. This is item 6 of
[action-trial-2026-09.md](action-trial-2026-09.md) "What is still wrong", where 17 of pygoat's 20
rows were one CSRF rule. A finding the Action moved into the table because of the inline cap
carries no rule and keeps its own row. `UNANCHORED_ROW_CAP` (50) now counts rows, and the
sentence after the table counts the findings in the rows not shown. Inline comments are
unchanged: one per line.

## What was measured

| Check | Result |
| --- | --- |
| Eight-digest fixture shaped like `enrocrypt/hashing.py` | 8 `crypto.weak.hash` findings on the 8 digest lines, each quoting its own line, 8 distinct fingerprints, identical on a second run, no limitation |
| 40 weak hashes in one file | 25 findings on 25 distinct lines; one `match_cap` limitation, `crypto.weak.hash reported 25 of 40 matches in bulk/hashes.py`; the tier 1 response carries both |
| 8 same-rule findings on consecutive lines through `cluster_findings` | 8 findings out, none merged |
| Same, plus a tier 2 twin on the fifth line | 8 out; the fold lands on the fifth line and nowhere else |
| `pattern_findings` on a file of 200 weak hashes | 117 ms, 50 findings (25 posted `crypto.weak.hash`, 25 quarantined `null.pointer.deref`), one limitation |
| `cluster_findings`, 200 same-rule findings in one file | 11 ms |
| `cluster_findings`, 200 tier 1 findings plus 200 tier 2 twins | 50 ms |
| `cluster_findings`, 1,000 same-rule findings | 0.86 s |

Timings are the best of three on macOS on Apple silicon, Python 3.11.6. The fold is still
quadratic. At the ceiling of 25 per rule per file it stays well under a second for any file tier 1
can produce, so the hot path was left as it is and the bound is recorded in
[../architecture/known-debt.md](../architecture/known-debt.md), "Quadratic work".

Tests: `services/analysis-service/src/tests/test_tier1_every_match.py`, the per-rule roll-up and
`match_cap` rendering in `services/api-service/tests/orchestrator.test.js` and
`services/api-service/tests/analysisLimitations.test.js`, and the Action's roll-up and limitation
log in `action/tests/test_publish_envelope.py` and `action/tests/test_orchestrator.py`.

## What was not measured

**The corpus.** The snapshot cache (`scripts/replay/.cache/snapshots/`) does not exist on the
machine this was written on, so the scorer was not rerun. Before this change the "In file" column
was 18 of 171 labels and recall on the labelled lines was 69 of 171 (0.40). The expectation is
that up to nine labels move from "In file" to "Hit"; that is a hypothesis until the command below
is run on `main` and on this branch:

```sh
PY=~/.pyenv/versions/3.11.6/bin/python
mkdir -p results
$PY -c 'import json; [print(r["repo"], r["ref"]) for r in json.load(open("benchmarks/vulnerable-corpus/labels.json"))["repositories"]]' |
while read repo ref; do
  $PY scripts/replay/replay.py --snapshot --include-quarantined \
      --repo "$repo" --ref "$ref" --out "results/$(echo "$repo" | tr / _).json"
done
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md
```

Record the "In file" and "Hit" columns from `/tmp/score.md` for both runs.

**Precision and dismiss rate.** A rule that is wrong on a file is now wrong up to 25 times on it.
The tier 1 precision gate (`test_tier1_precision_benchmark.py`) still passes, but it scores
adjudicated cases, not volume. The effect on dismiss rate needs the real-repository replay
([real-repo-replay-2026-09.md](real-repo-replay-2026-09.md)) rerun and its new findings read.

**A live pull request.** No model key exists locally and no live run was made.

## Other caps found, left in place

| Cap | Where | Behaviour |
| --- | --- | --- |
| `INLINE_COMMENT_CAP` 40 | `prAnalysisOrchestrator.js`, `action/orchestrator/pr_scope.py` | Comments past 40 are not posted. The Action moves them into the review-body table without a rule name. The App counts them in the placement sentence ("listed here only") but does not name them, and logs `inline comment cap reached`. One rule at its ceiling uses 25 of the 40 slots, so this cap is now easier to reach. It does not undo this change, since the findings are still reported and counted, but in the App they are not named. |
| `UNANCHORED_ROW_CAP` 50 | `publish.js`, `prAnalysisOrchestrator.js` | Rows past 50 are not listed; the number of findings left out is stated. Now counts rows per rule per file. |
| `MAX_REPAIR_FINDINGS` 100 | `action/orchestrator/remediation.py` | Findings past 100 get no repair attempt, and nothing says so. |
| `LLM_TRIAGE_MAX_FINDINGS` 100 | `services/analysis-service/src/llm_triage.py` | Findings past 100 are kept but not triaged. |
| Limitation dedupe | `normalizeLimitations` in `prAnalysisOrchestrator.js` | Keyed by path and kind, and unknown kinds become `not_analyzed`, so a budget limitation and another unknown kind on one path collapse to one sentence. `match_cap` is now its own kind and keyed by message as well. |
| Tier 1 budgets, 200-file cap | `main.py`, `pr_scope.py`, github-service | Already stated as limitations; unchanged. |
