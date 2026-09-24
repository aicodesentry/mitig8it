# Real-repository replay harness

Runs the analysis and remediation pipeline over recent merged pull requests of public
repositories, so the ways it breaks on code it has never seen are found here rather than
by a customer.

## Run

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# one repository
$PY scripts/replay/replay.py --repo expressjs/express --prs 15 --out results/expressjs-express.json

# aggregate several
$PY scripts/replay/summarize.py results/*.json --detail --out /tmp/replay.md

# compare a run after a service fix against an earlier run over the same cache
$PY scripts/replay/summarize.py results-after/*.json --baseline results-before/*.json

# prove the harness itself reaches the engine
$PY scripts/replay/selftest.py
```

Requirements: Python 3.11 with the analysis service's `requirements.txt`, `semgrep` on
`PATH`, `node` on `PATH` (the remediation sandbox runs JavaScript proofs), and an
authenticated `gh`. Nothing is written to GitHub: every call is `gh api --method GET`.

Options: `--cache` (default `scripts/replay/.cache`), `--timeout` (per-PR wall clock,
default 300s), `--python` (interpreter for the worker), `--refresh` (bypass the cache),
`--only-pr N` (repeatable, to re-run one pull request while triaging).

## What it does

`replay.py` rebuilds the production payload rather than inventing one. `prodfilters.py`
mirrors, function for function:

| Harness | Production |
| --- | --- |
| `scoped_files` | `fetchPullRequestFiles` in `services/github-service/src/services/githubInternalOperations.js` (added/modified/renamed, not `dist/`, not `node_modules`) |
| `PR_FILE_CAP` | the 200-file 422 in the same function |
| `should_fetch_content` | `shouldFetchFullFileContent` in `services/api-service/src/services/prAnalysisOrchestrator.js` |
| `CONTENT_BYTE_CAP` | the 500 kB drop in `fetchFileContents` |
| `reviewable_line_spans` | `extractReviewableLineSpans` in `services/api-service/src/services/suggestedFixValidator.js` |

If one of those changes in a service, change it here in the same commit or the replay
stops describing production.

Each pull request then runs in its own worker process (`worker.py`), under the wall clock,
so a hang or a hard crash costs one pull request instead of the run:

1. **Tier 1** `analyze_tier1_payload` with the patch-only payload, as the orchestrator sends it.
2. **Tier 2** `analyze_tier2_payload` with head-sha content and reviewable line spans, as the orchestrator sends it after `enrichFilesForTier2`.
3. **Tier 3** skipped. The replay sets `LLM_TRIAGE_ENABLED=false`, the service's own flag, so no model is called. Findings are therefore pre-triage: tier 3 would filter some of them.
4. **Remediation**, for every finding whose `rule_family` and language the engine supports: a `RepairRequest` built from the head-sha content, run through the real `RepairEngine` with the local sandbox driver (`InProcessSandboxBroker(LocalSubprocessDriver())`) and a provider that refuses every call. The template path therefore runs for real; a repair that would need the model is counted as `agent_needed` instead of being made.

## What it records

Per pull request: file count, patch and content bytes, per-stage duration, findings with
their rule and tier, limitations, every exception with its traceback, remediation
candidates produced, verification outcomes, and `agent_needed` counts. `summarize.py`
aggregates across repositories into the markdown tables used by
`docs/validation/real-repo-replay-2026-09.md`.

Raw GitHub responses are cached under `--cache` keyed by request path, so a rerun after a
service fix costs no API calls and compares like for like.

## Caveats

- **Tier 3 never runs.** Every finding count here is pre-triage.
- **The remediation snapshot is not the repository.** A `RepairRequest` needs a complete,
  non-truncated tree; cloning each head commit is out of scope, so the snapshot is the
  pull request's own changed files whose head content was fetched, and the tree OID is
  computed over exactly those. A repair whose proof needs a module outside the pull
  request will fail to verify here for a reason production would not have.
- **Verification is the development sandbox.** `allow_development_verification` is on and
  there is no image digest, so every result carries `development_unverified` and the
  limitations the service attaches to it. This measures pipeline integrity, not repair
  quality.
- **Timings include process start.** Each pull request pays one interpreter start and one
  scanner start; p50/p95 are wall clock for the worker, not service latency.
- **Merged pull requests are mostly not security changes.** Most of what is measured here
  is how the pipeline behaves on ordinary code, which is the point; a run with zero
  repair candidates is expected, and `selftest.py` exists to tell that apart from a broken
  harness.
