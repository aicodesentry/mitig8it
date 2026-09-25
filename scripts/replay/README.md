# Real-repository replay harness

Runs the analysis and remediation pipeline over real public code, so the ways it breaks on
code it has never seen are found here rather than by a customer.

Two modes, because they answer different questions. **Pull request mode** replays recent
merged pull requests and answers "does this rule set annoy a reviewer". **Snapshot mode**
analyses a whole repository tree at a pinned commit and, joined to
`benchmarks/vulnerable-corpus/labels.json` by `score.py`, answers "does this rule set find
anything". A rule that matches nothing and a rule that matches the wrong thing look
identical in the first mode.

## Run

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# one repository, by pull request
$PY scripts/replay/replay.py --repo expressjs/express --prs 15 --out results/expressjs-express.json

# one repository tree at a pinned commit, quarantined rules included so they stay measurable
$PY scripts/replay/replay.py --snapshot --include-quarantined \
    --repo OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
    --out results/nodegoat.json

# aggregate several pull request runs
$PY scripts/replay/summarize.py results/*.json --detail --out /tmp/replay.md

# compare a run after a service fix against an earlier run over the same cache
$PY scripts/replay/summarize.py results-after/*.json --baseline results-before/*.json

# precision and recall of snapshot runs against the corpus labels
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md

# both repair halves over the findings of earlier snapshot runs, and every complete pair's
# proof run against the original tree and against the patched one
$PY scripts/replay/replay.py --pairs --results results/*.json --out /tmp/pairs.json
$PY scripts/replay/summarize.py --pairs /tmp/pairs.json --out /tmp/pairs.md

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

The extension list inside `should_fetch_content` is the one part of this that is now
asserted rather than trusted: `TIER2_CODE_EXTENSIONS` and `TIER2_TEMPLATE_EXTENSIONS` exist
in three places, here and in `opengrep_runner.py` and in `prAnalysisOrchestrator.js`, and
`services/analysis-service/src/tests/test_supported_extension_parity.py` fails if the three
disagree. A drift there is invisible in a replay's output: the harness would simply report
recall over files production never fetches.

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

## Snapshot mode

`--snapshot --ref <40-char sha>` analyses a repository tree instead of pull requests.
`corpus.py` downloads that commit's tarball into `--cache/snapshots` and extracts it there,
refusing any archive member whose path escapes the extraction root; no source tree is
committed. A ref that is not a full commit sha is refused, because a measurement against a
branch name cannot be repeated.

The same production filters apply per file: `should_fetch_content` decides the extension and
the path, and the 500 kB drop is the same one `fetchFileContents` applies. What a snapshot
has to decide for itself is everything a pull request answered by being a diff:

* **Which files.** A tree has no changed-file list, so `corpus.py` walks it and excludes the
  directories a repository checks in but does not author (`node_modules`, `dist`, `vendor`,
  `__pycache__` and the rest of `VENDOR_DIRECTORY_NAMES`), plus every dotted directory.
* **What the patch is.** The whole file as an addition, which is exactly what production
  sends tier 1 for a newly added file, with `reviewable_line_spans` covering every line.
  A snapshot has no diff, so the only faithful reading of "what would be reviewed here" is
  the whole file, and that is also what makes the findings joinable to a line-range label.
* **How much at once.** The analysis service rejects more than 300 files in one payload, so
  a tree is sent in batches of at most 120 files or 1.5 MB, each in its own worker under its
  own wall clock, and the findings are merged.

`--include-quarantined` empties the posting policy inside the worker so a quarantined rule's
findings are recorded. Nothing downstream is fooled: `score.py` re-applies the policy from
the rule files and reports quarantined findings separately. Without it a run cannot tell
whether a quarantined rule has earned its way back.

`score.py` joins findings to labels by repository, ref, path and overlapping line range,
within two lines of slack. Recall falls out of that join. Precision does not, because these
repositories contain far more vulnerabilities than anyone has labelled, so precision is
computed only over adjudicated findings: the ones a label confirms plus the ones read by
hand. `--emit-queue` writes the reading list (every finding on a labelled line under an
unexpected class, plus a seeded random sample of the unlabelled) and `--adjudications` reads
the verdicts back.

## Pairs mode

`--pairs --results <snapshot result files>` answers the question the reach tables leave open:
for a finding that has **both** a template patch and a service-generated proof, does that proof
actually verify, and if not, which of the two trees does it fail on.

It runs no scanner. It reads the findings out of earlier snapshot results and joins them back to
the same pinned tree, so one expensive scan serves any number of these runs, and then calls the
engine's own pieces per finding: `static_gate` decides whether the finding is attempted at all,
`generate_proof` and `generate_template` decide the two halves, and a finding that has both gets
a real `build_patch_bundle` and a real `Verifier` run over the local sandbox. Nothing is
re-implemented, so a pair measured here is the pair the engine would have built.

What each pair records is the whole point: the proof's outcome **on the original tree** and **on
the patched tree** separately, each one's exit code and output tail, the verifier's reason, and
the limitations attached to the run. A pair verifies only when its proof fails on the original
and passes on the patched tree; every other combination is a distinct defect, and collapsing
them into one verdict is what hid them before.

The snapshot a pair runs against is not the whole tree: the remediation service accepts 500
files and the corpus trees are far larger, so the budget is spent nearest the finding first,
after the affected file and the root manifests. What a proof needs from the rest of the tree is
the module its subject imports and the manifest that proves a dependency, and both are there.
The manifests are read whatever their extension: `walk_analysable_files` answers the scanner's
question and `package.json` is not an analysable extension, so until this was fixed the root
manifests the worker's `PAIR_ROOT_FILES` names never actually arrived.

`--with-dependencies` installs each repository's declared dependencies before the pairs run and
lets the sandbox workspace see them. The install is the remediation service's own
`src/sandbox/dependencies.py`, so what is measured is what `policy.install_dependencies` does:
`npm ci --ignore-scripts` from the lockfile the repository carries, `pip install
--only-binary=:all:` into a venv beside the tree, under a ten-minute cap per repository, with
network only for that step. It runs in the worker, once per repository, and caches its result in
a marker beside the cached tree, so a rerun over the same cache costs no `npm ci`; the local
driver is then pointed at the installed tree through `SANDBOX_LOCAL_DEPENDENCY_ROOTS` and links
it into each workspace. The service installs per workspace instead, which is the isolation this
gives up in order to be runnable over hundreds of workspaces. Each record carries its
repository's install under `pairs.install`, and `summarize.py --pairs` renders it as a table.
Deleting `--cache` removes the installed trees with it.

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
