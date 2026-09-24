# Analysis Service

FastAPI service that analyzes changed pull request files.

## Responsibilities

- Accept changed-file PR payloads from the API service.
- Filter scanner rule fixtures. Test code is scanned, not filtered: `src/test_code_scope.py` recognizes `tests/`, `__tests__/`, `test_*`, `*.test.*`, and `*.spec.*`, marks those findings `in_test_code` in `evidence_details.extra`, preserves the scanner's `original_severity`, and reports them as `info` so they are visible without failing a check run.
- Run Tier 1 regex and dependency-risk checks.
- Run Tier 2 OpenGrep rules, in batches bounded by `OPENGREP_BATCH_MAX_FILES` and `OPENGREP_BATCH_MAX_BYTES`. A file larger than the byte budget gets its own batch, and a batch that fails outright raises, so the tier fails closed rather than returning partial results.
- Classify the scanner's own errors instead of failing on all of them. A warning-level parse problem in one file (`Lexical error`, `Syntax error`, `Partial parsing`) or a per-file resource ceiling (`Timeout`, `Out of memory`, `Too many matches`) keeps the findings from every other file and is reported as an entry in `analysis_limitations` naming the file, the kind of gap, and the line. Anything at error level that is not attributable to a file, such as an invalid rule or a config error, still fails the tier closed, now with the error types, paths, message prefixes, and the stderr tail in the raised message.
- Run optional Tier 3 LLM triage when configured. The Gemini default is `gemini-2.5-flash-lite` and the OpenAI default is `gpt-4o-mini`. Triage failure is non-blocking, and every log line and error body on those paths passes through `redact()` so a misconfigured provider call cannot print credentials.
- Build remediation patch metadata when possible. The repairs themselves are the remediation service's job, not this one's.
- Normalize, cluster, and return finding objects.
- Expose health and Prometheus metrics.

The blocking analysis routes are synchronous handlers, so FastAPI runs them in its threadpool and `/health` does not wait behind a scan. `POST /analyze/pr` runs tier 1 and tier 2 concurrently on a two-worker pool and merges by tier rather than by completion order, so fingerprints and clustering stay stable.

## Rule posting policy

A finding the product cannot stand behind must not be posted. Every tier 1 rule in `src/security_rules.py` therefore declares two things:

- `precision`, either `measured` or `unmeasured`. `measured` means someone read this rule's output on a real corpus and wrote down what they found, in `precision_evidence`. `unmeasured` means nobody has, which is the honest default.
- `posting`, either `post` or `quarantine`.

A **quarantined** rule still runs. Its matches are counted in `codesentry_analysis_quarantined_findings_total` and returned as `quarantined_findings` (a count per rule) on the tier 1 and combined responses, so the replay harness and the metrics can keep measuring it. What it does not do is arrive: `partition_by_posting_policy` in `src/main.py` is the single place a quarantined finding is removed, and it removes it before the response is built. Nothing downstream needs to know the policy exists. Nothing is posted to GitHub, nothing reaches the check summary, and nothing is handed to remediation, because the finding is not there.

The quarantine is not a deletion. A rule is re-enabled individually, with evidence, by:

1. fixing it, and showing the fix on the lines that were wrong. The false positives the September 2026 replay read by hand live in `benchmarks/tier1-precision/cases.json`;
2. adding its cases to that set, including the true positives it must keep finding;
3. running the gate, `src/tests/test_tier1_precision_benchmark.py`;
4. flipping `posting` to `post` and writing what was measured into `precision_evidence`.

Two structural rules back this up, both enforced by `src/tests/test_rule_posting_policy.py`:

- **A negative condition goes in `exclusion`, not in a lookahead.** `find_ineffective_lookaheads()` in `security_rules.py` is a static check over every regex tier 1 runs. It flags a negative lookahead that an unbounded greedy quantifier precedes with no required token in between, because the engine can always satisfy such a lookahead by letting the quantifier consume to the end of the line. A rule with that shape silently degrades to its leading alternation. `exclusion` is a second pass over the matched line, where backtracking cannot defeat it.
- **Tier 1 does not read comments.** `src/comment_stripper.py` blanks line comments, block comments, JSDoc, Ruby `=begin` blocks and Python docstrings for JavaScript, TypeScript, Go, Java, C#, PHP, Ruby and Python before any regex runs, keeping line numbers and column offsets so a finding still quotes the author's text. It never strips inside a string literal, and an unmodelled extension is not touched at all. A rule can also opt out of seeing string literal bodies with `reads_string_literals=False`; the credential rule keeps them, because a secret lives in a string.

## Tier 1 budget

Tier 1 runs every rule over every changed line, and on the largest payload the caps still allow (200 files of 75 kB) that measured 50 s against the orchestrator's 30 s budget. It is now bounded twice:

- `TIER1_BUDGET_SECONDS` (default 20) is the whole pass;
- `TIER1_FILE_BUDGET_SECONDS` (default 2) is one file.

Exceeding either stops that much of the work, keeps the findings already made, and appends a `{kind: "budget", path, message}` entry to `analysis_limitations` on the response. A partial tier 1 that says how partial it was is worth more than a blown deadline.

## Local Development

```bash
cd services/analysis-service
pip install -r src/requirements.txt
uvicorn src.main:app --reload --port 8001
```

For standalone runs, export the root `.env` first:

```bash
set -a
source .env
set +a
```

## Tests

```bash
cd services/analysis-service/src
pip install -r requirements-test.txt
pytest tests -q
```

## Main Endpoints

- `GET /`
- `GET /health`
- `GET /metrics`
- `POST /analyze/pr`
- `POST /analyze/pr/tier1`
- `POST /analyze/pr/tier2`
- `POST /analyze/pr/tier3`

Analysis requests and metrics require `x-internal-secret`. The expected value is `ANALYSIS_SERVICE_INTERNAL_SECRET` when set, otherwise `GITHUB_SERVICE_INTERNAL_SECRET`.

## Key Environment

- `GITHUB_SERVICE_INTERNAL_SECRET`
- `ANALYSIS_SERVICE_INTERNAL_SECRET`
- `LLM_PROVIDER`
- `LLM_MODEL` / `LLM_TRIAGE_MODEL`
- `LLM_API_KEY`
- `GEMINI_API_KEY` / `OPENAI_API_KEY` provider-specific local fallbacks
- `FRONTEND_URL`
- `ANALYSIS_CACHE_TTL_DAYS`
- `OPENGREP_BATCH_MAX_FILES` / `OPENGREP_BATCH_MAX_BYTES` batch bounds for tier 2
- `TIER1_BUDGET_SECONDS` total tier 1 wall clock, default 20
- `TIER1_FILE_BUDGET_SECONDS` per-file tier 1 wall clock, default 2

For the full env contract, see [environment.md](../getting-started/environment.md).
