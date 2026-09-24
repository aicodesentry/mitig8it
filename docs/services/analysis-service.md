# Analysis Service

FastAPI service that analyzes changed pull request files.

## Responsibilities

- Accept changed-file PR payloads from the API service.
- Filter scanner rule fixtures. Test code is scanned, not filtered: `src/test_code_scope.py` recognizes `tests/`, `__tests__/`, `test_*`, `*.test.*`, and `*.spec.*`, marks those findings `in_test_code` in `evidence_details.extra`, preserves the scanner's `original_severity`, and reports them as `info` so they are visible without failing a check run.
- Run Tier 1 regex and dependency-risk checks.
- Run Tier 2 OpenGrep rules, in batches bounded by `OPENGREP_BATCH_MAX_FILES` and `OPENGREP_BATCH_MAX_BYTES`. A file larger than the byte budget gets its own batch, and any batch failure raises, so the tier fails closed rather than returning partial results.
- Run optional Tier 3 LLM triage when configured. The Gemini default is `gemini-2.5-flash-lite` and the OpenAI default is `gpt-4o-mini`. Triage failure is non-blocking, and every log line and error body on those paths passes through `redact()` so a misconfigured provider call cannot print credentials.
- Build remediation patch metadata when possible. The repairs themselves are the remediation service's job, not this one's.
- Normalize, cluster, and return finding objects.
- Expose health and Prometheus metrics.

The blocking analysis routes are synchronous handlers, so FastAPI runs them in its threadpool and `/health` does not wait behind a scan. `POST /analyze/pr` runs tier 1 and tier 2 concurrently on a two-worker pool and merges by tier rather than by completion order, so fingerprints and clustering stay stable.

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

For the full env contract, see [environment.md](../getting-started/environment.md).

## Tier 2: the rule set and the posting policy

The AST rules live in `src/opengrep_rules/*.yml`. JavaScript, TypeScript and Python are covered
by 116 rules: 25 that predate the coverage work, and 91 in `javascript_coverage.yml` and
`python_coverage.yml`.

### Where the rules come from

Every rule is written in this repository. No rule is copied or adapted from a public rule
library, because the two obvious ones cannot be used in a paid service: `opengrep-rules` is
LGPL-2.1 **plus the Commons Clause**, which removes the right to sell a service whose value
derives substantially from the rules, and `semgrep-rules` is under the Semgrep Rules License
v1.0, which permits internal business use only and forbids making the rules available as a
service. The reading, with the licence text, is in
[third-party-rules.md](../legal/third-party-rules.md), along with the four steps to follow
before importing a rule from anywhere.

### What a rule must declare

`tests/test_tier2_rule_metadata.py` enforces this on every rule in the two coverage files:

- `cwe`, a `severity` the scanner understands, a `confidence`, and at least one language.
- `internal_type`, from `taxonomy.CANONICAL_INTERNAL_TYPES`. This is what the product groups,
  deduplicates and reports on, so a rule that passes its own check id makes a category of one
  that nothing else can join. Adding a value to that set is a deliberate product decision.
- `family`, when the finding is repairable, and only when the rule's CWE is the one the
  remediation service derives that family from. The engine reads the CWE, not this key, so a
  rule that declared a family its CWE does not produce would be handed to the engine as
  something else.
- `posting`, which is `post` or `quarantine`.
- `precision_evidence`, when someone has measured the rule on a corpus. It must name the
  corpus or the write-up, because a precision claim nobody can re-run is an opinion.

### The posting policy

A rule posts only on evidence. It may post when its labelled precision on a real corpus is at
least 0.8 over at least three labelled findings, or when it produced no findings on the corpus
**and** its pattern is a sink-only match with a clear taxonomy that makes no data-flow
assumption. Everything else is quarantined, and a quarantined rule must carry
`posting_evidence` saying what was measured, because that is what lets the next person
re-enable it.

A quarantined rule still runs and its findings are still counted, in the response's
`quarantined_findings` map and in `codesentry_analysis_quarantined_findings_total`. What it
does not do is reach a reviewer. The removal happens in exactly one place,
`main.partition_by_posting_policy`, which both tiers go through, so the api-service needs no
knowledge of the policy: the findings simply do not arrive, nothing is posted to GitHub,
nothing is counted in the check summary, and nothing is handed to remediation.

The policy is one policy, not a tier 2 one. Tier 1 declares the same states on the rule
object in `security_rules.py` (`precision`, `posting`, `precision_evidence`), and
`main.QUARANTINED_RULE_IDS` is the union of the two declarations, so a suppression, a metric
or a reviewer never has to ask which tier a rule came from.

Five rules are quarantined today: four tier 2 rules, whose measurement is in
[tier2-coverage-2026-09.md](../validation/tier2-coverage-2026-09.md), and the tier 1 rule
`path.traversal.user_path`, whose measurement is in
[vulnerable-corpus-2026-09.md](../validation/vulnerable-corpus-2026-09.md). The same corpus
gave 18 posting tier 2 rules a `precision_evidence` line.

### Re-enabling a quarantined rule

1. Narrow the pattern so the shape it was wrong about no longer matches.
2. Add that exact line to `benchmarks/tier2-precision/cases.json` as a no-finding case, with
   the repository and pull request it came from, and keep the rule's true-positive fixture.
3. Re-run the replay, or the vulnerable-corpus snapshot with `--include-quarantined`, and
   adjudicate what it now produces.
4. Change `posting` to `post` and replace `posting_evidence` with the new measurement.

A rule can also earn its way back without a pattern change, by being measured on code that
contains its shape: `scripts/replay/replay.py --snapshot --include-quarantined` keeps a
quarantined rule's findings, and `scripts/replay/score.py` reports them separately from what
posts. Three adjudicated findings at 0.8 or better is the bar, and it is a real bar:
`cwe-489.py-debug-constant-true` has two, both confirming the quarantine reason was wrong,
and it still cannot come back.

### Rule ids are resolved, not taken as given

Pointed at a directory, the scanner names a rule after the path it loaded it from relative to
the working directory, so the same rule arrives as `opengrep_rules.<id>` from one caller and
`services.analysis-service.src.opengrep_rules.<id>` from another. `canonical_check_id` resolves
the id back to the one the rule file declares. Without it a rule id could not key the posting
policy, a suppression, or a fingerprint.
