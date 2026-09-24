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
