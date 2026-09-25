# Mitig8it Developer Readiness Review

Date: 2026-08-14
Scope: full repository (branch `design/homepage-refresh`, working tree as-is)
Method: five independent senior-level review passes (Node backend services, Python analysis engine, frontend, infrastructure/CI/security, developer adoption), all strictly read-only. Behavioral claims about detection rules and filters were verified by executing the actual module code. No files were modified by the review.

---

## Verdict

The core product loop genuinely works end to end: webhook in, three-tier analysis, findings stored, review posted, dashboard triage. The engineering fundamentals are stronger than average for a project at this stage (see "What is genuinely good" below). But three walls currently stand between this codebase and real developers using it:

1. **Nobody can legally use it.** The repository is public with no LICENSE file, which defaults to all rights reserved. Nobody can adopt, fork, package, or contribute.
2. **Nobody can try it.** Seeing a single finding requires a GitHub App, a GitHub OAuth App, a public webhook tunnel, six containers, and a real PR: realistically 30 to 60 minutes across two GitHub admin consoles. There is no demo mode, no fixture replay, no CLI. The product can be deployed but not tried.
3. **Developers who do try it will not trust it.** Every analysis run can post up to three separate GitHub reviews with duplicated inline comments. Several high-confidence rules flag correct, secure code. A one-comment suffix (`# git add`) makes the entire detection engine skip a line. For a security reviewer, each of these is a credibility killer on first contact.

The highest-leverage work is not new features. It is: a LICENSE, a two-minute no-GitHub-App demo path built on the already-stateless `/analyze/pr` endpoint, and fixing the trust-breaking defects in the detection and comment-posting paths.

---

## Status of previously documented issues

| Item | Status | Evidence |
|---|---|---|
| TASK-01 production migrations | **Fixed** | `Dockerfile.prod` copies migrations; runner throws on missing dir; advisory lock; CI runs migrate/verify/migrate |
| TASK-02 suppression repo scoping | **Fixed** | `suppressions.js:52-61` scopes on `repository_id`, 404 on mismatch; tests exist |
| TASK-03 webhook dedup | **Open** | `routes/webhooks.js:51-65` still check-then-insert, ignores `processing_status`; failed deliveries stay permanently deduplicated |
| Jest `testMatch` (product analysis item 6) | **Open** | `jest.config.js:4` still excludes `src/__tests__/`; 43 tests (encryption, fingerprinting, auth middleware) never run in CI |
| Dead code playground (item 17) | **Open** | `analysis_routes.py` never mounted in `main.py`; frontend nav still links to it |
| Benchmark credibility (Move 1) | **Open** | Docs describe CLI flags `eval.py` does not have; committed results from a harness version that no longer exists; empty `gpt-5.5_results.json` still committed |

---

## Critical findings

### C1. Public repo, no LICENSE, no security policy
No LICENSE, SECURITY.md, CONTRIBUTING.md, or CODEOWNERS anywhere in the 302 tracked files. Two review passes independently ranked this first. A security product without a vulnerability disclosure policy is the specific thing external reviewers notice immediately. Effort: trivial.

### C2. Universal detection bypass via the "transcript artifact" filter
`services/analysis-service/src/finding_quality.py:6-28,47-54` (applied at `:114` and `opengrep_runner.py:75,78`). Any changed line containing `pytest`, `git add `, `git checkout `, `gh pr create`, or starting with `Bash(`/`Read(`/`Write(` is silently excluded from Tier 1 and Tier 2. Verified by execution: `os.system(user_input)  # git add helper` is skipped entirely. This is a dogfooding hack that shipped into the detection path. Fix: delete the filter, exclude self-scan noise by file path instead, and add a regression test asserting a `# git add` suffixed line is still scanned.

### C3. Prompt injection can delete findings via Tier 3 triage
`services/analysis-service/src/llm_triage.py:559-562,648-660,696-702`. Analyzed patch text is serialized into the prompt with no untrusted-data framing; a `false_positive` verdict deletes the finding outright and severity adjustments have no floor. A PR author can embed triage instructions in a comment or string literal to suppress findings about their own code. Fix: delimit analyzed code as untrusted data, never let a verdict delete a critical/high deterministic finding (demote to uncertain instead), clamp severity adjustment to one level.

### C4. Every analysis run posts up to three reviews with duplicated inline comments
`services/api-service/src/prAnalysisOrchestrator.js:827,851,903` each call `postReviewToGitHub`; Tier 2 and Tier 3 operate on the accumulated findings from earlier tiers, and dedupe only looks within a batch, never at comments already on the PR. Every `synchronize` event repeats the whole cycle. This is the single most user-visible defect: the product output surface IS the PR comments. Fix: post one review per run, key inline comments by `(path, line, fingerprint)` in an HTML marker, reconcile with create/update/delete deltas.

### C5. `main` is unprotected and auto-deploys to production
Verified via GitHub API: no branch protection, no rulesets. All four deploy workflows trigger on CI success on `main`, and `deploy-api-cloudrun.yml:111-119` runs production DB migrations on the way, with no backup, no `--no-traffic` canary, and no rollback step. `workflow_dispatch` additionally deploys any ref with zero CI. The `ci-required` aggregate job exists specifically to be a required check; nothing requires it. Fix: ruleset on `main` (PR + approval + `ci-required` + enforce admins), gate dispatch deploys on a verified passing CI run, attach `environment: production` to the deploy jobs (two GitHub Environments already exist and are unused), snapshot the DB before migrating, deploy tagged with `--no-traffic` and shift traffic after smoke.

### C6. Stale-run reclaim can execute the same analysis twice, concurrently
`services/api-service/src/db/analysisRuns.js:117-160` reclaims runs older than 20 minutes with no lease owner, no fencing token, no attempt counter, and no heartbeat. A run posting 40 sequential inline comments can legitimately exceed 20 minutes, at which point a second worker claims it: both post reviews (compounding C4), the second insert hits the unique fingerprint index and marks the run failed, possibly overwriting the first worker's completion. A permanently slow run is reclaimed forever and starves the queue. Fix: `lease_owner`/`lease_expires_at`/`attempt_count` columns, ownership-checked terminal writes, dead-letter after N attempts, wall-clock budget under the stale window.

### C7. There is no way to try the product without a GitHub App
Verified: no demo mode, no seeded data, no fixture replay anywhere in services or frontend; the dashboard is fully gated behind GitHub OAuth; the one "paste code" surface (playground) hits an endpoint that is never mounted. The cheapest credible fix already 90 percent exists: `POST /analyze/pr` is stateless and `scripts/e2e-happy-path.sh` already demonstrates driving it with a synthetic vulnerable patch. Needed: map port 8001 in a demo compose profile, a `demo-analyze.sh` that posts a local `git diff`, three or four checked-in vulnerable diff fixtures, and a README section "See a finding in 2 minutes, no GitHub App required."

### C8. A Vercel deploy produces a site where nobody can log in
`frontend/vercel.json:2-7` rewrites everything to `index.html` with no `/api` or `/auth` exclusions, so `GET /auth/me` returns the SPA shell and every user lands logged out. Firebase has the correct Cloud Run rewrites; Vercel has none, no CI workflow, and no `VITE_API_URL`. Two competing deploy stories in one repo also confuses contributors. Fix: delete `vercel.json`, `.vercelignore`, and `.vercel/`, making Firebase the single documented target (or fully wire Vercel; pick one).

### C9. Dashboard is unnavigable below 1024px
`frontend/src/components/DashboardLayout.jsx:35`: the sidebar is `hidden ... lg:flex` with no hamburger or drawer fallback. Below `lg`, navigation, theme toggle, and the logout button are unreachable; a phone user is stranded on one page. Fix: `lg:hidden` menu button toggling the aside, backdrop, Escape handler.

---

## The structural theme: production runs the untested path

Two review passes independently converged on this. It deserves its own section because it explains many individual findings:

- Production sets `INTERNAL_SERVICE_TRANSPORT=grpc` and `SERVICE_MODE=grpc`. The gRPC servers have **no in-app auth** (no interceptor checking the internal secret; the HTTP equivalents do check it), **no retries** (the retry logic lives in the HTTP client), and in gRPC mode github-service **serves no HTTP `/health` or `/metrics` at all**, so Prometheus scraping is silently broken and the analysis service's metrics increment into a process nothing scrapes.
- The proto schema (`common.proto`) has no `llm_triage` field and parsing ignores unknown fields, so **the entire Tier 3 verdict block is silently discarded on the production transport**. The HTTP path, which carries it correctly, is dev-only.
- All 43 orchestrator tests drive `triggerAnalysisJob`, a function no production code calls, and mock axios (the HTTP transport). Zero tests exist for the gRPC clients, servers, or claim/lease semantics.
- CI's docker-build job builds the dev `Dockerfile`s; the `Dockerfile.prod` files that actually ship are built for the first time inside the deploy workflow, ungated.
- Every image pins `node:18-alpine` (end-of-life April 2025) while CI tests on Node 20, and `frontend/Dockerfile` cannot even start: Vite 8 requires Node 20+, so the documented `docker compose up` path fails for the frontend.

Fixes, in order: add a gRPC auth interceptor mirroring the HTTP check (with constant-time compare), add `LlmTriage` to the proto with a contract test that sets `ignore_unknown_fields=False`, keep a small HTTP server for `/health` and `/metrics` alive in gRPC mode, move retry/backoff into a transport-agnostic wrapper (or delete one transport), build the prod Dockerfiles in CI, move everything to Node 22 in lockstep, and rewrite the orchestrator tests against `processQueuedAnalysisRun`.

---

## High-priority findings by area

### Backend services (api-service, github-service)
- **Fresh installation token minted per GitHub operation** (`githubAppAuth.js:39-81`): a 40-comment run performs 40 unnecessary token mints. Cache per installation with expiry, as already done for Cloud Run identity tokens.
- **No GitHub rate-limit handling**: `Retry-After` and `x-ratelimit-reset` ignored; 403 secondary limits treated as hard failures; unbounded pagination fetches 3,000 files to keep 200.
- **Service boundary violated in both directions**: github-service opens its own `pg.Pool` (unbounded, never closed) and writes to shared tables; api-service calls `api.github.com` directly and duplicates App JWT logic, so the App private key lives in two services. github-service also carries a second, fail-open webhook ingress (`routes/webhooks.js:41-44`) with one fully unauthenticated endpoint; it is unreachable in production but live in local dev. Delete it (TASK-03 already anticipates this).
- **Fingerprints are line-number and snippet sensitive** (`findingUtils.js:5-13`): any line shift re-fingerprints a finding, silently breaking the user's suppressions and re-posting comments. Exclude or bucket line numbers, version the scheme.
- **CORS allowlist admits any `*.web.app` origin containing "codesentry"** (`app.js:45-54`): Firebase subdomains are self-service, so `codesentry-evil.web.app` gets credentialed CORS. Exact-match allowlist from env.
- **Installation sync does minutes of unbounded synchronous GitHub work inside one HTTP request** (`routes/installations.js:155-319`), with access rows deleted before the failure-prone part and errors swallowed. Convert to a queued job.
- **Unhandled route errors leak raw Postgres messages** to clients; almost no input validation on write paths; OAuth `state` is not bound to the browser (replayable within 10 minutes); host-header-derived redirect when `FRONTEND_URL` is unset.
- **Nine env vars that change fundamental behavior are documented nowhere**, including `INTERNAL_SERVICE_TRANSPORT`, `SERVICE_MODE`, `AUTO_MIGRATE`, and all six gRPC vars. A developer following the docs runs a different transport locally than production uses.

### Analysis engine
- **The highest-confidence SQL injection rule flags correctly parameterized queries** (`security_rules.py:174-177` matches `%s` placeholders, the safe pattern). Verified by execution.
- **Five rules use a negative lookahead after `.*` that is a no-op**, so "missing auth check" style rules fire on code that has the auth check (`security_rules.py:42,76,291,580,615`). Verified. Two more rules are structurally dead (multi-line patterns matched per single line).
- Broader false-positive surface, all verified against safe inputs: `yaml.safe_load` variants flagged as critical deserialization, `postgres://localhost` dev strings flagged as hardcoded credentials (0.94 confidence), pandas `df.eval` as code injection, browser `DOMParser` as XXE, nearly any method chain as null deref. Confidence values are hand-assigned with no calibration corpus, and clustering can only ever raise severity and confidence, never lower.
- **Path traversal in the OpenGrep runner** (`opengrep_runner.py:474-478`): request-supplied file paths are joined into a temp dir without normalization; absolute paths escape it entirely. Requires a compromised caller, but it is the one place attacker-influenced content is written to disk.
- **Blocking work inside async handlers**: one large PR blocks the event loop, including `/health`, for up to about 165 seconds. No cap on concurrent semgrep processes, no memory limits, no Cloud Run concurrency/cpu/memory settings: OOM under load is the expected failure mode.
- **The combined `/analyze/pr` endpoint feeds Tier 2 a synthetic file with fabricated line numbers** (drops `content`), so inline comments can land on wrong lines; `reviewable_line_spans` is plumbed end to end and never read, so findings on untouched pre-existing code surface as PR findings.
- **Hand-maintained dependency vulnerability regexes are factually wrong** (requests CVE range misses 2.28-2.30; express range misses the actually vulnerable band). Query OSV.dev or drop the tier in favor of Dependabot, which the repo already runs.
- **Deterministic auto-fixes are semantically wrong** in several cases (JS `eval` replaced with `JSON.parse`; `document.write` fix wipes the document body; command injection "fixed" by deleting the feature; SQL placeholders hardcoded to MySQL syntax). LLM-authored patches get only cosmetic validation before being rendered as GitHub suggestion blocks.
- About 1,000 lines of dead playground code (`analysis_routes.py`, `vertex_ai_service`, etc.); `.env.example` advertises `ANTHROPIC_API_KEY`, which the client does not support; everything is branded OpenGrep but shells out to `semgrep` (license implications worth resolving deliberately).

### Frontend
- **The sidebar advertises fiction and hides the real thing**: Subscription page is hardcoded pricing with dead Upgrade buttons and zero backend billing routes; Profile notification toggles persist nothing; the Code Playground nav item points at an unreachable service (and the endpoint behind it has no auth, only a localStorage counter as rate limit); meanwhile the Suppressions and Settings routes exist but are absent from the nav array, reachable only by typing URLs.
- **Triage pages have no error states**: five pages terminate failures in `console.error`; a failed fetch renders "No suppressions configured", and a finding detail fetch failure shows "Loading finding..." forever. Mutations (suppress, dismiss) have no try/catch or pending state. An already-written `ErrorBoundary` component is never mounted, so any render throw is a white screen.
- **Triage exposes a fraction of the backend**: `GET /api/findings` (cross-repo, filterable) is wired in the API client and called by nothing; there is no way to answer "what are my open criticals across all repos". Suppress hardcodes reason and notes; retry and baseline endpoints have no UI.
- **N+1 fanout on dashboard mount**: one `listPRs` call per repository (31 requests for 30 repos) against a 400 req/10 min rate limit, refetching a list already held in context.
- Two broken Tailwind classes from a bad `gray` to `neutral` find/replace (`tranneutral-x-*`): the notification toggle knob never visibly moves. A dead OAuth callback page, route, and Firebase rewrite (backend never redirects there). One 470 KB chunk with all 22 pages statically imported. The Tailwind v4 migration itself (the deleted `tailwind.config.js`) was verified sound.

### Infrastructure and CI
- **Three internal secrets ship as plaintext Cloud Run env vars** instead of Secret Manager (readable in every historical revision spec), and the webhook secret now has two sources of truth that can silently drift.
- **Production `DATABASE_URL` is written unmasked into `$GITHUB_ENV`**: runtime-fetched secrets are not registered with the log masker, and this repo's build logs are public. Add `::add-mask::` or never persist it.
- **All eight containers run as root on unpinned bases**, no multi-stage builds; `grafana/agent:latest` is unreproducible by construction. No `docker` ecosystem in Dependabot, which is why Node 18 went EOL unnoticed.
- One static shared secret authenticates every internal boundary including `/metrics`, with no rotation story. Local compose publishes Postgres (default password `devpass123`) and lifecycle-enabled Prometheus to `0.0.0.0`; the full root `.env` (App private key included) is injected into all four containers including the frontend. `frontend/` has no `.dockerignore` while its Dockerfile does `COPY . .`.
- Webhook endpoint accepts 10 MB unauthenticated bodies with no rate limit on an `--allow-unauthenticated` service (cost/DoS surface; HMAC itself is done right). `firebase.json` sets no security headers, and the raw `run.app` URL bypasses anything added at the Firebase layer.
- Deploy jobs mutate IAM on every run and fall back to the over-privileged default compute service account when the runtime SA var is unset.

### Documentation and onboarding
- `scripts/e2e-happy-path.sh`, the first "verify it works" script a newcomer runs, fails against the documented default stack: it targets `localhost:8001` but compose does not map that port.
- The OAuth App requirement is contradictory: docs call the client ID/secret optional, `validate-env.sh` hard-fails without them.
- `docs/getting-started/github-app.md` tells the reader to create the App under the internal `aicodesentry` account, and never mentions GitHub App Manifests, which would collapse the hardest onboarding step to one click.
- No troubleshooting doc for the actual first-run failures (PEM newline mangling, webhook signature mismatch, "installed the App but nothing happens"). No API reference for `/analyze/pr`. No rule-authoring guide; the Tier 2 metadata contract (`analysis_scope`, `source_var`, confidence as string) is discoverable only by reading `opengrep_runner.py`. Benchmark docs describe CLI flags that do not exist.
- The codesentry/mitig8it naming split is honestly disclosed but still leaks into everything newcomers type (DB name, secret names, env aliasing like `WEBHOOK_SECRET` vs `GITHUB_WEBHOOK_SECRET` with `process.env` mutation to paper over it).
- The public `/benchmarks` marketing page is backed by a 42-sample self-referential eval that measures a raw LLM, not the shipped pipeline, with a committed empty results file. A skeptical developer finds this in minutes. Either rebuild the benchmark or reduce the page to methodology.

---

## What is genuinely good

Recorded so it does not get "fixed" and because it is real adoption collateral:

- **No secrets have ever been committed**: verified across all 711 commits, including deleted files. `.gitignore` and the service `.dockerignore` files are thorough and correct.
- CI is above average: 9 jobs including gitleaks, dependency review, npm/pip audit, bandit, per-service tests, and a migrate/verify/migrate idempotency check. Actions are SHA-pinned (one exception) with least-privilege permissions.
- Webhook HMAC verification uses `crypto.timingSafeEqual` and fails closed. Auth uses an httpOnly cookie (not localStorage) with a correctly paired origin+header CSRF gate. Cloud Run deploys prefer Workload Identity over service-account keys.
- The migration runner (advisory lock, fail-on-missing) and the suppression scoping fix are both solid; TASK-01 and TASK-02 were done properly.
- Real test suites exist: 267 tests in the analysis service, 43 more in api-service (currently orphaned by the testMatch bug), and the frontend's 38 tests, lint, and build all pass clean.
- The onboarding state machine in `OnboardingContext` is well modeled, and `docs/architecture/limitations.md` and `security-guardrails.md` have exactly the honest tone that wins skeptical developers; they should be linked from the README, not buried.

---

## Roadmap

### Weeks 1-2: make it triable and safe (all Small effort)
1. Add LICENSE, SECURITY.md, CONTRIBUTING.md, CODEOWNERS.
2. Turn on branch protection for `main` and gate `workflow_dispatch` deploys; attach `environment: production` to the four deploy jobs.
3. Ship the demo path: demo compose profile mapping port 8001, `demo-analyze.sh`, checked-in vulnerable diff fixtures, "see a finding in 2 minutes" README section.
4. Delete the transcript-artifact filter (C2) with a regression test.
5. Land TASK-03 and the one-line jest `testMatch` fix (both are repeat audit findings).
6. Fix `frontend/Dockerfile` to `node:20-alpine` + `npm ci` so `docker compose up` works; fix `e2e-happy-path.sh` port mismatch.
7. Delete `vercel.json`/`.vercel` artifacts (single deploy story), remove Subscription and the dead playground/auth-callback from the frontend, add Suppressions to the nav.
8. Move the three plaintext deploy secrets to Secret Manager and mask the fetched `DATABASE_URL`.
9. Rewrite `github-app.md` for an external audience; document the nine missing env vars.

### Month 2: make it trustworthy (Medium effort items)
1. Idempotent review posting: one review per run, marker-based comment reconciliation (C4).
2. Lease/fencing on `analysis_runs` with attempt caps and dead-lettering (C6).
3. Close the gRPC gap: auth interceptor, `LlmTriage` in the proto with a contract test, HTTP health/metrics in gRPC mode, prod Dockerfiles built in CI, Node 22 everywhere.
4. Fix the false-positive rules (SQL `%s`, the five no-op lookaheads, dead rules), then build a true-negative corpus from this repo's own source and gate rule PRs on it in CI.
5. Harden Tier 3: untrusted-data framing, no deletion of critical/high deterministic findings, severity clamp, chunked requests with partial JSON recovery.
6. Frontend trust surface: mount ErrorBoundary, real loading/error/pending states on the five triage pages, mobile navigation drawer.
7. Bound the analysis service: async-correct handlers, semgrep concurrency semaphore and memory caps, Cloud Run resource settings, path traversal guard.

### Quarter: make it adoptable (the distribution wedge)
Ranked by adoption payoff against effort, grounded in what the code supports today:

1. **CLI / local-diff mode (S)**: a `mitig8it scan` wrapper piping `git diff` into `/analyze/pr`. Zero new engine code; the week-1 demo script is its prototype. This is the funnel entry for everything below.
2. **GitHub Action wrapper, BYO LLM key (M)**: same engine invoked in-runner on `pull_request`, posting a check run with the workflow's own token. No App, no webhook, no tunnel, no hosting. Nothing in the code blocks it: `/analyze/pr` has no DB dependency. The stateless Action loses suppressions/baselines, which is exactly the upsell into the hosted App.
3. **Hosted GitHub App with one-click manifest install (M-L)**: the Cloud Run deployment exists; needs the App Manifest flow, sign-up polish, and the month-2 correctness items before unattended multi-tenant operation is safe. Do not lead with this while C4/C6 are open.
4. **Single-container self-host image (M)**: credible only after github-service is collapsed into api-service (its 257-line surface and both-directions boundary violations make this the right call anyway) and the codesentry rename is finished.

Supporting work in the same window: a `/dashboard/findings` cross-repo inbox backed by the already-existing endpoint, an OpenAPI spec for `/api` plus a rule-authoring guide, the rebuilt benchmark (pipeline-in-the-loop, external CVE corpus, per-tier attribution, CI regression gate), and a `DEMO_MODE` seeded dashboard.

---

## One-paragraph summary

Mitig8it's plumbing is real and its hygiene is better than most early-stage codebases, but it is currently a product that can only be deployed, not tried, not legally adopted, and not yet trusted with a skeptical developer's first PR. The order of operations that changes that: LICENSE and branch protection this week; the two-minute demo path and the detection-bypass fix next; then idempotent PR comments, the gRPC trust gap, and the false-positive purge; then distribution through a CLI and a GitHub Action, with the hosted App last. Almost everything in the first month is small, precisely located work; the file-and-line references above are sufficient to hand each item to an implementer directly.
