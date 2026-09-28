# The codesentry namespace

The product is Mitig8it. It was called CodeSentry, and the rename was never finished.
[overview.md](overview.md) admits this in one line: "The repository still uses the `codesentry`
namespace in database names, metrics, package metadata, and Cloud Run resources." An architecture
review flagged that line as a maintenance smell in a product about to be published and pinned by
strangers.

This page is the inventory behind that one line. It is not a rename and it does not propose one
wholesale. Some of these strings name live Cloud Run services, live Secret Manager secrets, a live
database and published identifiers other people pin, so a find and replace across the tree would
take production down while looking like a tidy-up. The useful work is telling those apart from the
strings that are only words, and this page does that, with a staged plan and an explicit list of
things that should stay as they are forever.

Nothing on this page is changed by this page. No rename is performed here.

## How the counts were measured

Every number below counts matching lines, not files and not occurrences within a line. The
population is:

```
grep -rIin codesentry --exclude-dir=.git --exclude=codesentry-namespace.md .
```

330 matching lines across 67 files, at `3f26cb08`, the tip of `main` this branch was cut from. This
page excludes itself, since it names the string on almost every line.

The lines were then partitioned in priority order by a sequence of `grep -E` filters, each applied
to what the previous filters left, so every line lands in exactly one bucket and the bucket counts
sum to 330. The filter for each bucket is given with that bucket below. Running them in the order
they appear reproduces the table.

## Summary

| Bucket | Lines | Files | What it is |
| --- | --- | --- | --- |
| Deploy-time identity | 208 | 24 | Cloud Run service and job names, Secret Manager secret names, GCP project and Firebase site ids, GitHub Actions variables and secrets |
| Published surface | 56 | 22 | The `aicodesentry/mitig8it` slug and the ghcr image built from it, plus nine Prometheus series still emitted as `codesentry_*` |
| Historical record and scored fixtures | 40 | 13 | Dated reviews, release notes, a validation log, the changelog, two benchmark corpora |
| Persistent state | 12 | 6 | The Postgres database name, and two keys in visitors' browser storage |
| Internal code | 6 | 4 | npm package metadata and two adversarial test fixtures |
| Cosmetic | 8 | 5 | Prose, a file header, a CLI description string |
| **Total** | **330** | **67** | |

The distribution is the finding. Two thirds of the remaining namespace is deploy-time identity, and
almost all of the rest is either a published identifier or a record of the past. The genuinely free
part of the rename, prose and package metadata, is 12 lines.

## Deploy-time identity

208 lines in 24 files. Four filters, applied in this order:

```
grep -E '(codesentry-260311-9f2b|codesentry-staging)'                       # 21 lines, 7 files
grep -E 'CODESENTRY_'                                                      # 40 lines, 7 files
grep -E 'codesentry-(database-url|jwt-secret|encryption-key|github-app|github-client|webhook-secret|gemini-api-key|repair-llm|remediation-internal-secret|gmp-config)'   # 81 lines, 13 files
grep -E 'codesentry-(api|github|analysis|remediation)'                     # 66 lines, 19 files
```

Every string in this bucket is the name of a thing that exists in a Google Cloud project or in this
repository's GitHub settings. The repository does not own these names; it only refers to them.
Changing a reference without changing the named thing does not produce a rename, it produces a
deploy that cannot find what it needs.

**Cloud Run services and the sandbox job.** `codesentry-api`, `codesentry-github`,
`codesentry-analysis`, `codesentry-remediation`, the four `-staging` siblings, and the Cloud Run job
`codesentry-remediation-sandbox`. Declared in the `SERVICE=` lines of the four deploy workflows
(`.github/workflows/deploy-api-cloudrun.yml:128` and its three peers) and defaulted in
`infrastructure/remediation/terraform/cloud_run_job.tf:44`.

A Cloud Run service name is part of its URL and cannot be edited. Deploying under a new name creates
a second service at a second URL and leaves the old one serving. What breaks if the workflow name is
changed alone: the new service has no `run.invoker` binding for the API's runtime service account, so
every API call to the github and analysis services fails closed; the GitHub App webhook still points
at the old API URL, so nothing arrives; `firebase.json` still rewrites `/api/**` to `serviceId:
codesentry-api`, so the dashboard talks to the abandoned revision; the managed Prometheus sidecar
config in `infrastructure/monitoring/runmonitoring.yaml:18` still names `codesentry-api` as its
target, so metrics stop; and the alert policy in `infrastructure/monitoring/main.tf:131` keeps
watching a service that no longer receives traffic, which reads as a healthy silence rather than an
outage. The old services also keep costing money and keep accepting webhooks.

**Secret Manager secret names.** Thirteen production secrets and thirteen `-staging` counterparts,
listed in full at `docs/deployment/cloud-run-firebase.md:68` onwards and
`docs/deployment/staging.md:121` onwards. They are wired by name in the `--set-secrets` arguments of
the deploy workflows, for example `.github/workflows/deploy-api-cloudrun.yml:230` through
`:238`. `codesentry-gmp-config` is a fourteenth, mounted as a file rather than an environment
variable, at `:256`.

A Secret Manager secret name cannot be edited either. A new name means creating a new secret,
copying the value, and granting the runtime service account `secretAccessor` on it. What breaks if a
workflow reference is changed alone: `gcloud run deploy` fails at admission with a permission or not
found error on the secret, so the revision never starts and the previous revision keeps serving.
That failure mode is the mild one, because it is loud and it does not roll forward. The sharp one is
`codesentry-database-url`: `.github/workflows/deploy-api-cloudrun.yml:162` reads it before the deploy
to run `npm run db:migrate` from the release image, so a rename there breaks the migration step,
which is the step that has to succeed before a new schema-dependent revision is allowed out.

**GCP project id and Firebase hosting sites.** `codesentry-260311-9f2b` is the GCP project id and
also the default Firebase hosting site id; `codesentry-staging` is the staging site. A GCP project id
is immutable for the life of the project. Renaming it means a new project, which means new services,
new secrets, new IAM, a new database instance and a new GitHub App webhook URL. It appears in
`infrastructure/monitoring/terraform.tfvars.example:3`, the Artifact Registry path in
`infrastructure/remediation/terraform/cloud_run_job.tf:55`, the Firebase site default in
`.github/workflows/deploy-frontend-firebase.yml:100`, and, notably, in shipped application code:
`services/api-service/src/app.js:33` puts `https://codesentry-260311-9f2b.web.app` in the CORS
allowlist. Two tests pin that exact origin
(`services/api-service/tests/cors.test.js:16` and `:20`). Changing the literal without changing the
hosting site logs out every dashboard user served from that site, because credentialed CORS fails and
the session cookie is `SameSite=None`.

The Artifact Registry repository is a related case. It is named `codesentry`, visible in the image
path at `cloud_run_job.tf:55`, but the deploy workflows read it from the repository variable
`vars.GAR_REPOSITORY` rather than hardcoding it. A new repository can therefore be created and the
variable repointed without touching workflow code, at the cost of losing the layer cache and leaving
old digests unreachable under the new path. Any image currently referenced by digest, including the
pinned sandbox job image, keeps resolving only through the old repository.

**GitHub Actions repository variables and secrets.** Seven variables and two secrets:

| Name | Kind | Read at |
| --- | --- | --- |
| `CODESENTRY_FRONTEND_URL` | variable | api, github, analysis, frontend deploys |
| `CODESENTRY_FRONTEND_URL_STAGING` | variable | the same four, staging branch |
| `CODESENTRY_GH_SERVICE_URL` | variable | `deploy-api-cloudrun.yml:103` |
| `CODESENTRY_GH_SERVICE_URL_STAGING` | variable | `deploy-api-cloudrun.yml:109` |
| `CODESENTRY_ANALYSIS_URL` | variable | `deploy-api-cloudrun.yml:104` |
| `CODESENTRY_ANALYSIS_URL_STAGING` | variable | `deploy-api-cloudrun.yml:110` |
| `CODESENTRY_API_RUNTIME_SERVICE_ACCOUNT` | variable | `deploy-github-cloudrun.yml:185`, `deploy-analysis-cloudrun.yml:182` |
| `CODESENTRY_INTERNAL_SECRET` | secret | api, github, analysis deploys |
| `CODESENTRY_WEBHOOK_SECRET` | secret | `deploy-github-cloudrun.yml:174` |

These are the one part of this bucket that is genuinely cheap to change, because the settings side is
two clicks and the value is copied rather than migrated. They are also the most dangerous to change
carelessly, because GitHub Actions resolves an undefined `vars.X` or `secrets.X` to the empty string
rather than failing. What breaks if the workflow reference is renamed and the repository variable is
not: the deploy succeeds. `FRONTEND_URL=''` means the API falls back to `http://localhost:5173`,
which silently removes the production origin from the CORS allowlist. `GITHUB_SERVICE_INTERNAL_SECRET=''`
means both ends compare empty strings, so the internal authentication check passes for anyone who
sends no header. `CODESENTRY_API_RUNTIME_SERVICE_ACCOUNT=''` means the `run.invoker` binding is added
for nobody. None of that shows up as a red deploy. If any of these is renamed, the rename and the
settings change have to land together, and the workflow should be given a guard that refuses an empty
value rather than continuing.

## Published surface

56 lines in 22 files, in two unrelated groups.

```
grep -E '[Aa][Ii][Cc]ode[Ss]entry'    # 43 lines, 17 files
grep -E 'codesentry_'                 # 13 lines, 5 files (after the frontend keys are taken out)
```

**The GitHub org slug, and the image named after it.** The organisation is `aicodesentry`, so the
repository is `aicodesentry/mitig8it` and the released container is
`ghcr.io/aicodesentry/mitig8it-action`. Every documented install string contains it:
`README.md:38`, `action/README.md:25`, `docs/getting-started/github-action.md:27`,
`docs/releasing.md:116`. `action/action.yml:131` compares `ACTION_REPOSITORY` against the literal
`aicodesentry/mitig8it` to decide whether to pull the published image or build from source, and
`action/tests/test_released_image.py:32` and `:33` pin both strings.
`action/tests/test_release.py:343` asserts the image name is declared once in the release workflow
and repeated in `docs/releasing.md`.

This is the class where a rename breaks other people rather than us. `uses: aicodesentry/mitig8it/action@v1`
is the string in every reader's workflow file. An org rename leaves a GitHub redirect in place for
the repository, but `action/action.yml:131` does an exact comparison on the resolved repository name,
so a redirected `uses:` would fail that check, log that the action did not come from
`aicodesentry/mitig8it`, and silently build the image from source instead of pulling the attested
release. Every pinned digest under `ghcr.io/aicodesentry/mitig8it-action` and every attestation
verified with `--owner aicodesentry` (`docs/releasing.md:107`) is tied to the old owner. This should
not change. The org name is an awkward fossil of the old product name and it is also the only stable
identity the action has.

**Prometheus series still named `codesentry_*`.** Nine series:

| Series | Emitted by |
| --- | --- |
| `codesentry_http_request_duration_seconds` | `services/api-service/src/utils/metricsRegistry.js:10` |
| `codesentry_analysis_requests_total` | `services/analysis-service/src/main.py:88` |
| `codesentry_analysis_findings_total` | `services/analysis-service/src/main.py:90` |
| `codesentry_analysis_duration_seconds` | `services/analysis-service/src/main.py:95` |
| `codesentry_analysis_quarantined_findings_total` | `services/analysis-service/src/main.py:100` |
| `codesentry_llm_triage_requests_total` | `services/analysis-service/src/llm_triage.py:21` |
| `codesentry_llm_triage_duration_seconds` | `services/analysis-service/src/llm_triage.py:26` |
| `codesentry_llm_triage_verdicts_total` | `services/analysis-service/src/llm_triage.py:31` |
| `codesentry_llm_triage_tokens_total` | `services/analysis-service/src/llm_triage.py:36` |

The product counters were already renamed. Everything queried by an alert or a dashboard in this
repository is `mitig8it_*`: `infrastructure/monitoring/main.tf:120`, `:134` and `:196`,
`infrastructure/remediation/grafana/alerts/remediation-rules.yaml:35`, `:37`, `:40`, `:65` and `:91`,
and all ten series in `infrastructure/remediation/grafana/dashboards/remediation-overview.json`.

Nothing in this repository queries any of the nine. Verified with:

```
grep -rn 'codesentry_' infrastructure/ docs/runbooks/ docs/operations/
```

which returns nothing. That result, plus one fact from
`docs/operations/observability.md:16` ("The github and analysis services expose `/metrics` and
nothing scrapes them. Only `codesentry-api` runs the sidecar"), reduces this bucket sharply. Eight of
the nine series come from the analysis service, which is not scraped in production, so they exist in
no Cloud Monitoring time series and no dashboard can be querying them. Only
`codesentry_http_request_duration_seconds` is scraped, through the sidecar whose config names
`codesentry-api`, and nothing in the repository queries that either.

So this group is published in the sense that it is on the wire, and effectively unqueried. The risk
is an ad hoc Grafana panel or a saved Cloud Monitoring chart outside the repository that names one of
them. The way to retire them safely is the standard Prometheus one: emit both names for one
retention window and then drop the old, which prom-client and the Python client both support by
declaring a second metric with the same labels.

**One live inconsistency, surfaced by this inventory.** `scripts/e2e-happy-path.sh:15` and `:17`
assert the API metrics endpoint contains `mitig8it_http_request_duration_seconds`. The API emits
`codesentry_http_request_duration_seconds`. The two disagree, so that smoke check cannot pass. It has
gone unnoticed because the script is not run by any workflow; it appears only in
`docs/getting-started/local-dev.md:86` and `docs/deployment/p0-rollout.md:56`, both of which are
manual steps. Meanwhile `services/api-service/tests/metricsLoopback.test.js:45` asserts the
`codesentry_` name and does run in CI, under the `api-tests` job. The renamer changed the reader and
not the writer. This is the one place in the whole inventory where the half-finished rename is
already a defect rather than a smell.

## Historical record and scored fixtures

40 lines in 13 files.

```
grep -E '^(docs/history/|docs/release-notes/|docs/validation/|CHANGELOG\.md|benchmarks/vulnerable-corpus/|benchmarks/secrets-precision/)'
```

Dated engineering reviews (`docs/history/PRODUCT-ANALYSIS-2026-08-08.md:83`,
`docs/history/DEVELOPER-READINESS-REVIEW-2026-08-14.md:122`), a handoff note that records exactly
which identifiers were deliberately left alone (`docs/history/HARDENING-HANDOFF.md:86`), the
changelog, and a dated validation log (`docs/validation/action-trial-2026-09.md`).

These should never be edited. A dated review that says "128 `codesentry` occurrences across 24 files"
is a measurement taken on a particular day, and rewriting its words to say Mitig8it would make the
document claim something it did not claim. `docs/history/EXECUTION-PLAN-2026-08-17.md:20` is explicit
about the convention already: "the product is Mitig8it; infrastructure and code still use the legacy
name CodeSentry. Do not rename anything unless a task explicitly says to."

The benchmark corpora are a stronger case than prose, because they are scored inputs rather than
descriptions, and one of them couples directly to a file Stage 0 wants to touch.

- `benchmarks/vulnerable-corpus/adjudications.json` holds 13 adjudications whose `where` field cites
  `aicodesentry/mitig8it` plus a file and line at a past commit, for example `:1375` and `:1391`.
  Editing the citation detaches the adjudication from the evidence it was made against.
- `benchmarks/secrets-precision/cases.json:370` and `:378` are two scored true-negative cases for the
  secret scanner. Each quotes, verbatim as its `line`, the local connection string
  `DATABASE_URL=postgresql://dev:devpass123@localhost:5432/codesentry` from `.env.example` and
  `docs/getting-started/environment.md`, and the `evidence` field names all four files the line
  appears in. This is a real coupling, not a coincidence: the local database name in `.env.example` is
  a quoted input to a precision benchmark. Renaming the local database without updating these two
  cases in the same commit leaves the benchmark scoring a line that no longer exists in the
  repository, which is exactly the kind of quiet corpus rot the benchmark is meant to detect in other
  people's code.

This bucket is the reason a tree-wide replace is wrong even for text. Twelve percent of the remaining
occurrences are in files whose value is that they have not been edited.

## Persistent state

12 lines in 6 files.

```
grep -E '^frontend/src/services/api\.js'                                      # 3 lines, 1 file
grep -E '(POSTGRES_DB|5432/codesentry|pg_isready .* -d codesentry)'           # 9 lines, 5 files
```

This is the hardest class, and it is also the smallest, because of a fact worth stating plainly:
**no schema object carries the name.** No database, schema, role, table or column identifier inside
the SQL contains `codesentry`. Verified with:

```
grep -rIin codesentry services/api-service/migrations/
```

which returns nothing. What is left is the database name itself and two browser keys.

**The database name.** `codesentry`, at `docker-compose.yml:52` (`POSTGRES_DB`) and in the
`DATABASE_URL` of the three services at `:81`, `:110` and `:136`, with the compose health check
naming it again at `:61`, and in `.env.example:17`, `services/api-service/.env.example:9`,
`services/github-service/.env.example:9` and `docs/getting-started/environment.md:71`.

Every one of those is local development. The production database name is not in this repository at
all: it is inside the value of the `codesentry-database-url` secret. That splits the problem in two,
and the two halves have very different costs.

Locally, the name is disposable. A developer who changes it and runs `docker compose down -v` gets a
fresh database and `npm run db:migrate` rebuilds it. The only cost is that every existing local
volume becomes invisible, so anyone with useful local state has to dump and reload it, and anyone who
pulls the change while a stack is running gets a service pointing at a database that does not exist.
There is one non-obvious coupling: two scored cases in `benchmarks/secrets-precision/cases.json` quote
the `.env.example` connection string verbatim, so a local rename has to update the benchmark in the
same commit or the corpus starts scoring a line that no longer exists.

In production it is the hardest single item on this page, and the reason is not the rename, it is
that PostgreSQL cannot rename a database that has a connection open. Doing it means: no service may
hold a connection, so every Cloud Run service scales to zero or is stopped; `ALTER DATABASE` runs
from an administrative connection to a different database; the secret value is updated to a new
version; and every service is redeployed to pick that version up. The API's migration step runs
against the same URL, so a migration in flight during the window is a partial migration against a
database that is being renamed underneath it. The alternative, dump and restore into a new database,
is longer but reversible, and it is the one to choose if this is ever done. Either way it is a
scheduled maintenance window with a rollback plan, for a string that appears in no user-facing
surface and in no log line, which is why the recommendation below is not to do it.

**Two keys in visitors' browsers.** `codesentry_auth_token` and `codesentry_force_github_reauth`, at
`frontend/src/services/api.js:10`, `:23` and `:28`. These are not ours to reset: they live in
`localStorage` on machines we do not control, and they survive a deploy.

`codesentry_auth_token` is only ever removed, never written. It is a legacy cleanup: authentication
moved to the `HttpOnly` `__session` cookie described at `overview.md:127`, and those two
`removeItem` calls exist to clear a token that an older build of the dashboard left behind. Renaming
the key would defeat its entire purpose, because the key it needs to remove is the one old builds
wrote. It should be left exactly as it is until the team is willing to decide that no browser still
holds the old key, at which point the right change is deletion rather than a rename.

`codesentry_force_github_reauth` is live, written at `:33` and read at `:38`. Renaming it drops the
flag for any user mid-flow when the new bundle loads, which sends them through a re-authorisation
they had already completed. Harmless once, invisible in any metric, and worth exactly nothing.

## Internal code

6 lines in 4 files.

```
grep -E '(^services/api-service/package(-lock)?\.json|codesentry-attacker-owned)'
```

`services/api-service/package.json:2` and `:4` name the package `codesentry-api` with the
description "CodeSentry API service", and `package-lock.json:2` and `:8` mirror the name. The package
is private and never published, so the name is read by nothing but `npm` itself. Changing it is safe
and requires regenerating the lockfile in the same commit, which is what makes it noisy rather than
free: a lockfile diff conflicts with any other branch that touches dependencies.

`services/api-service/tests/auth.test.js:162` and `tests/cors.test.js:52` use
`https://codesentry-attacker-owned.web.app` as a hostile origin. The name is load bearing in a way a
reader could easily miss. The CORS allowlist used to match on substring, accepting any `*.web.app`
origin containing `codesentry`, recorded as a P1 at `docs/history/BUG-REVIEW-2026-09-05.md:25` and
fixed. These two tests are the regression guard, and the origin has to contain the legacy product
name for them to guard anything. `cors.test.js:50` says so in its own test name. Renaming these
strings to `mitig8it-attacker-owned` would leave two tests that still pass and no longer test
anything.

## Cosmetic

8 lines in 5 files, everything the filters above did not claim.

Four are prose that describes the split honestly and will be wrong the moment any part of it is
fixed: `docs/architecture/overview.md:22` and `:129`, `docs/getting-started/environment.md:5`,
`docs/reference/system-overview.md:5`. Two are the benchmark evaluator's module docstring and its
`argparse` description, `benchmarks/eval.py:2` and `:197`, the second of which prints the old product
name in `--help`.

The last two are in `.env.example`. Line 2 is the file's title header, and it contains an em-dash,
which `CONTRIBUTING.md:155` forbids anywhere, so that line is already due for an edit on its own
merits. Line 60 is `EMAIL_FROM_NAME=CodeSentry`, and it is not cosmetic in effect even though it is
cosmetic in cost. `services/github-service/src/services/notificationService.js:81` and `:133` use
that variable as the display name on outbound mail, defaulting to `Mitig8it` when it is unset. A
self-hoster who copies `.env.example`, which is what the file is for, sends notification email signed
CodeSentry, and the example file is the only reason they would. This is a one-word fix and it should
be made.

## Staged plan

### Stage 0, now, one PR, no infrastructure change

Twelve lines, plus the two defects this inventory surfaced.

1. The 8 cosmetic lines. Rewrite the four prose passages to point here instead of restating a
   partial list, retitle `benchmarks/eval.py`, drop the em-dash header in `.env.example`, and set
   `EMAIL_FROM_NAME=Mitig8it` so a self-hoster's mail is signed correctly.
2. The 4 npm metadata lines, `codesentry-api` to `mitig8it-api`, with the regenerated lockfile in the
   same commit. Land this when no dependency branch is open, or defer it to Stage 0b on its own; it
   is the only item here that can conflict.
3. Fix `scripts/e2e-happy-path.sh` to assert the name the API actually emits, so the smoke check can
   pass. This is a bug fix that happens to live in this inventory, and it should not wait for the
   rest of the plan.
4. Leave the two adversarial test origins alone and add a one-line comment at each saying why, so the
   next person running a replace does not quietly disarm the CORS regression guard.

Nothing in Stage 0 touches a deployed identifier, a stored value or a published name. It is
reviewable in one sitting and it cannot break a deploy.

### Stage 1, needs an infrastructure change landing alongside

The nine GitHub Actions variables and secrets, 40 lines. This is the only part of the deploy-time
bucket where the cost is proportionate, because the settings change is copying nine values under new
names rather than migrating anything.

Sequence: add the nine new names in repository settings with the same values; land a PR that reads
the new names and adds a guard step to each deploy workflow that fails when a required value is
empty, because the current failure mode is a successful deploy with an empty CORS origin and an empty
internal secret; confirm a staging deploy; delete the old nine. The guard is the point of the
exercise and is worth adding whether or not the rename happens, since it closes the empty-string
authentication bypass described above.

Everything else in the deploy-time bucket, 168 lines, is a new Cloud Run service or a new secret plus
IAM plus a cutover, for no functional gain. See Stage 3.

### Stage 2, needs a migration

The nine `codesentry_*` series, if they are retired at all. Not a database migration, a metric one.

Declare the `mitig8it_*` name beside each existing series with identical labels, emit both, wait one
retention window so any panel outside the repository shows continuous data across the change, then
drop the `codesentry_*` declaration. The evidence above makes this cheaper than it sounds: eight of
the nine come from a service nothing scrapes, so they can be renamed outright with no dual-emit
period, and only `codesentry_http_request_duration_seconds` needs the overlap. Update
`metricsLoopback.test.js:45` in the same commit, since it pins the old name.

The database name is the other migration-shaped item, and the recommendation is not to do it. See
Stage 3.

### Stage 3, deliberately never

These should stay. Each one costs a coordinated production change and buys nothing a user or a
maintainer can see.

- **The `aicodesentry` org and the `ghcr.io/aicodesentry/mitig8it-action` image.** The 43 lines in
  the published-slug bucket. This is the identity strangers pin. Renaming it invalidates every pinned
  digest and every attestation verified with `--owner aicodesentry`, and because
  `action/action.yml:131` compares the repository name exactly, a redirected `uses:` would stop
  pulling the attested image and start building from source without saying that anything was wrong.
  The awkwardness of the org name is a smaller cost than one broken pin.
- **The GCP project id `codesentry-260311-9f2b`.** Immutable. A new project means new services, new
  secrets, new IAM, a new database instance, a new Firebase site and a new GitHub App webhook URL.
  The 21 lines that name it are the cheap part.
- **The four Cloud Run service names and the sandbox job name.** A Cloud Run service name is in its
  URL and cannot be edited. A cutover means a second service, an IAM rebinding, a `firebase.json`
  rewrite change, a sidecar config change, a webhook URL change at GitHub, and a window where two
  revisions accept traffic. The names appear in logs and runbooks and nowhere a user looks.
- **The fourteen Secret Manager secret names, twenty-seven with staging.** Create, copy, rebind,
  redeploy, delete, once per secret, with `codesentry-database-url` additionally gating the migration
  step. The names are visible only to whoever runs `gcloud secrets list`.
- **The production database name.** Renaming it requires every connection closed, which means a full
  outage, or a dump and restore, which means a longer one. The name appears in no user-facing surface
  and no log line.
- **`codesentry_auth_token` in `localStorage`.** Renaming it defeats its function, which is to delete
  a key written by older builds. Its correct end state is deletion, not a rename, once the team
  decides the old key is gone from the field.
- **`codesentry_force_github_reauth`.** Renaming it silently re-authorises whoever is mid-flow when
  the new bundle loads, in exchange for a string nobody reads.
- **The 40 historical and fixture lines.** Editing a dated review changes what it says happened, and
  editing a scored benchmark case changes what the benchmark measures.
- **The two `codesentry-attacker-owned` test origins.** They have to carry the legacy name for the
  CORS regression test to test anything.

That is 168 of the 208 deploy-time lines, all 43 published-slug lines, all 40 historical and fixture
lines, all 12 persistent-state lines and 2 of the 6 internal lines: **265 of 330 occurrences, or 80
percent, should stay.** The 65 that can move are the 8 cosmetic lines, the 4 npm metadata lines, the
40 GitHub Actions references and the 13 metric lines. The honest conclusion of this inventory is that the `codesentry` namespace is not debt to be
paid down, it is the set of names this system was built under, and the debt is only that
`overview.md` said so in a single line without saying which names or why.

## Sequencing relative to the public launch

**Before strangers start pinning this: Stage 0, and the Stage 1 guard.**

Stage 0 is worth doing before launch for one reason, which is not tidiness. Three of the four prose
lines are in the documents a new reader hits first, `overview.md`,
`docs/reference/system-overview.md` and `docs/getting-started/environment.md`, and each currently
restates a partial and slightly different list of where the old name survives. A reader who finds a
fourth place the docs did not mention concludes the documentation is approximate. Replacing three
approximate lists with one link to this page turns a smell into a documented decision, which is the
actual deliverable. `EMAIL_FROM_NAME` and the `e2e-happy-path.sh` mismatch are real defects with
one-line fixes and should go out with it.

The empty-value guard from Stage 1 is worth landing before launch on its own merits, whether or not
the nine variables are ever renamed. An undefined `secrets.CODESENTRY_INTERNAL_SECRET` deploys green
and leaves internal service authentication comparing empty strings. That is a security property
depending on a repository setting nobody is watching, and launch is when the number of people looking
at this deployment goes up.

**Not before launch, and probably not after: everything else.**

The instinct to finish a rename before publishing is the wrong instinct here, and the reason is
specifically about launch rather than about effort. Before launch, nothing external depends on these
names, so the rename is cheap and worthless. After launch, pinned refs and other people's saved
dashboards start depending on them, so the same rename gets more expensive every week. There is no
future point at which it becomes worth doing. That argues for deciding now, in writing, that it will
not happen, which is what Stage 3 is.

The one thing launch genuinely changes is the `aicodesentry` org name, and it changes it in the
direction of never. Today an org rename would break nothing outside this repository. The moment the
first stranger writes `uses: aicodesentry/mitig8it/action@v1` into their workflow, it breaks them. If
anyone wants that org renamed, the window is before the first external pin and it is measured in
days. The recommendation is still no, because the exact-match check in `action/action.yml:131` turns
a redirect into a silent fallback from an attested image to a source build, and shipping a supply
chain product with that failure mode available is worse than shipping one whose org name is a fossil.

The metric rename in Stage 2 can happen at any time, and there is a mild argument for doing it before
launch: the only exposure is a saved query outside this repository, and the set of people holding
such a query is currently the team. It is not urgent, because nothing in the repository queries the
nine series and eight of them are not even scraped, but it gets very slightly harder once other
operators run this stack. If it is done, it belongs in its own PR, after Stage 0, with the dual-emit
window applied only to `codesentry_http_request_duration_seconds`.
