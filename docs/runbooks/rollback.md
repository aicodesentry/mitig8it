# Rollback runbook

A deploy went out and it is worse than what it replaced. This is what to do about it.

Nothing in this runbook has been exercised against the deployed services. Every command here is
read from the workflow, the Terraform or the code that it undoes, and the places where the
repository cannot answer the question are written down as open questions at the end rather than
filled in with a plausible-looking command.
[docs/production-readiness.md](../production-readiness.md) carries "Runbooks exercised" as an open
item for exactly this reason.

Two things are worth knowing before anything else, because they shape every procedure below.

**No deploy in this repository is staged.** Every Cloud Run deploy runs `gcloud run deploy` with no
`--no-traffic` and no revision tag, so the new revision takes all the traffic as it is created, and
the workflow's smoke step runs afterwards. A failing smoke step therefore means the bad revision is
already serving. The same gap was recorded in
[docs/history/DEVELOPER-READINESS-REVIEW-2026-08-14.md](../history/DEVELOPER-READINESS-REVIEW-2026-08-14.md)
and has not changed.

**Rolling back the code does not roll back the schema.** The API deploy runs production migrations
before it deploys, the migration runner is forward-only, and no down migration exists anywhere in
this repository. Section 5 is about that and is the longest section here for a reason.

## Who is woken up

`infrastructure/monitoring/main.tf` creates exactly one notification channel, an email channel
named "Mitig8it owner", addressed to the `alert_email` Terraform variable. Its own description says
what that means: "One address, on purpose: an alert that goes to a list nobody owns is an alert
nobody answers. Change it to a rotation address once there is a rotation." There is no rotation.
`notification_channel_ids`, the input for an existing PagerDuty or Slack channel, defaults to an
empty list.

`terraform.tfvars` is not committed, so this repository cannot say which address is configured or
whether the channel has been confirmed (Google does not deliver to an unconfirmed email channel).
`.github/CODEOWNERS` makes `@nebullii` the reviewer of everything, and of
`/.github/workflows/` and `/infrastructure/` specifically. Treat that as the answer to "whose
decision is this" and see the open questions for what is still missing.

## 1. Do I know I need to roll back?

### The alerts that exist

Three alert policies exist, all in `infrastructure/monitoring/main.tf`, and
[observability.md](observability.md) describes what each one is asking.

| Policy | Severity | Fires when | What it usually means after a deploy |
| --- | --- | --- | --- |
| `mitig8it_reviews_failing` | CRITICAL | Over 15 minutes, at least 3 analysis runs started and more than 30 percent of them ended without publishing a review | The new code is reviewing and failing. Break it down by `reason` first |
| `mitig8it_reviews_stalled` | CRITICAL | `mitig8it_analysis_runs_stalled` is 1 for 5 minutes, or the started counter stops arriving for 15 minutes | The new revision is not picking work up, or it is not serving at all |
| `mitig8it_remediation_lease_reclaim` | WARNING | More than three lease reclaims in 30 minutes | Repair workers are being killed mid-job. Often a memory or restart symptom of the new revision |

The failure breakdown is the first query to run, because it says whose deploy it was:

```promql
sum by (reason) (increase(mitig8it_analysis_runs_failed_total[15m]))
```

`analysis_incomplete` points at the analysis service. `github_files_invalid`,
`publication_incomplete` and `publication_failed` point at the github service or at GitHub itself.
`infrastructure` points at a downstream that is cold, unreachable, or newly refusing the API's
calls, which is what a bad github or analysis deploy looks like from the API's side. `unhandled` is
a bug in the API. The closed set and its meanings are in
[observability.md](observability.md#the-alerts).

### What no alert watches

Being explicit about this, because waiting for a page that cannot arrive is the worst way to spend
an incident:

- **Every product metric is emitted by the API**, and the Managed Prometheus sidecar runs only on
  `codesentry-api`. A bad github, analysis or remediation deploy is visible only through its effect
  on the API's numbers.
- **The frontend has no alert at all.** Nothing reads Firebase Hosting. A broken frontend deploy is
  found by the deploy's own `curl` of `${SMOKE_URL}/`, which only proves the site answers, or by
  somebody opening it.
- **If `METRICS_SIDECAR_ENABLED` is not `true`, no policy can fire**, because no series reach Cloud
  Monitoring. The variable is opt-in and the API deploys as a single container without it; see the
  last paragraph of [observability.md](observability.md). Confirm the variable and the `collector`
  container before you rely on any of the three policies above.
- **Nothing exercises the published action image after a release.**
  `.github/workflows/mitig8it-self-review.yml` runs `uses: ./action`, which builds from source, so
  the self-review does not pull what a user pulls. The post-release check is the manual cold run in
  step 4 of [docs/releasing.md](../releasing.md#4-afterwards-by-hand).

### The other signals

- **A red deploy job.** The API smokes `/health` over the public URL, the remediation service
  smokes an authenticated `/health`, the frontend curls the public site. The github and analysis
  services only have their URL printed: both run `SERVICE_MODE=grpc` behind `--use-http2` with gRPC
  startup and liveness probes, so there is no HTTP endpoint to curl and the deploy verifies less
  about them than it does about the other three.
- **The API refusing to start.** In production `AUTO_MIGRATE` is not set, so
  `src/services/schemaBootstrap.js` refuses to boot with `Pending database migrations: ...` rather
  than mutating the schema. A revision that cannot boot never becomes Ready, which the stall policy
  sees as silence.

## 2. Which deploy was it?

Find the deploy before you undo it, because the CI-triggered deploys are path-filtered and usually
only one component moved.

| Component | Cloud Run service | Staging service | Workflow | Deploys when the commit touches |
| --- | --- | --- | --- | --- |
| API | `codesentry-api` | `codesentry-api-staging` | `deploy-api-cloudrun.yml` | `services/api-service/`, `proto/`, its own workflow file |
| GitHub service | `codesentry-github` | `codesentry-github-staging` | `deploy-github-cloudrun.yml` | `services/github-service/`, `proto/`, its own workflow file |
| Analysis service | `codesentry-analysis` | `codesentry-analysis-staging` | `deploy-analysis-cloudrun.yml` | `services/analysis-service/`, `proto/`, its own workflow file |
| Repair service | `codesentry-remediation` | `codesentry-remediation-staging` | `deploy-remediation-cloudrun.yml` | `services/remediation-service/`, its own workflow file (on push, with no CI gate) |
| Frontend | Firebase Hosting, target `production` | target `staging` | `deploy-frontend-firebase.yml` | `frontend/`, `firebase.json`, its own workflow file |

Each image tag carries the commit, which is how a revision is tied back to a change: the tag is
`api-<first 12 characters of the sha>` and the same shape for `analysis-`, `github-`,
`remediation-` and `remediation-job-`, in
`us-central1-docker.pkg.dev/<GCP_PROJECT_ID>/<GAR_REPOSITORY>/`. None of the five Cloud Run deploys
pins the image by digest; each deploys the tag it has just pushed. The only digest pins in the
repository are the repair service's sandbox job image (section 3) and the published action image
(section 6).

Set these once for every command below. The values are the repository variables `GCP_PROJECT_ID`
and `GCP_REGION`; the project and region used in [observability.md](observability.md) are shown as
the example.

```sh
PROJECT=codesentry-260311-9f2b
REGION=us-central1
```

## 3. Roll one Cloud Run service back to its previous revision

Traffic, not a redeploy. Rolling traffic back to an existing revision restores that revision
whole: its image, its environment variables, its secret references, its probes and its container
layout. A manual `gcloud run deploy --image <old tag>` does not, and on the API it would drop the
`collector` sidecar, which is the failure mode [observability.md](observability.md#the-alerts)
warns about under `mitig8it_reviews_stalled`.

```sh
SERVICE=codesentry-api        # or codesentry-github, codesentry-analysis, codesentry-remediation

# Newest first. ACTIVE marks the revision serving traffic today.
gcloud run revisions list --service "$SERVICE" --region "$REGION" --project "$PROJECT"

# Where traffic actually points, which is not always the newest revision.
gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --format='yaml(status.traffic)'
```

Pick the previous revision and confirm which commit it is, by the tag in its image:

```sh
GOOD_REV=<revision name from the list above>

gcloud run revisions describe "$GOOD_REV" --region "$REGION" --project "$PROJECT" \
  --format='value(spec.containers[].image)'
```

The 12 hex characters after the dash are the commit. Check it is the commit you mean before
shifting anything.

```sh
gcloud run services update-traffic "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --to-revisions "${GOOD_REV}=100"
```

Then verify, with the same check the deploy makes:

```sh
URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --format='value(status.url)')

# codesentry-api is deployed --allow-unauthenticated.
curl -sfS "${URL}/health"

# codesentry-remediation is not. The deploy uses an identity token for its own URL.
TOKEN=$(gcloud auth print-identity-token --audiences="$URL")
curl -sfS -H "Authorization: Bearer ${TOKEN}" "${URL}/health"
```

For `codesentry-github` and `codesentry-analysis` there is nothing to curl: both serve gRPC only.
The evidence that the rollback worked is the revision reaching Ready, plus the
`mitig8it_analysis_runs_failed_total` breakdown from section 1 dropping back.

### What a traffic rollback does not undo

- **`main`.** The bad commit is still there. Section 7.
- **The secret values.** Every `--set-secrets` reference in every workflow is `:latest`, so a
  revision pins the reference and not the version. A new instance of the old revision reads
  whatever `latest` is now. If the bad change included a new secret version, roll the secret back
  too, by disabling or destroying that version, or by adding a new version carrying the old value.
  The plain environment variables are different: `GITHUB_SERVICE_INTERNAL_SECRET`,
  `ANALYSIS_SERVICE_INTERNAL_SECRET` and `WEBHOOK_SECRET` are set with `--update-env-vars` from
  GitHub Actions secrets, so their values are baked into the revision and do roll back with it.
  After rolling one service back, the two ends of an internal secret can disagree.
- **IAM.** The github and analysis deploys grant `roles/run.invoker` to the API's runtime service
  account on every run. A traffic rollback changes no binding, which is what you want.
- **The frontend.** Nothing needs doing: `firebase.json` rewrites `/api`, `/auth` and `/health` to
  `serviceId: codesentry-api` with no revision or tag, so the frontend follows the traffic split
  automatically.
- **The repair service's sandbox job.** See below.

### The API, specifically

The API is the one service whose deploy changes the database, and its migrations run before
`gcloud run deploy`. Rolling its traffic back rolls back only the code. Read section 5 before
deciding the rollback is finished.

If `METRICS_SIDECAR_ENABLED` is `true`, the revision you roll back to must be one that also had the
sidecar, or the metrics stop and you lose the signal that told you to roll back. Check it:

```sh
gcloud run revisions describe "$GOOD_REV" --region "$REGION" --project "$PROJECT" \
  --format='value(spec.containers[].name)'
```

`api-1` alone means no sidecar in that revision. `api-1` and `collector` is what the deploy asserts
for a sidecar-enabled deploy.

### The repair service, specifically

Two things are peculiar to `codesentry-remediation`.

**In-flight repair state is per instance and is lost.** The service runs
`REMEDIATION_EXECUTION_BACKEND=local` with `REMEDIATION_LOCAL_STATE_DIR=/tmp/remediation`,
`--max-instances 1` and the worker loop in-process. Shifting traffic starts a new instance with an
empty state directory, so whatever that instance was working on does not resume. Expect lease
reclaims afterwards; that is the warning policy doing its job, not a second incident.

**If the revision ran `SANDBOX_DRIVER=cloud_run_job`, the sandbox job has to move with it.** The
driver compares the digest it reads back from the Cloud Run Admin API against the
`SANDBOX_IMAGE_DIGEST` baked into the service revision and refuses the run on any disagreement. A
traffic rollback restores the old `SANDBOX_IMAGE_DIGEST` while the job still points at the new
image, and then every sandbox run refuses. Point the job back as well:

```sh
# The digest the revision you rolled back to expects.
gcloud run revisions describe "$GOOD_REV" --region "$REGION" --project "$PROJECT" \
  --format='value(spec.containers[0].env)' | tr ',' '\n' | grep SANDBOX_IMAGE_DIGEST

gcloud run jobs update "<SANDBOX_JOB_NAME>" --image "<that digest>" \
  --region "$REGION" --project "$PROJECT"
```

The ordering comment in `deploy-remediation-cloudrun.yml` explains why the two must agree. The
default driver is `local`, and a push to `main` never changes it, so most revisions have no
`SANDBOX_IMAGE_DIGEST` at all and this does not apply.

### Resuming automated deploys afterwards

`gcloud run services update-traffic --to-revisions` pins the service to a named revision. Cloud Run
documents that a deploy to a service whose traffic is pinned creates the new revision without
giving it traffic, and `gcloud` says so in its output. If that holds here, the next CI deploy will
look green while serving the old code, and its smoke step will pass against the old revision, which
is the quietest possible way for a rollback to become an outage of the deploy pipeline. This has
not been tested against these services. Read the "Deploy API" step output on the next deploy, and
when you are ready for automated deploys to serve traffic again:

```sh
gcloud run services update-traffic "$SERVICE" --region "$REGION" --project "$PROJECT" --to-latest
```

## 4. Roll the frontend back

Firebase Hosting is not Cloud Run and has no revisions. A deploy creates a *version* (the uploaded
files) and a *release* (the version that is live). Rolling back means making an earlier version
live again. There are two ways, and the CLI the workflow uses is not one of them:
`deploy-frontend-firebase.yml` pins `firebase-tools@13`, which has no rollback subcommand. Check
with `npx firebase-tools@13 --help` if you want to confirm before reaching for something else.

**The fast way: the console.** Firebase console, Hosting, the site, Release history, the row you
want, then Rollback. One click, it takes effect immediately, and it restores that version's
`firebase.json` rewrites along with the files.

**The scriptable way: the Hosting REST API.** A release is created by pointing at an existing
version.

```sh
SITE=codesentry-260311-9f2b     # vars.FIREBASE_HOSTING_SITE, defaulted to this in the workflow
TOKEN=$(gcloud auth print-access-token)

# Recent releases, newest first. Each carries version.name and releaseTime.
curl -sfS -H "Authorization: Bearer ${TOKEN}" \
  "https://firebasehosting.googleapis.com/v1beta1/sites/${SITE}/releases?pageSize=10"

# Make a previous version live again.
VERSION=<the versions/... id from the release you want>
curl -sfS -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Length: 0' \
  "https://firebasehosting.googleapis.com/v1beta1/sites/${SITE}/releases?versionName=sites/${SITE}/versions/${VERSION}"
```

Neither path has been run against this project. If the REST call is refused, the console is the
fallback, not a reason to improvise.

**The auditable way, when you have a few minutes: redeploy a good ref.** The frontend workflow
exposes `workflow_dispatch`, and a dispatch checks out the ref you select, so dispatching it on a
branch or tag holding the good frontend rebuilds and redeploys that tree. It costs an `npm ci` and
a build, it produces a new Hosting version rather than reusing an old one, and it leaves the same
record in Actions that every other deploy leaves. Prefer it when the frontend is degraded rather
than down.

One ordering note. `deploy-staging.yml` deploys the github and analysis services, then the API,
then the frontend last, so the frontend is never pointing at an API that has not been updated. Roll
back in the reverse order: frontend first, then the API, then the services behind it.

## 5. The hard case: a migration already ran

### What the mechanism is, and what it is not

`services/api-service/migrations/` holds sequential SQL files, `0001_initial_schema.sql` through
`0028_analysis_run_delivery_correlation.sql`. `src/services/migrationRunner.js` sorts them by
filename, skips the ones already recorded in `schema_migrations`, and applies each remaining file
in its own transaction under a Postgres advisory lock, recording the filename and a SHA-256 of the
file's contents. `deploy-api-cloudrun.yml` runs it against production in the step named **"Run API
migrations from release image"**, which comes after the image is pushed and before
`gcloud run deploy`.

There is no down migration, no `.down.sql`, no `revert` command and no rollback path in the runner.
`npm run db:migrate` applies, `npm run db:verify` reports pending, and that is the whole interface.
The handoff note in
[docs/history/HARDENING-HANDOFF.md](../history/HARDENING-HANDOFF.md) says the same thing in one
line: "Schema deletion/downgrade is not supplied."

Two properties of the runner matter during an incident:

- **Rolling the code back does not confuse the runner.** It iterates the files present in the image
  and ignores `schema_migrations` rows that have no file, so an older image sees nothing pending and
  boots. An API revision one migration behind the schema starts normally; whether it *works* is a
  question about the SQL, not about the runner.
- **Never edit or delete an applied migration file.** The checksum is compared on every run and a
  changed file fails the next deploy with `Migration checksum mismatch for <file>`. A correction is
  always a new file with the next number.

`services/api-service/migrations/` is currently owned by an outside contributor's issue and was
read, not modified, for this runbook.

### Did the bad deploy include a migration?

Three ways, cheapest first.

The deploy log. The migration step prints exactly what it applied:

```
{"level":"info","msg":"Database migrations complete","applied":["0028_analysis_run_delivery_correlation.sql"]}
```

An empty `applied` array means the deploy changed no schema, and section 3 is the whole rollback.

The database:

```sh
psql "$DATABASE_URL" -c \
  "SELECT version, applied_at FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;"
```

The commits, if you know the last good sha:

```sh
git diff --name-only <last-good-sha> <bad-sha> -- services/api-service/migrations/
```

### Then read the SQL, because the answer depends on it

An additive migration (a new table, a new column that is nullable or has a default, a new index, a
loosened constraint) leaves the old code working: it does not know about the new object and does
not need to. A migration that drops or renames something the old code reads, or adds a constraint
the old code violates, does not.

Across the 28 files in this repository the only statement that removes anything is in
`0020_automatic_remediation_jobs.sql`:

```sql
ALTER TABLE remediation_jobs ALTER COLUMN created_by DROP NOT NULL;
```

which is a loosening, so older code that always supplied `created_by` keeps working. The check that
produced that claim, so you can repeat it on whatever the tree holds when you read this:

```sh
grep -rniE 'drop (table|column)|alter column .* type|drop not null|rename' \
  services/api-service/migrations/
```

That is a statement about the files, not a promise about the next one. Read the migration in the
bad deploy yourself.

### The options, in the order to consider them

**A. Roll the code back and leave the schema forward.** Usually correct, and it is the only option
that is fast. The new objects sit unused until the fixed deploy needs them. Do this when the
migration is additive and the damage is in the application code.

Two things to check even here. The github service reads the same `codesentry-database-url` secret
and runs no migrations of its own, so it is now also one schema version ahead of nothing in
particular; if the bad commit touched both services, roll both back or neither. And the
`remediation_jobs` and `analysis_runs` rows written by the bad code are still there. Nothing in the
schema undoes them, and [remediation.md](remediation.md) is the runbook for the ones that reached
GitHub.

**B. Forward-fix instead of rolling back.** When the migration is not reversible, and one that
dropped or rewrote a column is not, this is the honest answer rather than a fallback. Write the fix
as a new commit on `main`, let CI pass, and let the normal deploy carry it, or dispatch the deploy
workflow on the fix branch if waiting for the path filter is not acceptable. The recovery for an
irreversible migration is always a new migration, never an undo.

**C. Write a new forward migration that relaxes what the last one tightened.** For the specific
case where the new schema rejects writes the old code makes, for example a `NOT NULL` column with
no default or a new `CHECK`. A new file (`0029_...`) that drops the constraint restores the old
code's ability to write while leaving the data alone. It is still a forward migration and still
gets a number, a review and a test. Do not reach for it to "undo" a dropped column: the column's
data is gone and recreating it empty is a different failure.

**D. Point-in-time restore of the database, as a last resort.** The database is Neon Postgres.
The only mention of a restore anywhere in this repository is one line of
[docs/deployment/p0-rollout.md](../deployment/p0-rollout.md), "Take a full Neon/Postgres backup or
point-in-time restore bookmark before any mutation", and
[docs/production-readiness.md](../production-readiness.md) carries "Database backup and restore
drill: restore to a point in time exercised once and documented" as **open**, with no evidence. So:
no procedure has been written and no restore has ever been performed here.

What is certain without a drill is the cost. A restore to before the migration discards every row
written since that point, and this database is the only copy of the findings, the analysis run
history, the remediation jobs and the append-only outcome records. There is no second store to
reconcile against. Treat a restore as a decision about losing data, taken by the owner, and never
as a rollback step. Consider it only when the migration corrupted data and options A to C cannot
get to a correct state.

Note also that no deploy takes a backup. The migration step runs straight against production; the
readiness review from 2026-08-14 flagged "no backup, no `--no-traffic` canary, and no rollback
step", and only this document has changed since.

### The special case: the deploy failed at the migration step

Migrations run before `gcloud run deploy`, so a failure there means no new revision exists. Cloud
Run has nothing to roll back and the old revision is still serving. The schema, though, may have
moved: each file commits in its own transaction, so the files before the failing one are applied and
the failing one is not.

1. Read the `applied` array in the step's error output, or query `schema_migrations`, to see where
   it stopped.
2. The running revision is the old code. Decide whether it tolerates the partly-applied schema, by
   reading the applied files and nothing else.
3. Fix forward. Do not re-run the deploy hoping the same SQL behaves differently, and do not edit
   the failing file if any part of it committed anywhere, including staging, because the checksum
   is then already recorded.

## 6. Roll the published action back

The action is distributed differently from everything else: the image lives on `ghcr.io` and
`action/released-image.env` on the release commit names it by digest. `uses:
aicodesentry/mitig8it/action@v1` checks the repository out at the `v1` tag, and the four conditions
in `action/action.yml` decide whether to pull that digest or build from source. Condition 4 is that
a tag ref agrees with the version the file names, and `v1` satisfies it for any `1.x`.

So the lever is the tag.

```sh
git fetch --tags --force
git rev-parse v1 v1.0.1 v1.0.0          # where the tags point now

# Point v1 back at the previous release commit, which already carries its own digest.
git tag --force v1 <previous release commit sha>
git push --force origin refs/tags/v1
```

Everybody pinned `@v1` pulls the previous digest on their next run, with nothing to do at their end.
This is the whole rollback, and it is why `@v1` is the documented default in
[docs/releasing.md](../releasing.md#how-a-user-pins).

What it does not reach:

- **Anybody pinned `@v1.0.1`, or to the 40-character sha of the bad release commit, keeps running
  the bad image.** No tag move changes that. It is the pin working as advertised.
- **Deleting the image from `ghcr.io`, or making the package private, does not help them.** A pull
  that fails is not fatal in `action/action.yml`: it warns and builds the image from source at that
  ref, which is the same bad code, just slower. The behaviour is identical; only the cold start
  changes.
- **Deleting the `v1.0.1` tag or its GitHub release is worse than the bad release.** Their checkout
  of the ref fails, so the step fails, so a job that was getting a bad review now gets a broken
  workflow. If you do it anyway, it is a decision to break those users on purpose and it belongs in
  the release notes.

There is no yank. The only real fix for a version pin is a new version and telling people: a fix
commit on `main`, a new `## [X.Y.Z]` section in `CHANGELOG.md` with a real date, and a release.
Note two constraints from `.github/workflows/release.yml` while you do it:

- It refuses a commit whose `action/released-image.env` already records a digest, so you cannot
  re-release the bad commit. A forward fix is a fresh commit on `main`, which is the intended path.
- It force-moves `v<major>` on every release. A `v1` you moved back by hand is moved forward again
  by the next release, so the fix release must be the thing `v1` lands on.

The attestation and the SBOM stay attached to the bad version. That is correct: they record what was
built, and the record should not change because the build turned out to be wrong.

## 7. After the rollback

### Revert on main, or it comes back

A traffic rollback changes Cloud Run and nothing else. `main` still holds the bad commit, and the
next commit that touches that service's paths will deploy it again along with whatever came after
it. Because the deploys are path-filtered, that can be days later and by somebody who has no idea
this incident happened. Open the revert as an ordinary pull request, let CI pass on it, and say in
the message which revision was rolled back and why.

If you pinned traffic with `--to-revisions`, do not forget the note at the end of section 3 about
letting automated deploys serve traffic again.

Verify the fix on staging first where it is worth the time: push to the `staging` branch and
`deploy-staging.yml` deploys the whole set to its `-staging` counterparts, in dependency order.
That is what staging is for, and it is cheap because staging is deployed with
`api_min_instances: '0'`.

### What to record, and where

There is no incident log in this repository, so this is a list of the places that already exist and
expect to be updated. The open questions below say what is missing.

| What | Where | Why there |
| --- | --- | --- |
| The revert itself, and which revision was rolled back | The revert pull request body | It is the only record a future reader of `git log` will find |
| Anything user-visible that shipped and was withdrawn | `CHANGELOG.md`, under `## [Unreleased]` | Users read it, and a withdrawn change is a change |
| A number you measured during the incident, latency, failure ratio, queue depth | [observability.md](observability.md), in "What to measure after the next deploy" | That section exists because none of those numbers has been measured against the deployed service. An incident is a measurement |
| An alert that should have fired and did not, or fired uselessly | `infrastructure/monitoring/main.tf`, next to the policy, plus a threshold change if the data supports it | The thresholds are documented as untuned in [observability.md](observability.md#the-alerts) |
| The fact that this runbook was used, and what was wrong with it | [docs/production-readiness.md](../production-readiness.md), the "Runbooks exercised" row | It is open specifically because nothing here has been exercised |
| A migration that could not be rolled back and what was done instead | A note in the new forward migration's own SQL comment, and the revert pull request | The next person to read that file needs to know why it exists |

Follow the repository's own conventions when you write any of it: a number carries a link to
whatever measured it, and where something is untested, say untested.
[CONTRIBUTING.md](../../CONTRIBUTING.md) has both rules.

## Open questions

Written down rather than guessed, because a runbook with an invented command in it is worse than a
runbook with a gap.

1. **Who actually receives the page, and can they act on it?** The repository defines one email
   channel fed by an uncommitted `alert_email`. It cannot say which address that is, whether the
   channel has been confirmed with Google, or whether anyone is awake at 03:00. There is no
   PagerDuty or Slack channel configured (`notification_channel_ids` defaults to `[]`).
2. **Which human accounts hold `roles/run.admin` and Firebase Hosting admin on the project?** The
   deploys authenticate as `GCP_SERVICE_ACCOUNT_EMAIL` through Workload Identity. Nothing records
   whether the person woken up can run `gcloud run services update-traffic` from their own laptop.
   That is the difference between this document and a rollback.
3. **Does a pinned traffic split stop the next automated deploy from serving?** Section 3 assumes
   Cloud Run's documented behaviour. It has not been tested here, and the consequence of being
   wrong in either direction is significant.
4. **What is the Neon plan's point-in-time restore window?** Not recorded anywhere. Until somebody
   checks, option D in section 5 has an unknown reach as well as an untested procedure.
5. **How far back can a Firebase Hosting rollback reach?** Hosting version retention is a project
   setting and is not recorded in this repository.
6. **Where does an incident get written up?** `docs/history/` holds dated review documents and is
   the closest existing convention, but nothing says that is the place, and no incident has been
   written up yet.
7. **Should the deploys stage traffic at all?** Every rollback in this document is after the fact
   because no workflow deploys with `--no-traffic` and a revision tag, which would allow a smoke
   test against the new revision before it serves anybody. That is a change to five workflows and a
   decision for the owner, not something this runbook should assume.
8. **What is the ordering rule when the API and the github service disagree?** Both read the same
   database and only the API runs migrations. There is no written rule for which to roll back first
   when a commit touched both.
