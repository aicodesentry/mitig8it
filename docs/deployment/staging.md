# Staging environment

Somewhere to try a change before the only environment there is.

The workflows are in place. The cloud resources are not: nothing in this repository
creates a project, a database, a GitHub App or a Firebase site, and this page is the
list of what the owner has to create by hand, once.

Until every step below is done, a push to `staging` fails at the first missing secret.
That is deliberate. A staging deploy that silently fell back to a production secret
would point staging at production data, and the first thing anyone does in staging is
break something.

## How it works once it is set up

Push to the `staging` branch. `.github/workflows/deploy-staging.yml` calls the same
four Cloud Run workflows and the frontend workflow with `environment: staging`, which:

- appends `-staging` to every Cloud Run service name, so `codesentry-api` becomes
  `codesentry-api-staging`;
- appends `-staging` to every Secret Manager secret name, so
  `codesentry-database-url` becomes `codesentry-database-url-staging` and
  `codesentry-github-app-id` becomes `codesentry-github-app-staging-id`;
- reads the `*_STAGING` repository variables for the service URLs;
- deploys the frontend to the `staging` Firebase Hosting target, whose rewrites point
  at `codesentry-api-staging`;
- deploys the API with `api_min_instances: 0`, so an idle staging environment costs
  nothing.

The same environment input is available on each workflow's manual run, so a single
service can be pushed to staging without the branch.

Order is enforced: the github and analysis services deploy first because the API's
deploy writes their URLs into its own environment, and the frontend deploys last so it
is never pointing at an API that has not been updated.

## One-time owner steps

### 1. A database

Create a Neon branch from production, or a separate database. A branch is preferable:
it starts with the production schema, and the API's migrations run against it on the
first staging deploy exactly as they do in production.

```sh
# From the Neon console or CLI, branch the production database and copy its
# connection string. Then:
printf '%s' 'postgresql://...staging connection string...' | \
  gcloud secrets create codesentry-database-url-staging --data-file=- \
    --replication-policy=automatic --project codesentry-260311-9f2b
```

Never point staging at the production connection string. Staging writes review
comments, check runs and remediation branches; pointed at production data it would
write them against real repositories.

### 2. A separate GitHub App

Create a second GitHub App, for example `mitig8it-staging`. It must be a separate App,
not a second installation of the production one: the webhook URL, the callback URL and
the private key all differ, and one App cannot have two of each.

Install it **only on the test repositories**. Do not install it on any repository whose
pull requests matter. A staging deploy is expected to post wrong comments, create
unwanted check runs and occasionally open branches that should not exist.

Configure it with:

- Webhook URL: `https://<codesentry-api-staging URL>/webhooks/github`
- Callback URL: `https://<staging frontend URL>/auth/github/callback`
- The same permissions and event subscriptions as the production App.

Then store its credentials:

```sh
P=codesentry-260311-9f2b
printf '%s' '<app id>' | gcloud secrets create codesentry-github-app-staging-id \
  --data-file=- --replication-policy=automatic --project "$P"
gcloud secrets create codesentry-github-app-staging-private-key \
  --data-file=./staging-app.private-key.pem --replication-policy=automatic --project "$P"
printf '%s' '<oauth client id>' | gcloud secrets create codesentry-github-client-staging-id \
  --data-file=- --replication-policy=automatic --project "$P"
printf '%s' '<oauth client secret>' | gcloud secrets create codesentry-github-client-staging-secret \
  --data-file=- --replication-policy=automatic --project "$P"
printf '%s' '<webhook secret>' | gcloud secrets create codesentry-webhook-secret-staging \
  --data-file=- --replication-policy=automatic --project "$P"
```

Delete the local copy of the private key once it is in Secret Manager.

### 3. The remaining secrets

Generate fresh values. Do not copy the production ones: a staging environment that
shares the production JWT secret or encryption key means a token minted in staging is
valid in production.

```sh
P=codesentry-260311-9f2b
for name in codesentry-jwt-secret-staging codesentry-encryption-key-staging \
            codesentry-remediation-internal-secret-staging; do
  openssl rand -base64 32 | tr -d '\n' | \
    gcloud secrets create "$name" --data-file=- --replication-policy=automatic --project "$P"
done

# The analysis and repair providers. Reuse the production keys only if the provider
# account is the same and the spend is acceptable; otherwise create staging keys.
printf '%s' '<key>' | gcloud secrets create codesentry-gemini-api-key-staging \
  --data-file=- --replication-policy=automatic --project "$P"
printf '%s' '<url>'  | gcloud secrets create codesentry-repair-llm-base-url-staging \
  --data-file=- --replication-policy=automatic --project "$P"
printf '%s' '<key>'  | gcloud secrets create codesentry-repair-llm-api-key-staging \
  --data-file=- --replication-policy=automatic --project "$P"
printf '%s' '<model>' | gcloud secrets create codesentry-repair-llm-model-staging \
  --data-file=- --replication-policy=automatic --project "$P"
```

The full list the workflows reference:

| Secret | Used by |
| --- | --- |
| `codesentry-database-url-staging` | API, github service, API migrations |
| `codesentry-jwt-secret-staging` | API |
| `codesentry-encryption-key-staging` | API |
| `codesentry-github-app-staging-id` | API, github service |
| `codesentry-github-app-staging-private-key` | API, github service |
| `codesentry-github-client-staging-id` | API |
| `codesentry-github-client-staging-secret` | API |
| `codesentry-webhook-secret-staging` | API |
| `codesentry-remediation-internal-secret-staging` | API, remediation service |
| `codesentry-gemini-api-key-staging` | analysis service |
| `codesentry-repair-llm-base-url-staging` | remediation service |
| `codesentry-repair-llm-api-key-staging` | remediation service |
| `codesentry-repair-llm-model-staging` | remediation service |

The Cloud Run runtime service account needs `roles/secretmanager.secretAccessor` on
each of them, the same as for the production secrets.

### 4. A Firebase Hosting site

```sh
firebase hosting:sites:create codesentry-staging --project codesentry-260311-9f2b
```

`firebase.json` already declares a `staging` hosting target whose rewrites point at
`codesentry-api-staging`. The workflow binds the target to the site on each run with
`firebase target:apply`, so nothing has to be committed to `.firebaserc`.

### 5. Repository variables

Add these in GitHub, under Settings, Secrets and variables, Actions, Variables. The
first deploy is a chicken-and-egg: the Cloud Run URLs do not exist until the services
are deployed once.

| Variable | Value |
| --- | --- |
| `CODESENTRY_FRONTEND_URL_STAGING` | `https://codesentry-staging.web.app` |
| `CODESENTRY_GH_SERVICE_URL_STAGING` | the `codesentry-github-staging` Cloud Run URL |
| `CODESENTRY_ANALYSIS_URL_STAGING` | the `codesentry-analysis-staging` Cloud Run URL |
| `FIREBASE_HOSTING_SITE_STAGING` | `codesentry-staging` |

To break the cycle, run **Deploy GitHub Service** and **Deploy Analysis** manually with
`environment: staging` first, read their URLs out of the workflow logs, set the
variables, then push to `staging`.

### 6. IAM

The API's runtime service account needs `roles/run.invoker` on
`codesentry-github-staging`, `codesentry-analysis-staging` and
`codesentry-remediation-staging`. The github and analysis workflows grant it
themselves. The remediation binding is not granted by any workflow:

```sh
gcloud run services add-iam-policy-binding codesentry-remediation-staging \
  --region us-central1 --project codesentry-260311-9f2b \
  --member="serviceAccount:<api runtime service account>" \
  --role=roles/run.invoker
```

## What staging is not

- **Not monitored.** The alert policies in `infrastructure/monitoring/` are not scoped
  to a service, so staging failures would page the owner. If staging is noisy, add a
  service-name filter to the PromQL in those policies rather than silencing them.
- **Not a load test.** One instance, scale to zero, a branched database. It answers
  "does this deploy and work at all", not "does this hold up".
- **Not a place for real repositories.** The staging GitHub App is installed on test
  repositories only, and that is the whole safety boundary. There is nothing else
  stopping a staging deploy from writing to a repository it can see.
