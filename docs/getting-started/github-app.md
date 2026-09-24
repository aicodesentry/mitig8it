# GitHub App Setup

Create the GitHub App under account/org `aicodesentry`.

## Required Permissions
Repository permissions:
- Contents: Read & write. Read-only is enough for analysis alone. Applying a fix creates a commit on the pull request branch, so the write scope is required whenever `REMEDIATION_APPLY_ENABLED` is on.
- Pull requests: Read & write
- Checks: Read & write
- Metadata: Read-only

## Subscribe to events
- Pull request
- Pull request review
- Pull request review thread. Required: resolving or unresolving the app's own review thread is how a reviewer accepts or reopens a finding without ever opening the workspace. Without it those decisions are never recorded.
- Pull request review comment. Required: a reply of `not an issue`, `false positive` or `/mitig8it dismiss` under the app's finding comment dismisses the finding. Without it those replies are never seen.
- Push
- Installation
- Installation repositories

Both new subscriptions feed the outcome log described in
[finding outcomes](../architecture/finding-outcomes.md); the quality metrics are computed
from it, so an installation missing them will under-report its dismiss rate.

## Webhook URL
Set to:
- local with tunnel: `https://<your-tunnel>/webhooks/github`
- production: `https://<your-domain>/webhooks/github`

## Required Environment Variables
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`
- `GITHUB_WEBHOOK_SECRET`
- `GITHUB_APP_SLUG`

Optional dashboard OAuth variables:
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`

## Installation
Install app on target repositories or organization, then use:
- frontend onboarding page (`/app/onboarding`)
- settings sync endpoint (`POST /api/installations/sync`)
