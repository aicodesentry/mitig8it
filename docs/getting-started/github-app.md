# GitHub App Setup

Create the GitHub App under account/org `aicodesentry`.

## Required Permissions
Repository permissions:
- Contents: Read & write. Read-only is enough for analysis alone. Applying a fix creates a commit on the pull request branch, so the write scope is required whenever `REMEDIATION_APPLY_ENABLED` is on.
- Pull requests: Read & write
- Checks: Read & write
- Metadata: Read-only

Webhook permissions:
- Pull requests
- Pull request reviews
- Push
- Installation
- Installation repositories

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
