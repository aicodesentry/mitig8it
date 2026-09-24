# GitHub App Setup

Create the GitHub App under account/org `aicodesentry`.

## Required Permissions
Repository permissions:
- Contents: Read
- Pull requests: Read & write
- Checks: Read & write
- Metadata: Read

Mitig8it does not hold write access to repository contents and cannot create a commit
or merge a pull request. Contents read is what the analysis and the repair sandbox need
to read the changed files. A verified fix is published as a suggestion block under its
finding comment, which needs only pull request write; GitHub's own "Commit suggestion"
button then applies it as a commit under the developer's identity.

Webhook permissions:
- Pull requests
- Pull request reviews
- Push
- Installation
- Installation repositories

## Reducing the permissions on an existing App
For an App that was created with Contents: Read & write, the owner changes it once:

1. Open the App's settings: `https://github.com/settings/apps/<app-slug>/permissions`
   (an organization-owned App: `https://github.com/organizations/<org>/settings/apps/<app-slug>/permissions`).
2. Set Repository permissions > Contents to **Read-only**. Leave Pull requests and
   Checks at Read & write and Metadata at Read-only.
3. Save. GitHub then shows the change as pending for every existing installation.

What GitHub's documentation says about acceptance, and what it means here:

- GitHub's "Editing a GitHub App's permissions" documentation states that when an App's
  permissions change, GitHub emails every account that has it installed and each
  installation must accept the new permissions before the App can use them.
- The same documentation notes that GitHub automatically applies the change, without
  asking the installer to accept it, when the App is only **removing** permissions or
  reducing an existing permission's access level. Contents write to Contents read is a
  reduction, so most installations pick it up without any action from the installer.
- GitHub does not guarantee this for every case, so treat acceptance as possible but not
  required: an installation that is still pending simply keeps the wider permission it
  already granted until it accepts. Nothing in Mitig8it uses contents write, so a pending
  installation behaves exactly like an accepted one.
- `installation` webhooks with action `new_permissions_accepted` report acceptances as
  they arrive, if you want to track them.

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
