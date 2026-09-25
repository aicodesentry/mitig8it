# GitHub Action

Mitig8it runs in two shapes. The GitHub App reviews pull requests from our infrastructure and
keeps the history behind a dashboard. The GitHub Action runs the same review inside your own
runner and keeps nothing.

This page covers the action. For the app, see [GitHub App Setup](github-app.md).

## Install

```yaml
name: Security review
on: pull_request
permissions:
  contents: read
  pull-requests: write
  checks: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aicodesentry/mitig8it/action@main
```

## Permissions

The three permissions above are the whole grant, and each one buys something visible:
`contents: read` to read the changed files at the head commit, `pull-requests: write` to post the
review and the inline comments, `checks: write` to post the `Mitig8it Security Review` check run.

`contents: write` is absent, and the action refuses to start when a workflow grants it. The
refusal is the point: a reviewer that could also rewrite the branch it is reviewing would be
asking for trust that an action installed in five lines has not earned. Fixes are GitHub
suggestion blocks and become commits only when a reviewer clicks Commit suggestion.

## What leaves the runner

Nothing, by default. The scanner, its rules, the repair engine and the publisher are all in the
image, and the only host contacted is the GitHub API.

Setting `model-api-key` sends redacted snippets around each finding to the provider you name, for
tier 3 triage and for the repair agent. Without it, tier 3 is switched off and the repair engine
is handed a provider that abstains, so only the deterministic template repairs run. The review
summary states which of the two happened on every run.

## Inputs

| Input | Default |
| --- | --- |
| `github-token` | `${{ github.token }}` |
| `fail-on` | `none` (`none`, `high`, `critical`) |
| `post-fixes` | `true` |
| `model-api-key` | none |
| `model-provider` | OpenAI |
| `model` | `gpt-4o-mini` |
| `max-files` | `200` |

## What it reuses

The action is a packaging of the existing services, not a second implementation.

- The scan is `analyze_pull_request_payload` in the analysis service, called in process. Same
  tiers, same rule files, same fail-closed behaviour when semgrep does not run.
- The repairs are the remediation service's engine with `SANDBOX_BROKER_MODE=inprocess` and the
  local subprocess driver, which is why every candidate is `development_unverified`.
- The publishing is the github-service's own `createCheckRun`, `postInlineComment` and
  `publishFindingFixSections`, with a workflow-token provider installed into the identity seam
  described in [Architecture Overview](../architecture/overview.md). The App path is unchanged.

What is written for the action is the driver that replaces the api-service: reading the event,
listing the changed files, applying the scope rules, and deciding the exit code. The scope rules
themselves live in Node in production, so they are ported into `action/orchestrator/pr_scope.py`
with parity tests that read the Node sources and fail when the two drift.

## Differences from the app

No dashboard, no stored findings, no outcome metrics, no suppressions and no baseline: without a
database, every run reviews the pull request fresh, so a finding you chose not to act on returns
on the next pull request that touches those lines.

Verification is the same in both: `development_unverified`, in a local sandbox. The isolated
sandbox is not in production on either path.

Full reference: [action/README.md](../../action/README.md).
