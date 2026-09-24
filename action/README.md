# Mitig8it as a GitHub Action

Review every pull request for exploitable code, and post a fix under each finding you can apply
with one click. It runs in your own runner, with your workflow's own token. Nothing leaves the
runner unless you choose to give it a model key.

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

That is the whole installation. To remove it, delete the file.

## Why these permissions, and no others

| Permission | What it is for |
| --- | --- |
| `contents: read` | Read the files the pull request changed, at the head commit |
| `pull-requests: write` | Post the review and the inline finding comments |
| `checks: write` | Post the `Mitig8it Security Review` check run |

`contents: write` is not on the list, and the action **refuses to start if the workflow grants
it**. A tool that reviews your code and can also rewrite it asks for a kind of trust that five
lines of YAML have not earned. Fixes are posted as GitHub suggestion blocks, which only become
commits when a human clicks **Commit suggestion**; the action itself has no way to write to your
branch, and the refusal is there so that is a property of the setup rather than a promise.

If another job in the same workflow needs `contents: write`, give that job its own `permissions`
block and leave the workflow-level default read-only.

The token is `${{ github.token }}`: scoped to this one repository, issued by GitHub for this one
job, and expired by the time the job finishes. There is no app to install, no organisation-wide
grant, and no credential of ours anywhere in the process.

## What leaves the runner

By default, **nothing**. The scanner, its rule files, the repair engine and the publisher are all
in the image. The only host contacted is the GitHub API the runner was already talking to, and
the only thing sent to it is the review you can read on the pull request.

If you set `model-api-key`, that changes, and it changes only for the parts that need a model:
redacted code snippets around a finding are sent to the model provider you name, for triage and
for repair generation. Without the key the model paths are switched off, only the deterministic
template repairs run, and the review summary says so on every run so you never have to guess
which half of the product produced a given result.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `github-token` | `${{ github.token }}` | The token the review posts with |
| `fail-on` | `none` | Which findings fail the job: `none`, `high` or `critical` |
| `post-fixes` | `true` | Attach fix suggestions under findings |
| `model-api-key` | none | Enables model triage and the repair agent |
| `model-provider` | OpenAI | Base URL of an OpenAI-compatible API |
| `model` | `gpt-4o-mini` | Model name, used only with a key |
| `max-files` | `200` | Refuse a pull request larger than this rather than review part of it |

`fail-on` defaults to `none` deliberately. Adding a security review should not break a merge on
the day you add it. Turn it up once you have seen what it reports on your code.

### Outputs

`findings`, `critical`, `high`, `fixes`, `conclusion`.

## How fixes are applied

A fix arrives as a GitHub suggestion block under the finding it repairs, with a line stating what
was verified:

> Verified: regression test failed on the original code and passed with this change (development
> sandbox).

Read that line literally. The engine writes a regression test for the finding, runs it against
your original code to confirm it fails, applies the repair, and runs it again to confirm it
passes. In the action that verification happens in this container, as ordinary subprocesses. It
is a real test result and it is **not** an isolated sandbox, which is why the line says
development sandbox rather than isolated sandbox. Nothing is applied until you click **Commit
suggestion**.

Five repair families are supported: `sql_parameterization`, `command_arguments` and
`path_containment` on JavaScript and Python, plus `hardcoded_credential` and `code_injection_eval`
on Python. A finding outside those is reported without a fix.

## Re-running

Every comment the action posts carries a marker. A second run on the same head finds its own
previous comment and edits it rather than posting beside it, and a run that changes nothing
writes nothing. Pushing a new commit produces a review of that commit.

## What this is not

The action is the review pipeline, not the product around it.

| | Action | GitHub App |
| --- | --- | --- |
| Where it runs | Your runner | Our infrastructure |
| What it holds | Nothing; the job ends and the state is gone | Findings, runs and history in a database |
| Dashboard | None | Findings, trends and per-repository history |
| Outcome metrics | None | Which fixes were applied, which findings recurred |
| Suppressions and baselines | None; every run reviews the pull request fresh | Persistent, per repository |
| Repair verification | This container, as subprocesses | The same today; an isolated sandbox is not yet in production either |

The last row is worth being plain about: the app does not currently verify in an isolated sandbox
either. Every candidate the product has ever produced is `development_unverified`. The action is
not a weaker tier of verification than the app; it is the same tier, stated the same way.

Without a database there are no suppressions and no baseline, so a finding you have decided not
to act on will be reported again on the next pull request that touches those lines. If that
matters more to you than keeping everything in your own runner, the app is the other trade.

## How it is packaged

This is a composite action, not a container action, and the difference matters.

The image bundles the analysis, remediation and github services, which live beside the action in
the repository, so it has to be built with the **repository root** as the Docker context. GitHub
builds a container action with the *action directory* as the context, which makes every one of
those paths vanish. So the action builds the image itself:

```sh
docker build --file "${GITHUB_ACTION_PATH}/Dockerfile" --tag mitig8it-action:local "${GITHUB_ACTION_PATH}/.."
```

The parent of the action path is the repository root in both cases that matter: `uses: ./action`
resolves inside your checkout, and a remote `uses: aicodesentry/mitig8it/action@ref` makes GitHub
check out the whole repository and point the action path at the subdirectory in it.

Both the action and CI build through the same script, `action/build-image.sh`, so the image the
dogfood builds and the image CI proves buildable cannot drift apart.

The first run on a runner pays for the full build. After that a layer cache keyed on the
Dockerfile, the pinned Python requirements and the github-service lockfile is restored by
`actions/cache`, so an ordinary source change reuses the base image, the apt packages, the Node
tarball and the Python wheels and only replays the `COPY` layers. The build step prints
`Image built in Ns.` and the image size on every run, which is where to read the real numbers
for your runner.

Caching needs a builder that can export one. buildx's default `docker` driver cannot, and asking
it to does not degrade quietly: it fails the build with `Cache export is not supported for the
docker driver`. The script therefore creates a `docker-container` builder on demand and reuses
it, keeping `--load` so the image still lands in the local daemon. Nothing is pushed anywhere.
Every step of that is optional: no buildx, a builder that cannot be created, or no cache
directory each fall back to a plain `docker build` with a line saying why it will be slower.

## Working on the action

```sh
cd action
pip install pytest httpx pyyaml
pytest tests -q

# From the repository root, not from action/: the context is the root.
cd .. && docker build --file action/Dockerfile --tag mitig8it-action:dev .
```

The suite runs without the services' own dependencies installed; the tests that need the scanner
or the repair engine skip in that case and run inside the image in CI.

Tests marked `repo_definition` read the workflow files and the services' own requirement lists,
which the image has no reason to carry. They assert things about the repository rather than
about the image, so the in-image run excludes them:

```sh
pytest tests -q -m "not repo_definition"   # what CI runs inside the image
pytest tests -q                            # what CI runs on the host
```

Two families of test exist to stop specific mistakes recurring:

- `test_node_parity.py` reads the Node sources the scope rules were ported from and fails when
  the two drift, so a change to the api-service's file filters or the github-service's caps
  fails here until `orchestrator/pr_scope.py` is updated to match.
- `test_action_definition.py` reads `action.yml` and the workflows. It asserts the action stays
  composite, that every `COPY` source in the Dockerfile exists relative to the repository root,
  and that both workflows parse. An unparsable workflow is worth a test of its own: GitHub
  rejects the whole run before any job starts and reports only "this run likely failed because
  of a workflow file issue", naming no file and no line.

Lint the workflows the way CI does:

```sh
actionlint
```
