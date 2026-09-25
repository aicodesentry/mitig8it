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

## Excluding paths

A `.mitig8it.yml` at the repository root keeps paths out of the review:

```yaml
exclude:
  - benchmarks/fixtures/**
  - vendor/**
```

An excluded path is never analysed: it is dropped before any content is fetched, so no finding,
comment or fix suggestion can come from it, and it is not counted towards `max-files`. The App
reads the same file and applies it the same way, so the two agree on what a pull request's review
covers.

## What the check summary says it looked at

Every run states four numbers, so a directory with no finding on it is never ambiguous:

> 10 files analysed, 2 read as a patch only (the scanner has no deep rules for those file types),
> 1 excluded by .mitig8it.yml, 1 skipped as build output or a vendored dependency.

**Analysed** is the files the semgrep tier reads whole. **Read as a patch only** is the rest of
the change: a workflow YAML, a README, a lockfile. Those are not unreviewed, and the sentence
deliberately does not say they are; the regex tier still reads their diff, and the
committed-secret rule is the one that most often fires there. What it does say is that no
language-aware rule ran on them, which is what a reader needs in order to know what a clean
result is worth.

Full syntax and limits: [Repository Configuration](../docs/getting-started/configuration.md).

### Outputs

`findings`, `critical`, `high`, `fixes`, `conclusion`.

## How fixes are applied

A fix whose change is one contiguous region of one file arrives as a GitHub suggestion block
under the finding it repairs, with a line stating what was verified:

> Verified: regression test failed on the original code and passed with this change (development
> sandbox).

Read that line literally. The engine writes a regression test for the finding, runs it against
your original code to confirm it fails, applies the repair, and runs it again to confirm it
passes. In the action that verification happens in this container, as ordinary subprocesses. It
is a real test result and it is **not** an isolated sandbox, which is why the line says
development sandbox rather than isolated sandbox. Nothing is applied until you click **Commit
suggestion**.

A fix that changes more than one region gets a suggestion for the region on the finding's line
and a second comment for each other region the pull request touches; an added import outside the
diff becomes a note rather than a comment. A fix that changes several files, or a region the pull
request does not touch at all, is shown as a diff with one line saying why it cannot be a
suggestion, because a suggestion covering part of a verified change is not the change that was
verified.

Five repair families are supported, all of them on both JavaScript and Python:
`sql_parameterization`, `command_arguments`, `path_containment`, `hardcoded_credential` and
`code_injection_eval` (`LANGUAGE_FAMILIES` in `services/remediation-service/src/families.py` is
the list this sentence describes). A finding outside those is reported without a fix.

Verifying a JavaScript repair needs the Node the image pins, which is the one
`services/remediation-service/Dockerfile` pins; the two are compared by a test, because when they
drifted apart every JavaScript verification refused to run and the only trace was one line in a
job log.

## What the review looks like

One review per run. The summary body and every new inline comment are submitted together as a
single GitHub review with one COMMENT event, so the pull request timeline gets one entry per run
rather than one per finding.

A finding on a line the pull request did not change gets no inline comment, because GitHub will
not accept one there and a comment on the nearest changed line would point at the wrong code.
Those findings are listed in the review body instead, under **Findings on lines this pull request
did not change**, with their severity, rule, path and line and a permalink to the commit that was
reviewed. They are counted separately in the check summary. The App does the same, in the same
words.

The check title, the check summary and the review body state one total, computed once, with the
breakdown beside it.

## Re-running

Every comment the action posts carries a marker. A second run on the same head finds its own
previous comment and edits it rather than posting beside it; a comment whose text has not changed
is left untouched, so a run that has nothing new to say makes no write at all. Pushing a new
commit produces a review of that commit.

A finding that has gone away has its thread closed. The action resolves the thread when the token
may, and otherwise deletes its own comment, which removes the conversation rather than folding it
away: a minimized thread still counts as unresolved, so a repository that requires every
conversation resolved would stay blocked by a finding its author had already fixed. A comment
carrying a published fix is kept either way. Every run logs one line saying what it saw and what
it did:

> Review threads: 8 seen, 8 with our marker, 0 resolved, 1 retired, 0 kept for a published fix,
> 0 failed.

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
or the repair engine skip in that case and run inside the image in CI. Node is needed for the
tests that run the publisher or compare a port against its Node original, and it has to be the
major the image pins, because `test_node_runtime.py` asks the interpreter on PATH for the
features the repair engine's sandbox harness needs.

Tests marked `repo_definition` read the workflow files and the services' own requirement lists,
which the image has no reason to carry. They assert things about the repository rather than
about the image, so the in-image run excludes them:

```sh
pytest tests -q -m "not repo_definition"   # what CI runs inside the image
pytest tests -q                            # what CI runs on the host
```

Several families of test exist to stop specific mistakes recurring:

- `test_node_parity.py` reads the Node sources the scope rules were ported from and fails when
  the two drift, so a change to the api-service's file filters or the github-service's caps
  fails here until `orchestrator/pr_scope.py` is updated to match.
- `test_inline_fix_parity.py` goes further and executes the Node it was ported from.
  `orchestrator/inline_fixes.py` is the api-service's suggestion geometry in Python, and an
  algorithm copied into another language drifts in ways a literal comparison cannot see, so both
  implementations are run over the same inputs and compared.
- `test_action_definition.py` reads `action.yml` and the workflows. It asserts the action stays
  composite, that every `COPY` source in the Dockerfile exists relative to the repository root,
  and that both workflows parse. An unparsable workflow is worth a test of its own: GitHub
  rejects the whole run before any job starts and reports only "this run likely failed because
  of a workflow file issue", naming no file and no line.

Lint the workflows the way CI does:

```sh
actionlint
```
