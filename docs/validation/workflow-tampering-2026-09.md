# Workflow tampering rules, measured

Nine tier 2 rules for GitHub Actions workflows, run over the `.github/workflows` directory of 27
repositories at pinned refs. 240 workflow files. 57 findings from two rules; the other seven
produced nothing. 31 verdicts by hand.

Seven rules post and two are quarantined. The two quarantined rules are quarantined on their own
measurement and are named here with what was read.

## Why these rules exist

The product reviews a stranger's pull request on behalf of a maintainer. The first thing a hostile
pull request can attack is the repository's own automation, and before this work nothing in the
product read a workflow at all: `.yml` was not in the tier 2 scope, so a pull request that
rewrote `.github/workflows/ci.yml` was reviewed as though it had changed nothing.

A workflow change is also the highest value per rule in the whole set. It fires rarely, and it is
close to unambiguous: a workflow either checks out untrusted code under `pull_request_target` or
it does not.

## The corpus

| Group | Repositories | Workflow files |
| --- | ---: | ---: |
| The clean replay set | 11 | 142 |
| Vulnerable corpus repositories that have a workflow directory | 15 | 85 |
| This repository | 1 | 13 |
| **Total** | **27** | **240** |

The clean repositories are the eleven of
[real-repo-replay-2026-09.md](real-repo-replay-2026-09.md), pinned to their default branch head on
27 September 2026 rather than to a pull request, because a merged pull request almost never touches
a workflow and pull request mode would therefore have measured nothing. Eight of the 23
vulnerable-corpus repositories have no `.github/workflows` at their pinned ref (`appsecco/dvna`,
`anxolerd/dvpwa`, `zamotany/logkitty`, `commenthol/serialize-to-js`, `commenthol/safer-eval`,
`Stranger6667/pyanyapi`, `illagrenan/django-make-app`, `tadashi-aikawa/owlmixin`); the other
fifteen do.

This repository is in the corpus on purpose. Four of the eleven findings that quarantined a rule
are ours, and one of the two true positives in the whole clean half is ours as well.

Every measurement went through the real `run_opengrep`, so the findings are the findings the
product would produce, with the fingerprints the adjudications file is keyed by. The 31 verdicts
are in `benchmarks/vulnerable-corpus/adjudications.json` under
`sampled_as: "workflow_tampering_2026_09_27"`, one sentence each, with the sample recorded in that
file's `sample.workflow_tampering_pass_2026_09_27`.

## Per-rule table

| Rule | Findings | Read | True | False | Precision | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `cwe-1357.gha-third-party-action-unpinned` | 46 | 10 | 10 | 0 | 1.00 | **Posts** on the measurement |
| `cwe-732.gha-write-permission-under-privileged-trigger` | 11 | 10 | 0 | 10 | 0.00 | **Quarantined** |
| `cwe-78.gha-run-untrusted-interpolation` | 13 → 0 | 10 | 0 | 10 | 0.00 → n/a | **Narrowed**, then posts |
| `cwe-200.gha-secret-in-untrusted-checkout-job` | 1 → 0 | 1 | 0 | 1 | 0.00 → n/a | **Narrowed**, then posts |
| `cwe-829.gha-untrusted-checkout-privileged-trigger` | 0 | n/a | n/a | n/a | n/a | Posts: zero findings, literal constructs, clear taxonomy |
| `cwe-829.gha-build-step-under-privileged-trigger` | 0 | n/a | n/a | n/a | n/a | Posts: zero findings, literal constructs, clear taxonomy |
| `cwe-732.gha-permissions-write-all` | 0 | n/a | n/a | n/a | n/a | Posts: zero findings, one literal key and value |
| `cwe-522.gha-persist-credentials-on-untrusted-checkout` | 0 | n/a | n/a | n/a | n/a | Posts: zero findings, two literal keys in one step. Widened after the measurement, see below |
| `cwe-668.gha-self-hosted-runner-fork-trigger` | 0 | n/a | n/a | n/a | n/a | **Quarantined**: true only if the repository is public, which the pattern cannot see |

The "→ 0" rows are rules whose measured findings were all read, all false, and the pattern then
narrowed; the number after the arrow is what the narrowed pattern produces over the same 240 files.
Both rules post under the second clause of the posting policy, and the lines they were narrowed
away from are checked in as no-finding cases in `benchmarks/tier2-precision/cases.json`, so neither
narrowing can be undone silently.

## The credential rule was widened after this measurement

`cwe-522.gha-persist-credentials-on-untrusted-checkout` was measured as
`cwe-522.gha-persist-credentials-under-privileged-trigger`, which asked for three things: a
`pull_request_target` or `workflow_run` trigger, an untrusted `ref:`, and `persist-credentials:
true` within six lines of it. In that form it could not post anything the checkout rule did not
already post. Every input that satisfied all three satisfied
`cwe-829.gha-untrusted-checkout-privileged-trigger` too, which needs only the first two, so once
the pair is reconciled and the credential finding folds into the checkout finding (see
`finding_quality.SUBSUMED_INTERNAL_TYPES`) the rule would never reach a reviewer at all.

So the trigger requirement was dropped. What the rule now owns on its own is the case the checkout
rule does not reach: an ordinary `pull_request` workflow that checks out the head branch and keeps
the token, the usual shape of a job that pushes a formatting commit back to a contributor's branch.
There the fix is the one line, not the step, which is why it is worth a comment of its own.

This widening is not measured. The replay reads GitHub and has not been re-run, and dropping a
conjunct can only widen, so the zero above is a lower bound on the new pattern and not a precision
figure for it. Both shapes are pinned in `benchmarks/tier2-precision/cases.json` -- the pair that
folds into one comment, and the `pull_request` workflow that fires alone -- so the reconciliation
and the widening cannot be undone silently. The next replay is what turns the zero into a
measurement of the rule as it now stands.

The five rules that never fired post under the same clause the 87 rules in
[tier2-coverage-2026-09.md](tier2-coverage-2026-09.md) posted under, and it costs the same thing
here that it cost there: it is an argument about the pattern, not a measurement of it. The first
workflow that actually contains one of these shapes is the first real test of those five rules.

## The 46 unpinned action references

The rule reports a third-party action referenced by a tag or a branch rather than a commit digest.
`actions/*` and `github/*` are excluded, along with a local `./` action and a `docker://` image:
including the first-party namespaces would have made the rule fire on nearly every workflow in
existence, which is a rule a reviewer learns to ignore.

A seeded random ten of the 46 were read (seed 20260927). All ten are true. Three of them are a
**branch** rather than a tag, which is the worst case of this shape, and all three are in a step
that receives a publishing credential:

| Where | Reference | Why it matters |
| --- | --- | --- |
| `benbusby/whoogle-search` `pypi.yml:36` and `:65` | `pypa/gh-action-pypi-publish@master` | the step is handed `TEST_PYPI_API_TOKEN` and `PYPI_API_TOKEN` |
| `google/slo-generator` `build.yml:28` | `google-github-actions/setup-gcloud@master` | the step is handed `GOOGLE_APPLICATION_CREDENTIALS` |
| `juice-shop/juice-shop` `image_actions.yml:33` | `calibreapp/image-actions@main` | the step is handed a `GITHUB_TOKEN` that can push |

The other seven are movable tags: `docker/login-action@v1` beside Docker Hub credentials,
`codecov/codecov-action@v7.1.0`, `pypa/gh-action-pypi-publish@release/v1` and `@release/v1.14`,
`GabrielBB/xvfb-action@v1`, `qltysh/qlty-action/coverage@v2`.

One of the 46 is in this repository: `dependabot/fetch-metadata@v3` in
`.github/workflows/dependabot-automerge.yml`. It is a true positive by the same reading as the
other ten.

## The eleven write permissions, and why that rule is quarantined

`cwe-732.gha-write-permission-under-privileged-trigger` asked whether a `pull_request_target` or
`workflow_run` workflow grants a write scope on something other than comments. The idea was that
"wider than the job needs" is decidable in that one case.

It is not. Ten of the eleven findings were read and every one is a job using exactly the scope it
asked for:

| Scope | Where | What it is for |
| --- | --- | --- |
| `id-token: write` | ours ×3 (`deploy-analysis-cloudrun.yml`, `deploy-api-cloudrun.yml`, `deploy-github-cloudrun.yml`), `vercel/next.js` ×2 (`automated_code_review.yml`, `upload_preview_tarballs.yml`) | minting the OIDC token for Workload Identity Federation or a scoped upload |
| `actions: write` | `vercel/next.js` ×3 (`retry_deploy_test.yml`, `retry_test.yml`, `sync_backport_canary_release.yml`) | the only scope that can re-run or dispatch a workflow |
| `contents: write` + `pull-requests: write` | ours (`auto-update-pr-branches.yml`), `fastify/fastify` (`backport.yml`) | pushing a branch and opening a pull request, which is the job |

Labelled precision 0.00 over ten. The reason is structural rather than a matter of degree: a
workflow only uses one of these triggers when it needs to do something a fork's token cannot, so
the scope being present is the reason the workflow exists. Two of the ten even set `contents: read`
beside the `id-token: write` the rule complained about, which is exactly the narrow block the
rule's own message asks for.

So it is quarantined rather than narrowed. Re-enabling it needs something the pattern does not
have: what the job actually uses the token for. A rule that compared the granted scopes against
the API calls the steps make would be a different rule, not a narrowing of this one. Its
true-positive fixture stays in the benchmark, because that is what a re-enabling would be measured
against, and the benchmark now asserts that a quarantined rule's match never survives
`partition_by_posting_policy`.

## The ten false shell injections, and what the pattern does now

The injection rule was written as `pattern-inside: "run: ..."` plus a regex for GitHub's
documented list of attacker-controlled event fields. It produced 13 findings; the ten read are all
the same shape, in ten of `electerm/electerm`'s build workflows:

```yaml
    - run: npm i

    - name: Install R2 dependencies if needed
      if: ${{ contains(github.event.head_commit.message, '[r2]') }}
      run: npm i -D @aws-sdk/client-s3
```

The finding landed on the `if:` line. An `if:` expression is evaluated by Actions and never by a
shell, so the claim is false. The cause is `generic` mode: `...` is token matching with no notion
of a YAML block, so it ran past the end of the single-line `- run: npm i` step and into the next
step's keys. That is not a tuning problem, it is the operator being the wrong tool, and it is
recorded at the top of `workflow_coverage.yml` so the next person does not reach for it again.

The pattern is now two alternatives. One matches an interpolation on the `run:` line itself. The
other matches a block scalar (`run: |`), crossing only lines that do not open a new step key
(`name:`, `id:`, `if:`, `env:`, `with:`, `uses:`, and the rest) or a new list item; a shell comment
inside the script is deliberately crossable, because `# install first` is script text and refusing
to cross it lost real matches. Both anchor the reported match with PCRE's `\K` so the finding lands
on the line a reviewer has to change.

Over the same 240 files the narrowed rule produces nothing. It still fires on the shapes it exists
for, which is what its fixtures in `benchmarks/tier2-precision/cases.json` assert, including the
block-scalar-after-a-shell-comment case.

The environment binding that fixes it is checked in as a **no-finding** case, and that is
load-bearing rather than tidy: the static assertion verification level proves a patch by showing
the rule fires before the change and not after it, so a rule that still fired on its own fix could
never have a proven repair.

## The one false secret exposure

`cwe-200.gha-secret-in-untrusted-checkout-job` produced one finding, in
`google/slo-generator` `deploy.yml:58`, and it is false. The `ref:` the rule read as a checkout of
untrusted code is an input to a different action:

```yaml
      - name: Wait for container image build
        uses: tomchv/wait-my-workflow@v1.1.0
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
```

and the workflow is triggered by `push` to master, so no contributor revision is present at all.
The rule now requires three things in order: the privileged trigger, a `uses: ...checkout` step,
and the untrusted `ref:` under it, before it will look for a secret. That line is a no-finding
case.

## The self-hosted runner rule, and why it is quarantined with no findings

`cwe-668.gha-self-hosted-runner-fork-trigger` found nothing on the corpus, so there is no
measurement, and it does not qualify for the sink-only exemption.

A self-hosted runner is a real machine that survives between jobs, so a workflow a fork can
trigger runs a stranger's code there. That is GitHub's own warning. But whether a fork can trigger
it depends on the repository being public and accepting fork pull requests, and a self-hosted
runner on `pull_request` in a private repository is the ordinary, correct setup for a great many
teams. The pattern sees the workflow, not the repository.

This is the same objection that quarantined `cwe-79.py-jinja-autoescape-off`, whose claim is true
only when the templates render HTML. Re-enable it when the finding can carry the repository's
visibility, which the analysis request already knows and does not currently pass to the scanner.

## Known debt

- **Five of the nine posting rules have never fired.** They post on an argument about the pattern.
  Nothing in the corpus contains a `pull_request_target` that checks out a pull request head, a
  `permissions: write-all`, or a persisted credential on an untrusted checkout, which is good news
  about the corpus and no news about the rules.
- **The trigger is matched at an indentation, not in the `on:` block.** Every rule that names a
  trigger asks for `^[ \t]{0,4}(?:pull_request_target|workflow_run)[ \t]*:`, which is where a
  trigger appears in every workflow anyone writes, but it is not a parse. A `pull_request_target`
  key four spaces deep inside something else would be read as a trigger.
- **The build-step rule names a command list.** `npm ci`, `pip install`, `mvn`, `pytest` and the
  rest. A build invoked through a script the workflow calls (`./scripts/build.sh`) is not matched,
  and cannot be from the workflow alone.
- **Recall is unmeasured.** There is no labelled workflow corpus, so nothing here says what these
  nine rules miss. The corpus answers noise, as it did for the tier 2 coverage set.
- **The digest lookup is off by default, and until 29 September 2026 it was unsettable.** The
  pinning repair needs the commit a tag resolves to, which has to be looked up while the product
  still has a network. `WORKFLOW_ACTION_DIGEST_LOOKUP` gates it and is unset by default, so a
  finding carries the action reference and no digest, and the repair is refused with
  `action_digest_unresolved`. The variable was read by
  `services/analysis-service/src/workflow_action_digest.py` and set by no deploy workflow, while
  that module's own docstring said the hosted deployment set it, so the most precise rule in this
  document could never produce a fix in either product and nothing said so.
  `deploy-analysis-cloudrun.yml` now passes a repository variable of the same name through to the
  service, normalised to `true` or empty, and `tests/test_workflow_action_digest.py` fails if that
  line is dropped again. It is still off unless an operator sets the variable, which is the right
  default for the only outbound request this service makes.

  **Turning it on is not yet a fix, and this is the honest part.** Without
  `WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN` the lookup uses the unauthenticated GitHub API limit, 60
  requests an hour shared by every instance behind one egress address. Over that limit the lookup
  returns None, which lands back on `action_digest_unresolved`, so the failure is safe and silent
  rather than wrong, and the repair simply stops appearing under load with no signal that it is the
  rate limit. A product promise cannot rest on that. The App already holds an installation token in
  github-service, which is the service with GitHub credentials and retry handling, so resolving the
  digest there and passing it in with the finding is the change worth making. The Action must keep
  the lookup off whatever happens, because its contract is that nothing leaves the runner. The other refusal this family carried,
  `static_assertion_verification_unavailable`, is gone: the level the family declares now exists
  ([static-assertion-2026-09.md](static-assertion-2026-09.md)). It remains reachable for an
  operator who sets `allow_static_assertion_verification` false, or a deployment with no analysis
  service to re-run the rule.

## Reproducing this

The scan is the service's own runner over the workflow files of the corpus repositories:

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# every rule over one tree, through the real tier 2 runner
$PY scripts/replay/replay.py --snapshot --include-quarantined \
    --repo vercel/next.js --ref <40-char sha> --out results/next.json

# the gate that keeps the narrowings and the quarantines honest
cd services/analysis-service/src && $PY -m pytest tests/test_tier2_precision_benchmark.py -q
```

Snapshot mode reaches workflow files because `corpus.py` now walks `.github`; before this change
it skipped every dotted directory, so a snapshot would have reported zero workflow findings
however many a tree contained.
