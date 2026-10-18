# Workflow supply-chain rules and lockfile signals, October 2026

Four new GitHub Actions workflow rules, measured over the same 27 repositories as
[workflow-tampering-2026-09.md](workflow-tampering-2026-09.md): 242 workflow files, 6 findings from
two of the four rules, all 6 read by hand. Three rules post and one is quarantined. Two of the four
get a repair in the `workflow_hardening` template, verified at the static assertion level. A new
offline lockfile check, `dependency_diff.py`, adds three quarantined signals and is not measured.

Measured on 17 October 2026.

## The corpus, refetched

The 240 files of the September document were refetched at the same refs: the vulnerable-corpus
repositories at the refs in `benchmarks/vulnerable-corpus/labels.json`, and the eleven clean replay
repositories at the last commit on their default branch on or before 27 September 2026, which is
how that document pinned them. The 26 third-party repositories gave back 227 files, 142 clean and
85 vulnerable-corpus, which is that document's per-group count exactly. This repository now has 15
workflows rather than 13, so the total is 242.

As a check that the refetch is the same corpus and not just the same size, the September rules
were re-run over it alongside the new ones:

| Rule | September | October |
| --- | ---: | ---: |
| `cwe-732.gha-write-permission-under-privileged-trigger` (quarantined) | 11 | 11 |
| `cwe-1357.gha-third-party-action-unpinned` | 46 | 45 |
| every other September rule | 0 | 0 |

The one unpinned reference that is gone is ours: `dependabot/fetch-metadata` in
`dependabot-automerge.yml` has been pinned to a digest since the September measurement.

Every finding went through the service's real `run_opengrep_with_limitations`, so the fingerprints
are the ones the adjudications file is keyed by. The six verdicts are in
`benchmarks/vulnerable-corpus/adjudications.json` under
`sampled_as: "workflow_supply_chain_2026_10_17"`, with the pass recorded in
`sample.workflow_supply_chain_pass_2026_10_17`.

## Per-rule table

| Rule | Findings | Read | True | False | Decision | Repair |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `cwe-829.gha-pwn-request-checkout` | 0 | n/a | n/a | n/a | **Posts**: zero findings, literal constructs | base revision, or `ref:` removed |
| `cwe-829.gha-untrusted-artifact-executed` | 0 | n/a | n/a | n/a | **Posts**: zero findings, literal constructs | none, said in the message |
| `cwe-494.gha-remote-script-piped-to-shell` | 4 | 4 | 4 | 0 | **Posts** on the measurement | none, said in the message |
| `cwe-732.gha-write-grant-on-pull-request-target` | 2 | 2 | 0 | 2 | **Quarantined** | write grant removed |

"Posts: zero findings, literal constructs" is the second clause of the posting policy the September
document applied to five rules, and it costs the same here: it is an argument about the pattern, not
a measurement of it. Nothing in 242 real workflows contains either shape, which says something about
the corpus and nothing about the rules' precision.

### Pwn request checkout

`pull_request_target` or `workflow_run`, then an `actions/checkout` step whose `ref:` names
`github.event.pull_request.head.sha`, `head.ref`, `merge_commit_sha`,
`github.event.workflow_run.head_sha`, `head_branch`, `github.head_ref` or a `refs/pull/` ref. It is
the September checkout rule (`cwe-829.gha-untrusted-checkout-privileged-trigger`) with the one
requirement that rule lacks: the `ref:` has to be an input to `actions/checkout`, at most eight lines
below the `uses:` and without crossing into another step. The google/slo-generator shape that
produced the September false positive (an untrusted `ref:` passed to `tomchv/wait-my-workflow`) is
checked in as a no-finding case for this rule.

The two rules share `untrusted_code_checkout`, so where both match one step they cluster into one
comment. The narrower rule declares confidence 0.95 against the wider rule's 0.9 so that it is
always the survivor; a tie would have left the choice to the scanner's output order. The subsumption
case in `benchmarks/tier2-precision/cases.json` that already folded the credential rule into the
checkout rule now carries all three rule ids, with the pwn request rule surviving.

### Untrusted artifact executed

`workflow_run`, then `actions/download-artifact` with a `path:`, then a `run:` that executes a file
under that path (`bash out/run.sh`, `node dist/index.js`) or changes into it and installs (`cd dist
&& npm ci`). The path is bound by backreference, so a `workflow_run` job that downloads coverage
data and passes it to a script from its own checkout, which is the legitimate shape GitHub
recommends, is not matched. That shape is a no-finding case.

What it does not catch, and the zero above should not be read as coverage of: a download with no
`path:`, a path executed directly (`./out/run.sh`), a `working-directory:` pointing at the download,
`make` or `docker build` over it, and `gh run download`.

### Remote script piped to a shell

`curl`, `wget`, `iwr`, `irm`, `Invoke-WebRequest` or `Invoke-RestMethod`, a pipe, and an interpreter
(`sh`, `bash`, `iex`, `python`, `node` and the rest), with `sudo` and `/usr/bin/env` prefixes, on a
single-line `run:` or inside a block scalar. A pipe into `gpg`, `jq`, `tar` or `sha256sum -c` is not
matched, and neither is a script downloaded to a file and checked before it runs; both are
no-finding cases.

All four findings are true by the rule's claim, that the job executes bytes nothing pins:

| Where | Line |
| --- | --- |
| `benbusby/whoogle-search` `scan.yml:17` | the grype installer, fetched from the `main` branch of anchore/grype |
| `fastify/fastify` `package-manager-ci.yml:72` | `yarnpkg.com/install.sh` |
| `juice-shop/juice-shop` `ci.yml:359` | the Heroku CLI installer, in the deploy job |
| `vercel/next.js` `build_and_deploy.yml:530` | the wasm-pack installer |

Four is not a rate. None of the four is on a trigger a contributor can fire, so what this rule
reports is exposure to the script's host, not an attack a pull request can make, and it is the rule
in this set most likely to be dismissed as accepted practice. That is a dismiss-rate question the
corpus cannot answer.

### Write grant on `pull_request_target`

`write-all`, `contents: write` or `id-token: write` in a workflow triggered by
`pull_request_target`. It narrows the quarantined September rule on both axes: one trigger instead
of two, three grants instead of every write scope. The narrowing removed nine of that rule's eleven
findings. The two it kept are false for the reason the September document gave:

| Where | Grant | What it is for |
| --- | --- | --- |
| `fastify/fastify` `backport.yml:15` | `contents: write` | pushing the backport branch, in a job that only runs for a merged pull request |
| `vercel/next.js` `automated_code_review.yml:27` | `id-token: write` | minting a scoped comment token; the job checks out the base commit and is gated on members |

Quarantined. The objection is structural and survives the narrowing: a workflow uses this trigger
because it needs to do something a fork's token cannot, so the grant is usually why the workflow
exists. What would re-enable it is a signal the pattern does not have, whether the same job also
runs contributor code.

## The repairs

Two of the four rules now have a template in `services/remediation-service/src/templates.py`. The
dispatch is by rule id, including the ids the clusterer merged into the finding
(`evidence_details.extra.merged_rule_ids`), and never by internal type: both types are shared with
wider rules whose findings the templates would be wrong for.

**Pwn request.** Under `pull_request_target` the `ref:` value becomes
`${{ github.event.pull_request.base.sha }}`, keeping the author's quotes and trailing comment. Under
`workflow_run`, or a workflow with both triggers (the base expression is empty under
`workflow_run`), the `ref:` line is removed, together with its `with:` if it was the only input.
The template refuses a `ref:` that is not under an `actions/checkout` step, a line that is not an
untrusted `ref:`, and a file with neither trigger.

**Write grant.** `write-all` becomes `read-all`, `contents: write` becomes `contents: read`, and
`id-token: write` is deleted, because it has no read level; a `permissions:` block that this leaves
empty becomes `permissions: {}` rather than a null key. The description says a step that needed the
grant will now fail. Because the rule is quarantined, no finding of it reaches remediation today;
this is the repair a re-enabled rule would ship.

The artifact and remote-script rules get no template, and their messages say "No automatic fix is
offered for this finding" with the reason: which workflow a step belongs in, and how a tool should
be installed instead, are design decisions.

Both repairs are verified by the static assertion over the real scanner in
`services/remediation-service/tests/test_workflow_supply_chain_repairs.py`: the rule matches the
finding's line in the original, matches nothing in the patched file, no other rule starts matching,
and nothing outside the declared hunks changed. A file with a second grant is refused on clause 2,
as every multi-site file is ([static-assertion-2026-09.md](static-assertion-2026-09.md)).

### Two things found while wiring the repairs

**The static assertion could not assert any workflow repair.** The analysis side's
`static_assertion.tier2_scannable` asked whether the path had a supported source extension, and
`.yml` is not one: tier 2 reads workflows by path (`.github/workflows/`), not by extension. Every
workflow rule was therefore refused as `rule_not_applicable`, including for the two repairs the
family already had, while the September document recorded the level as available to the family. It
now asks `is_tier2_scannable_path`, the same predicate `run_opengrep` gates the scanner on, and
`services/analysis-service/src/tests/test_static_assertion.py` pins both directions: a workflow rule
on a workflow path is answered, and on ordinary YAML it is still refused.

**File policy still refuses every workflow patch, and this branch does not change that.** The
default repair policy lists `.github/` under `forbidden_path_prefixes`, so the engine skips a
workflow finding as `protected_path` before any template runs; and `build_patch_bundle` accepts
only `APPLICATION_SUFFIXES`, which has no `.yml`, so even with the prefix removed the bundle is
refused as `unsupported_application_file`. Who may edit CI is a policy decision for the repository
owner, not something to loosen to make a repair count, so it is left as it is and pinned by
`test_patch_policy_still_refuses_to_bundle_a_workflow`. The static assertion tests build their
bundle by hand from the template's own hunks for that reason. The consequence is plain: **no
`workflow_hardening` repair, old or new, reaches a reviewer under the default policy.** The findings
do, with their explanation.

## Lockfile signals

`services/analysis-service/src/dependency_diff.py` reads the patch of a changed
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock` or `requirements*.txt`, offline,
and reports a dependency whose lockfile entry was added in this pull request when:

| Rule id | Signal |
| --- | --- |
| `dependency.lockfile.install_script` | npm `hasInstallScript: true`, or pnpm `requiresBuild: true` |
| `dependency.lockfile.non_registry_source` | a git source, a plain `http://` URL, or an `https://` tarball that is not a registry download (no `/-/` in the path) |
| `dependency.lockfile.name_near_popular` | one edit (insertion, deletion, substitution or adjacent swap) from one of the 200 most downloaded packages of its ecosystem, and not itself on the list |

Medium severity, `internal_type: supply_chain_risk` (new in `taxonomy.DECLARED_INTERNAL_TYPES`),
CWE-1357, and the line is the added line that opens the entry. The remediation says no automatic
fix is offered and why. All three rule ids are declared quarantined in `dependency_diff.POSTING`,
which `main.QUARANTINED_RULE_IDS` now unions, so the findings run, are counted, and never reach a
reviewer or remediation.

The popular-name list is `services/analysis-service/src/data/top_packages.json`, checked in with its
provenance: npm from `npm-high-impact@1.13.0` (`lib/top-download.js`, the first 200 entries), PyPI
from hugovk/top-pypi-packages (30-day downloads, last update 1 October 2026, the first 200 rows),
both fetched 17 October 2026. Popular names shorter than four characters are not compared, because
`ms`, `qs` and `ws` are all real and one edit apart. PyPI names are compared normalized.

What it does not read: `package-lock.json` v1, `npm-shrinkwrap.json`, `Pipfile.lock`, `uv.lock` and
every other lockfile; a version bump of an entry that already existed, even one that gains an install
script; a lockfile whose patch the host did not send (GitHub omits very large diffs and tier 1 skips
a patch over 200 kB, which a regenerated `package-lock.json` often is).

## What is not measured

- **Lockfile signals: nothing.** No pull request with a lockfile change has been run through
  `dependency_diff`. The obvious false-positive classes are named in the module: native modules have
  install scripts, forks are pinned by git URL, and popular short names have legitimate neighbours.
  The quarantine stays until a replay reads them.
- **Recall of all four workflow rules.** There is no labelled workflow corpus, as in September.
- **Two of the three posting workflow rules have never fired on real code.** Their fixtures are the
  only evidence they match what they claim.
- **Dismiss rate of the remote-script rule.** Four true findings say the claim holds; they do not
  say a maintainer acts on it.
- **The repairs on real findings.** There were none to repair: the pwn request rule found nothing
  and the write grant rule is quarantined.

## Reproducing this

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# the corpus, refetched and scanned with every tier 2 rule (gh api GET only; cached)
$PY scripts/replay/workflow_corpus.py --cache /tmp/workflow-corpus --self-ref origin/main \
    > /tmp/workflow-findings.json

# the rule fixtures, the narrowings and the quarantine gate
cd services/analysis-service/src
$PY -m pytest tests/test_tier2_precision_benchmark.py tests/test_tier2_rule_metadata.py \
    tests/test_workflow_rules_are_path_scoped.py tests/test_static_assertion.py \
    tests/test_dependency_diff.py tests/test_rule_posting_policy.py -q

# the repairs and their static assertion over the real scanner
cd ../../remediation-service
../../.venv/remediation/bin/python -m pytest tests/test_workflow_supply_chain_repairs.py -q
```

The lockfile signals would be measured by the pull request replay over repositories whose recent
merged pull requests change a lockfile (dependency update bots make that most of them), with
`--include-quarantined`, reading every `dependency.lockfile.*` finding:

```sh
$PY scripts/replay/replay.py --repo expressjs/express --prs 30 --include-quarantined \
    --out results/express-lockfiles.json
```

To refresh the popular-name list, take the first 200 entries of
`https://unpkg.com/npm-high-impact@<version>/lib/top-download.js` and the first 200 `project` values
of `https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json`, and update the
`provenance` block of `top_packages.json` to match.
