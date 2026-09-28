# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). What the version number promises
and what may change under it is stated in [docs/releasing.md](docs/releasing.md): in short, the
action's inputs, outputs and the `.mitig8it.yml` format are the stable surface, and the rule sets,
their measured precision and which findings post are not.

Every number in this file links to the run that measured it. None of them is an estimate.

## [Unreleased]

Nothing yet.

## [1.0.0] - unreleased

The first release. `.github/workflows/release.yml` refuses to run until the date above is a real
one, so this heading is not a placeholder anybody can forget: setting it is step one of
[docs/releasing.md](docs/releasing.md).

Everything below already exists in the repository and is measured. 1.0.0 is not new work; it is the
point at which what exists becomes something a stranger can pin.

### Added

- **Pull request review as a GitHub Action.** Five lines of YAML, run in the caller's own runner
  with the workflow's own token. Nothing leaves the runner unless a `model-api-key` is supplied,
  and the summary says on every run which of the two happened. Inputs: `github-token`, `fail-on`,
  `post-fixes`, `model-api-key`, `model-provider`, `model`, `max-files`. Outputs: `findings`,
  `critical`, `high`, `fixes`, `conclusion`.
- **The action refuses to run with `contents: write`.** A reviewer that could rewrite the branch it
  is reviewing asks for trust that five lines of YAML have not earned, so the refusal is enforced
  against the token rather than promised in a document.
- **Pull request review as a hosted GitHub App**, with the dashboard, per-repository history,
  suppressions and baselines that need a database. The Action and the App run the same pipeline;
  [action/README.md](action/README.md) has the table of what each one does not do.
- **Two deterministic analysis tiers.** Tier 1 is regex rules over the diff. Tier 2 is AST rules
  over the whole file, for JavaScript, TypeScript, Python and 16 template extensions, every rule
  written in this repository because both public rule libraries forbid use in a paid service
  ([docs/legal/third-party-rules.md](docs/legal/third-party-rules.md)). The rule set grows between
  releases and the count is deliberately not pinned here;
  [docs/validation/tier2-coverage-2026-09.md](docs/validation/tier2-coverage-2026-09.md) is the
  document of record, and it measured 130 rules of which 124 were allowed to post.
- **A rule that cannot stand behind its findings does not post them.** A rule measured below 0.8
  precision over at least three adjudicated findings is quarantined: it still runs and is still
  counted, and nothing it produces reaches a reviewer, is counted in the check summary, or is
  handed to remediation. Each quarantined rule carries a `precision_evidence` string naming the
  measurement that would let someone re-enable it. 6 tier 1 rules are quarantined today.
- **Inline findings with measured precision.** 0.97 for what posts, over 172 findings adjudicated
  by hand across 23 vulnerable repositories; 0.67 for everything the scanner produces before the
  quarantine applies
  ([docs/validation/vulnerable-corpus-2026-09.md](docs/validation/vulnerable-corpus-2026-09.md)).
  On ten real repositories the action posted 65 inline comments: 63 true positives, 1 false
  positive, 1 that could not be called either way
  ([docs/validation/action-trial-2026-09.md](docs/validation/action-trial-2026-09.md)).
- **Fixes verified by execution.** For a finding in `sql_parameterization`, `command_arguments`,
  `path_containment`, `hardcoded_credential` or `code_injection_eval`, on JavaScript or Python, the
  engine writes a regression test, runs it against the original tree to confirm it fails, applies
  the repair, and runs it again to confirm it passes. It refuses rather than guessing, and the
  refusal reasons are counted output rather than silence.
- **Fixes verified by static assertion**, for the one family that cannot be executed. A workflow
  file has no test to run, so the rule that flagged the line is re-run over the original and the
  patched text, nothing else in the file is allowed to change, and nothing is executed. Every such
  candidate says in the evidence a reviewer reads that no test ran, that nothing shows the
  vulnerability was reachable, and that the patched file was never loaded
  ([docs/validation/static-assertion-2026-09.md](docs/validation/static-assertion-2026-09.md)).
- **A workflow category.** CI and CD rules over `.github/workflows`, including
  `cwe-1357.gha-third-party-action-unpinned`, measured at 1.00 precision over 46 findings from 240
  workflow files across 27 repositories
  ([docs/validation/workflow-tampering-2026-09.md](docs/validation/workflow-tampering-2026-09.md)),
  and `workflow_hardening` repairs for what it finds.
- **One-click apply through GitHub suggestions.** A verified fix whose change is one contiguous
  region of one file is posted as a suggestion block under the finding it repairs, and becomes a
  commit only when a human clicks Commit suggestion. A fix spanning several files, or a region the
  pull request does not touch, is shown as a diff with one line saying why it cannot be a
  suggestion, because a suggestion covering part of a verified change is not the change that was
  verified.
- **`.mitig8it.yml` exclusions**, read identically by the Action and the App. An excluded path is
  dropped before any content is fetched, so no finding, comment or fix can come from it, and it is
  not counted towards `max-files`.
- **A check run that says what was looked at.** Files analysed whole, files read as a patch only,
  files excluded by configuration, and files skipped as build output or a vendored dependency, so a
  directory with no finding on it is never ambiguous.
- **One review per run.** The summary body and every new inline comment are submitted as a single
  GitHub review with one COMMENT event, so the timeline gets one entry per run rather than one per
  finding. A re-run edits its own previous comments rather than posting beside them, makes no write
  at all when it has nothing new to say, and retires the thread of a finding that has gone away.
- **A findings-off-the-diff section.** GitHub will not accept an inline comment on a line the pull
  request did not change, and the nearest changed line would point at the wrong code, so those
  findings are listed in the review body with severity, rule, location and a permalink to the
  reviewed commit instead of existing only as a number.
- **A pinnable release.** `uses: aicodesentry/mitig8it/action@v1`, a container image published to
  `ghcr.io` with a provenance attestation and an SBOM, and a released ref that pulls that image by
  digest instead of building one. Every documented install names a release tag or a commit sha, and
  a test fails if one ever names a branch again.
- **A version on every review.** The check run summary and the review body both name the version
  that produced them, so a bug report quotes a version rather than a date. A ref that is not a
  release says so rather than naming one it does not have.

### Known limitations at 1.0.0

These are measured, not suspected, and each one is stated where a user will meet it rather than
only here.

- **Recall is the weak half: 0.58** on labelled lines, and uneven by class. Deserialization and
  dynamic code execution are near 1.00; cross-site scripting reaches 26 of 32 labels with 18 from
  rules allowed to post; path traversal is 7 of 14. A clean review is not evidence that a file is
  clean.
- **Verification is development-grade or weaker.** Tests run as ordinary subprocesses with no
  network, kernel or filesystem isolation, in the Action and the App alike. Every executed
  candidate is `development_unverified` and every comment says "development sandbox". The isolated
  job is written and has never been proven to run.
- **17 verified fixes on real vulnerable code**, out of 249 corpus findings in a supported family:
  8 verified by running a test and 9 at `static_assertion`, where nothing executed. The binding
  constraint on the executed 8 is loading the module the proof names;
  `dependency_not_available_in_sandbox` is the largest single reason a finding gets no proof, at 84.
- **JavaScript, TypeScript and Python only**, plus 16 template extensions for tier 2.
- **The Action keeps nothing**, so it has no suppressions and no baseline: a finding you decided not
  to act on returns on the next pull request that touches those lines.
- **The cold start of a released ref is unmeasured.** The build it replaces was measured at 85 to
  111 seconds cold and 36 to 65 warm for a 745 MB image; nobody has yet timed a pull of that image
  on a GitHub runner, and no number will be published here until CI has produced one.

[Unreleased]: https://github.com/aicodesentry/mitig8it/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/aicodesentry/mitig8it/releases/tag/v1.0.0
