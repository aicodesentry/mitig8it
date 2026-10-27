# Working in this repository

Mitig8it reviews a pull request for exploitable code and posts a fix underneath the finding, as a
suggestion the developer commits in one click. The product's claim is the proof: a generated
regression test that fails on the original tree and passes on the repair. A change that raises
finding volume faster than fix coverage is a regression, not a feature.

## Read the measurement before proposing anything

Nearly every obvious idea here has already been tried and written up. `docs/validation/` holds the
number and the run that produced it for every claim the project makes. Check it before suggesting a
direction, and quote published ranges in full (recall is 0.40 to 0.58, not 0.58).

Two that catch people repeatedly:

- Installing repository dependencies in the proof sandbox was measured. It moved verified pairs
  from 8 to 8. See `docs/validation/pairs-2026-09.md`.
- Broken authorization and IDOR are unreachable without taint tracking. Do not promise them.

`docs/architecture/known-debt.md` lists what was deliberately left undone and why. If something
looks obviously wrong, it is probably in there with a reason.

## Commands

```sh
make deps     # create the two virtualenvs and install node modules, the way CI does
make test     # every suite, stopping at the first failure
make bench    # tier 1 and tier 2 precision gates plus the remediation corpus, one table
```

Per-suite targets exist for a faster loop: `test-analysis`, `test-remediation`, `test-api`,
`test-github`, `test-frontend`, `test-action`, `test-harness`, `test-quality`.

Both virtualenvs are built with `python3.11` and they are separate because the two services pin
incompatible `opentelemetry-api` versions, not incompatible Pythons. The remediation container
itself runs 3.12, so a version-sensitive change needs checking in the image and not only in the
virtualenv. Node is 22.

**Always put a timeout on a test command.** The full analysis suite runs real semgrep scans and
takes about seven and a half minutes; `timeout 900` is a sensible ceiling. A command with no
timeout that appears to hang is usually semgrep working.

## House style

- **No em-dashes.** Anywhere: code, comments, commit messages, documentation, pull request bodies.
- **No `Co-Authored-By` or assistant attribution trailers** in commit messages.
- **Every commit needs `Signed-off-by`** matching its author. Use `git commit -s`. The DCO check
  fails the pull request otherwise, and `github-actions[bot]` is the only exemption.
- Comments in this tree say *why*, not *what*. Match the surrounding density before adding one.
- Documentation states what was measured and what was not. "Nothing in this directory is an
  estimate" is a promise the repository keeps.

## Branches and worktrees

Direct pushes to `main` are blocked by `.githooks/pre-push`; run `scripts/install-git-hooks.sh`
once. Work on a branch, open a pull request.

Worktrees under `.claude/worktrees/` are frequently **behind their pushed remotes**, and some
remotes already carry a merge of `main`. Before touching one:

```sh
git fetch origin <branch> && git reset --hard origin/<branch>
```

A force-push from a stale worktree discards work silently. The stash stack is shared across
worktrees, so never use bare `git stash` / `git stash pop`.

### Conflict shapes seen repeatedly

- `docs/validation/README.md` index row, and appends to `benchmarks/tier2-precision/cases.json` and
  `benchmarks/vulnerable-corpus/adjudications.json`: **pure unions.** Keep both sides and verify by
  entry count rather than by eye.
- `services/analysis-service/src/tests/test_tier2_rule_metadata.py`: **not a union.** Both sides
  tend to edit the same `workflow_hardening` key, and a textual union leaves two identical keys in
  one dict literal where the last silently wins. Take the widened CWE set, append the new families.

## CI facts worth knowing

- `Required CI` aggregates the other jobs. It is only a merge gate if a branch rule names it;
  check `branches/main/protection` before assuming it blocks anything.
- `npm audit` and `pip-audit` run on a daily schedule in `security-audit.yml`, deliberately **not**
  in the blocking gate. An advisory feed moves without the code moving, and a nightly CVE used to
  turn every open pull request red for a reason its author could not act on.
- If a pull request reports **no checks at all**, that is not a broken CI. Look for runs with
  conclusion `action_required`: the repository requires manual approval for workflow runs, and a
  bot's merge commit or an outside contributor's push lands there.
- `Dockerfile.prod` is what ships for api, github and analysis. CI builds both it and the dev
  `Dockerfile`.
- The deploys are staged: `--no-traffic --tag candidate`, check the candidate's own URL, then
  `update-traffic --to-latest`. A failed check promotes nothing. `docs/runbooks/rollback.md` is the
  authority on what to do when a bad revision did get promoted.

## Definition of done

A detection or fix change is not done when its tests pass. It is done when it has run against a
real pull request. Open one on `nebullii/test-only` with the Action pinned to the branch ref, and
read what a maintainer would read: the findings, the suggestion blocks, and the Verified lines.
`docs/architecture/agentic-remediation-progress.md` carries the evidence history, and
`docs/validation/action-trial-2026-09.md` is what that reading looks like written down.

Every fix carries a regression test that fails on the original and passes on the change. That is
the bar the product sets for other people's code, so it is the bar for its own.
