# Validation

Every number Mitig8it publishes about itself is measured here and written down with the run that
produced it. Nothing in this directory is an estimate.

| Document | What it measures |
| --- | --- |
| [vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md) | Precision and recall on 171 labelled vulnerabilities in 23 repositories, per rule, per class and per language, plus how far the repair families reach on real vulnerable code. |
| [real-repo-replay-2026-09.md](real-repo-replay-2026-09.md) | What the pipeline says on 165 merged pull requests from 11 public repositories that have no known vulnerability in them. |
| [tier2-coverage-2026-09.md](tier2-coverage-2026-09.md) | The widening of the AST rule set, what it found on that same clean corpus, and which rules are allowed to post as a result. |
| [action-trial-2026-09.md](action-trial-2026-09.md) | The GitHub Action installed on private copies of ten real repositories and read as their maintainer would read it. |
| [pairs-2026-09.md](pairs-2026-09.md) | Why a repair pair that exists does not verify: each complete pair's proof run against the original tree and the patched tree, what the two outcomes said, and what installing the repository's own dependencies changed. |

Two more documents belong to the same record without being measurements:
[../legal/third-party-rules.md](../legal/third-party-rules.md) is why every rule in the tree is
written in this repository, and
[../../benchmarks/remediation/README.md](../../benchmarks/remediation/README.md) is what the
evaluation corpus contains and what a pass rate from it does and does not mean.

## Reproducing the benchmarks

```sh
make deps
make bench
```

`make bench` runs the tier 1 precision gate, the tier 2 precision gate, and the remediation corpus
under the reference and engine-local adapters, then prints one table. Prerequisites are in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

The larger measurements in the documents above are not part of `make bench`, because they download
and analyse 23 third-party repositories and replay 165 pull requests against the GitHub API. Each
document names the command that reproduces it:
`benchmarks/vulnerable-corpus/README.md` for the corpus and `scripts/replay/README.md` for the
replay.

## Reference output

This is `make bench` on the integration branch, run on 25 September 2026, macOS on Apple silicon,
Python 3.11.6, Node 24.1.0. A run on your machine should print the same counts and rates; the
per-suite banner lines are omitted here.

```text
make bench, 2026-09-25

Benchmark                         Cases  Pass  Fail  Pass rate  Precision  Coverage  Abstention  Note
--------------------------------  -----  ----  ----  ---------  ---------  --------  ----------  -----------------------------
tier 1 precision gate             88     88    0     1.00       -          -         -           from 38 adjudicated findings
tier 2 precision gate             140    140   0     1.00       -          -         -           from 138 adjudicated findings
remediation corpus, reference     59     59    0     1.00       1.00       1.00      1.00        46 verified, 13 abstained
remediation corpus, engine-local  59     59    0     1.00       1.00       1.00      1.00        46 verified, 13 abstained

Precision, coverage and abstention are the remediation corpus's own definitions:
  precision   independently correct repairs / repairs the engine verified
  coverage    independently correct repairs / supported fixtures
  abstention  negative and adversarial fixtures correctly refused / all of them
The reference adapter replays the checked-in repairs, so it measures fixture integrity
rather than the agent. The engine-local adapter runs the real pipeline against a
scripted provider, so it measures pipeline integrity rather than repair quality.
Neither is a measurement of a model. See benchmarks/remediation/README.md.
```

### How to read that table

A 1.00 here is not a quality claim, and the four rows do not mean the same thing.

The two precision gates are regression gates, not measurements. Their cases are lines that were
already read by hand and judged, in the corpus and replay runs above: every false positive the
replay found, and one true positive per rule family. They pass when the rules still suppress what
was judged wrong and still find what was judged right. A rule change that breaks either direction
fails here. The measured precision of the rules themselves is the 0.67 to 0.97 range in the corpus
document, not this column.

The remediation corpus rows are 59 authored fixtures against a release manifest that asks for 120
externally reviewed cases. The reference adapter replays the checked-in repair, so its 1.00 says
the fixtures and the grader agree with each other. The engine-local adapter runs the real pipeline
against a scripted provider replaying that fixture's reviewed repair, so its 1.00 says the pipeline
carries a finding from intake to a verified candidate. Neither measures a model, and 59 authored
cases cannot establish a rate. Both adapters verify in the local subprocess sandbox, so every
candidate is `development_unverified`.

The two numbers that do measure the product on code it had not seen are in the corpus and action
trial documents: precision 0.67 to 0.97 depending on which rules post, recall 0.40 to 0.58, and
63 of 65 posted comments judged true positives on ten real repositories.
