# Remediation corpus intake and preregistration

`python -m benchmarks.remediation.corpus_intake` is an offline planner and input
integrity check. It makes no model calls, fetches no repositories, executes no
source/test code, and supplies no signatures or review approvals. Successful
intake is **not** a passed release gate, statistically validated recommendation,
or production-readiness decision. All thresholds remain in the existing
`benchmarks/remediation/release-manifest.json` and shared precision gate.

## Inspect the actual deficits

```sh
.venv/remediation/bin/python -m benchmarks.remediation.corpus_intake plan
```

The current 81 authored cases comprise 67 supported, 10 negatives and four
adversarial cases; holdout contains 17 supported and two of each control kind.
The report includes family/kind counts within each split. There is no invented
train/validation floor.

The headline minimum of 120 is not the effective minimum: seven families times
20 supported cases, plus 30 negative and 30 adversarial cases, requires **200**.
The family gaps are SQL 7, command 7, path 9, credentials 10, eval 16, password
12 and cookies 12. Adding those 73 supported, 20 negatives and 26 adversarial
cases takes **119 additions** to satisfy the family/kind floors.

The holdout now independently needs 20 supported cases **per family**, 30 negative
cases and 30 adversarial cases. Its supported-family gaps total 123; its control
gaps are 28 negative and 28 adversarial. Without resplitting existing cases or
reusing lineages, satisfying these strata requires **179 additions**, yielding
260 total cases and at least 200 in holdout. Train/validation controls cannot fill
holdout deficits, even when aggregate holdout accuracy is perfect.

Separately, the 100-published-prediction requirement has at most 15 current
publishable holdout slots: two of the 17 supported holdout cases explicitly require
production abstention. They remain in the supported coverage denominator. The
additional prediction-capacity gap is therefore 85, already dominated by the
stratified intake requirement above. Those slots are not
qualifying predictions: real model runs, independent adjudication, the Wilson
bound, coverage, signed review, and production isolation remain unproven.

`intake_requests` describes requested counts, not invented case identities.
`review_queue` lists the existing authored inputs by digest and explicitly marks
them as not established as preregistered. Nothing retroactively turns a seen case
into independent holdout.

## Prepare new inputs before observing model results

An independent case curator supplies a separate candidate directory using the
existing `fixture.json` contract, source/reference files, and fixed exploit and
legitimate-behavior tests. Do not edit the evaluated seed merely to fill counts.
Each fixture additionally needs `intake_provenance` with exactly these fields:

- `origin`: `independent_repository`;
- `upstream_repository` and `lineage_root`: credential-free HTTPS owner/repository
  URLs. For a fork or derivative, identify the original lineage rather than
  inventing a new one; URL case and `.git` suffix differences do not create a
  new lineage;
- `upstream_revision`: exact 40-character Git commit SHA;
- `collected_at`: UTC `YYYY-MM-DDTHH:MM:SSZ`, after the upstream commit and no
  later than preregistration;
- `case_authors` and `oracle_authors`: nonempty, distinct stable identity lists,
  with no overlap. These declarations are not authenticated reviewer approvals;
- `model_outputs_observed`: the literal boolean `false`;
- `source_artifacts`: exactly every affected source path, each mapping to
  `{"upstream_path": "...", "sha256": "sha256:...", "git_blob_oid": "..."}`;
- `oracle_artifacts`: exactly the fixed `tests/` files named by verification
  checks and the optional trusted fixture test, mapped to their `sha256:...`;
- `review_document` and `review_document_digest`: a nonempty local provenance,
  license, sampling/independence, label, and behavior-preservation rubric document.

Source, reference, test and review-document roles must not overlap. Every fixture
file, including metadata and reference repairs, is included in its frozen digest.
Missing provenance, changed bytes, symlinks, observed outputs, overlapping authors,
and embedded result records are refused. Merely updating a declared hash cannot
substitute new source: the tool reads the pinned blob from the local upstream Git
checkout, requires a regular file, and compares its exact bytes.

Provide an origins JSON map from each canonical lowercase upstream URL to an
existing local Git checkout. Obtain and license-check those repositories through
an authorized workflow first. The intake command never clones or fetches them.

```sh
.venv/remediation/bin/python -m benchmarks.remediation.corpus_intake preregister \
  --candidates /path/to/new-candidate-inputs \
  --origins /path/to/local-upstream-checkouts.json \
  --output benchmarks/remediation/release/intake/<new-batch-id>.json
```

Create the `release/intake` directory when the first real batch is available. No
empty or fabricated registration is supplied here. An existing output is never
overwritten. Known baseline and ledger case IDs, repository/lineage identities,
upstream revisions and exact source hashes cannot be reused, including under a
new name or split. Additional external registration histories may be supplied
with repeated `--history` arguments; committed local ledger entries are always
loaded and cannot be omitted through flags.

Review and commit that preregistration **before** evaluating the model. Ledger
files are append-only: modification, deletion, renaming, or dirty/missing committed
records is refused. Correct a rejected batch with a genuinely new registration
and retain the old record; do not erase unfavorable inputs after seeing outputs.
This intentionally conservative policy can reserve a lineage without admitting
it to the corpus. Case exclusions require independent review, not record deletion.

## Validate frozen intake and produce the review queue

```sh
.venv/remediation/bin/python -m benchmarks.remediation.corpus_intake validate \
  --candidates /path/to/new-candidate-inputs \
  --origins /path/to/local-upstream-checkouts.json \
  --registration benchmarks/remediation/release/intake/<batch-id>.json \
  --registration-revision <commit-containing-the-preregistration>
```

The registration must exactly match its committed bytes and current manifest,
baseline inventory, prior registrations, and all candidate inputs. Later batches
do not invalidate an earlier batch: history is checked as of its preregistration
commit, while ledger tampering is checked through current HEAD.

To bind subsequent observations, add `--evaluation /path/to/intake-results.json`.
That document has exactly `registration_digest`, `registration_revision`,
`source_revision`, `started_at`, `finished_at`, and a `results` array. Times use
UTC `YYYY-MM-DDTHH:MM:SSZ`; evaluation must start strictly after the committed
preregistration, finish afterward, and not be in the future. The evaluated source
commit must descend from the preregistration commit. Every row must identify its
`fixture_id`, `repository_id`, `split`, `kind`, `family`, and `fixture_digest`
exactly; duplicate, missing, extra, or relabeled rows fail. Other per-row evidence
is retained for the separate evaluator/reviewer; a failed result is not excluded
from intake merely because it failed.

The emitted queue binds each case and says `awaiting_independent_review`,
`review_approved: false`, and whether results are available. Preserve full signed
production-sandbox/model evidence and use the separate
[external release-review runbook](remediation-release-evidence.md). Intake does
not replace that protocol or grant deployment admission.

## Production admission requires the complete preregistration chain

The production release verifier independently repeats intake validation; signed
result metadata alone is insufficient. Its fixed origin policy is
`benchmarks/remediation/release/intake-origins.json`, mapping credential-free
canonical upstream URLs to existing local Git checkouts. Supply that non-secret
policy through an owner-reviewed change and prepare the local repositories before
verification. It is not accepted from a release bundle or environment variable.
An absent policy or unavailable pinned blob fails closed; verification never fetches.

The evaluated source revision determines the **entire** committed intake ledger.
The verifier derives each registration's actual introduction commit and digest
from Git, reconstructs its historical baseline, and validates current complete
fixtures, source blobs, reference repairs, oracles, and provenance against the
frozen registration. A case already present in that historical baseline cannot
become a new independent case through a later signature, new ID, or new split.
The current authored seed has no preregistration exception and remains
nonpromotable. Do not create retrospective registrations for it.

Every registered case must be present in the counted corpus and result array;
every counted fixture must have exactly one registration. There is no mechanism
to quietly omit an unfavorable or pending registered batch. Exclusions would need
a separately designed and independently approved protocol, not file deletion or
an evaluator-selected subset. Metadata-only fixtures, incomplete test contracts,
changed source/oracle bytes, and reused lineages cannot count toward statistics.

Release evaluations record UTC `started_at` and `finished_at` plus independently
derived `preregistrations`, an array of `{path, revision, digest}`. Evaluation must
start after each introduction commit. The release receipt must sign the computed
`intake` binding: ledger/population/origin-policy digests, exact count, and evaluation
times. A valid old authentication-only receipt without that binding does not
authorize admission. Approved reviewers also cannot approve cases for which their
identity appears as a case or oracle author.

This is a prerequisite, not a replacement for external signatures, statistical
and holdout/control gates, production sandbox evidence, or exact evaluated service
and runner image identities. Tests isolate statistics with explicit mocks where
appropriate and separately exercise this chain against temporary real Git objects;
none of those synthetic tests constitutes an actual release approval.

## Limits and operator obligations

Git hashes/ancestry and declared timestamps establish local ordering and input
consistency, not trusted timestamping or that nobody privately saw a model output.
Identity strings do not prove people are independent; exact duplicates and
declared lineages do not discover every hidden fork or semantic near-clone.
Independent reviewers must audit sampling, origin/fork relationships, licenses,
exposure history, author identities, labels, oracle adequacy, and legitimate
behavior (including password migration and cookie/TLS effects). No self-signing,
threshold changes, synthetic approvals, or claims of production accuracy are
authorized by a successful command.

Tests use temporary, explicitly synthetic Git repositories only:

```sh
.venv/remediation/bin/python -m pytest \
  benchmarks/remediation/tests/test_corpus_intake.py -q
```
