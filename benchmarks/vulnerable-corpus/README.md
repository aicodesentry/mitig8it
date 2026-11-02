# Vulnerable corpus

Code that is known to contain vulnerabilities, with the vulnerable lines labelled, so the
rule set can be measured for **recall** as well as for noise.

The real-repository replay (`docs/validation/real-repo-replay-2026-09.md`) runs 165 merged
pull requests of mature libraries. It is the right corpus for "does this rule set annoy a
reviewer", and it is the wrong corpus for "does this rule set find anything": a rule that
matches nothing and a rule that matches the wrong thing both score zero findings there.
`docs/validation/tier2-coverage-2026-09.md` says so in as many words. This is the corpus
that answers the other question.

## What is in it

Two kinds of source, because they fail in different ways.

**Intentionally vulnerable applications.** Their own documentation says where each
vulnerability lives, so the ground truth is written down rather than inferred. They are
also written to be found, so a rule that only works on them has proved little.

**CVE fix commits.** The commit that fixed a published advisory, replayed against its
*parent* tree, which still contains the vulnerability. The lines the fix deletes are the
vulnerable lines. This is real code that a real maintainer had to repair, and it is
unforgiving: much of it looks nothing like a textbook example.

Every repository's licence was read in the downloaded snapshot, not taken from the GitHub
API field. `labels.json` records the licence and the sentence that was checked for each.
A repository with no licence file grants no permission and is not in the corpus, which is
why `we45/Vulnerable-Flask-App` was considered and dropped in favour of `anxolerd/dvpwa`.

## Files

| File | What it is |
| --- | --- |
| `labels.json` | The corpus: the repositories with their pinned refs and licences, and every label. |
| `adjudications.json` | Verdicts on findings no label covers, keyed by finding fingerprint. Every entry carries a `source`, and `hand` is the only one precision counts. |
| `harvest_cve_labels.py` | Proposes candidate labels from advisories that name their fixing commit. |
| `recall-baseline.json` | Per label, whether it is detected and whether a posting rule detects it. Generated; see below. |

`source` exists because a model may suggest a verdict and only a human may license a rule
to post: `load_adjudications` refuses a file where any entry omits it, and `score.py` keeps a
verdict whose source is anything but `hand` out of the precision numerator and denominator,
reporting it as model-suggested and putting it on the reading list for a human instead.

A label is one vulnerability:

```json
{
  "id": "dsvw-cmdi-nslookup",
  "repo": "stamparm/DSVW",
  "ref": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
  "path": "dsvw.py",
  "line_range": [31, 31],
  "cwe": "CWE-78",
  "rule_classes_expected": ["command_injection"],
  "source": "DSVW CASES: Command Injection (blind), ?domain=;id",
  "evidence": "the source line, as it is in the tree"
}
```

`rule_classes_expected` is drawn from `taxonomy.CANONICAL_INTERNAL_TYPES`, which is the
vocabulary the product groups findings by; `score.py` refuses a label that invents a class.
It lists every class a correct scanner could report for that line, so a finding that names
any of them counts as a hit.

## No source tree is committed

The snapshots are downloaded, not vendored: a corpus of intentionally vulnerable
applications inside this repository would be a supply of exploitable code in every clone,
and would drag six upstream licences into the tree. `scripts/replay/corpus.py` downloads
the tarball for a `(repo, ref)` pair into `scripts/replay/.cache/snapshots/`, which
`.gitignore` covers, and extracts it there. A member whose path escapes the extraction root
is refused.

Refetching is deleting the cache and running the harness again; every ref in `labels.json`
is a full 40-character commit sha, so what comes back is byte-identical:

```sh
rm -rf scripts/replay/.cache/snapshots
scripts/replay/replay.py --snapshot --repo stamparm/DSVW \
    --ref 9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908 --out results/dsvw.json
```

## Running the measurement

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# one repository tree, both tiers, quarantined rules included so they can be re-measured
$PY scripts/replay/replay.py --snapshot --include-quarantined \
    --repo OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
    --out results/nodegoat.json

# the reading list: every finding at a labelled line under an unexpected class, every
# model-suggested verdict awaiting a human, and a sample of the findings no label covers,
# ranked by what reading them would unblock. The posting bar is three adjudicated findings
# at 0.8 or better (docs/services/analysis-service.md), so quarantined rules short of that
# bar come first, then rules that post today on fewer verdicts than the bar asks for.
# `--seed` still reproduces a given list: it is the tie-break within a rank.
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --emit-queue /tmp/queue.json

# precision and recall, once the verdicts are written back
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md
```

## The recall ratchet

`recall-baseline.json` records, for every label, whether a finding of an expected class lands
on the labelled lines (`hit`) and whether one of those findings comes from a rule that is
allowed to post (`posting_hit`). `scripts/replay/ratchet.py check` compares a fresh run with
it, so a label that is detected today cannot stop being detected without somebody seeing it.
The precision benchmarks cannot do this: they keep one true positive per rule family, and a
rule can lose most of its real detections and still match that one.

```sh
make recall-ratchet     # scan the 23 trees, compare with the baseline
make recall-baseline    # scan the 23 trees, rewrite the baseline
```

or, with the result files already on disk:

```sh
$PY scripts/replay/ratchet.py measure --results results/
$PY scripts/replay/ratchet.py check results/
$PY scripts/replay/ratchet.py update results/
```

`check` exits 1 and names the label ids when a label that was hit is no longer hit, and,
listed separately, when a label that a posting rule hit is now hit only by a quarantined
rule. A newly hit label is printed as an improvement and does not fail. It exits 2 when the
run is not a measurement of the whole corpus (a repository has no result, a batch died, a
stage ran out of time, the scanner was missing) or when the baseline and `labels.json` name
different labels, because findings lost to a timeout are indistinguishable from a rule that
stopped matching. `measure` runs tier 1 without its time budget for the same reason;
`scripts/replay/README.md` says what that budget was doing to snapshot runs.

Refresh the baseline in the same change whenever one of these is true, and commit the result:

* a rule change reaches a label it did not reach before, so the gain is held from then on;
* a label is added to or removed from `labels.json`;
* a loss is intended, for example a rule is quarantined on measured precision. The label then
  appears in the baseline's diff, which is where a reviewer is asked to agree to it.

The baseline also carries the rule ids that matched when it was written. They are there so a
failure can say what used to match, and they decide nothing: a label stays hit when a
different rule takes it over.

`.github/workflows/recall-ratchet.yml` runs the check on pull requests that touch the rules,
the scanner wrapper, `scripts/replay/` or this directory.

## Adding a label

A label is a measurement, so it has to be one someone read.

* Print the range out of the snapshot before writing it down. A line number copied from a
  blog post or an advisory summary is a guess, and a guessed label silently becomes a
  missed vulnerability in the recall table.
* Label a **sink**, not a design decision. "No CSRF middleware", "no authorization check"
  and "the seed data has a weak password" are real defects with no line for a pattern to
  match; a line range for them measures nothing and makes recall look worse than it is.
  What was left out for this reason is listed in
  `docs/validation/vulnerable-corpus-2026-09.md`.
* Keep the range tight. One to four lines, around the call that does the dangerous thing.
  `score.py` allows two lines of slack in either direction, which is the width of a wrapped
  call; a label spanning a whole function would collect any finding in it.
* For a CVE, take the range from the fix diff's **old side**, at the parent commit's line
  numbers, and check that what the fix deleted really is the vulnerable statement.
  `harvest_cve_labels.py` prints the candidates; it does not decide.
* Refresh `recall-baseline.json` in the same change. The ratchet refuses to compare while the
  two files name different labels.

## Strict standalone detection report

The historical `score.py` report is exploratory: it flattens findings without
retaining completed-zero-result versus failed/missing file coverage, and joins
hand verdicts by fingerprint without binding the system/configuration revision.
Do not use its fixture percentages as production accuracy or release admission.
The labels are incomplete, so an unlabelled alert is not automatically false and
an unobserved tree is not automatically a missed vulnerability.

The stricter offline contract is separate and does not modify these labels:

```sh
.venv/analysis/bin/python -m benchmarks.detection_evaluation \
  --labels benchmarks/vulnerable-corpus/labels.json \
  --observations path/to/detection-observations.json \
  --adjudications path/to/scoped-adjudications.json
.venv/analysis/bin/python -m pytest benchmarks/test_detection_evaluation.py -q
```

No observations is a supported diagnostic: all labels remain unobserved. Legacy
replay JSON or fingerprint-only adjudications are explicitly invalid for this
contract; the report never backfills identity from the current checkout.

Each observation document must use `schema_version: detection-observations-v1`
and contain:

- `corpus_sha256`: SHA-256 of the complete canonical label document (JSON with
  sorted keys and compact separators), not just the labels that were detected.
- `scope: published_detection`, the pinned `repo` and full 40-character `ref`.
  Only one observation document per repository/tree is accepted; do not pool
  repeated runs or different systems as independent samples.
- `system`: full 40-character `source_revision`, 64-character `artifact_sha256`,
  `configuration_sha256`, and `publication_policy_sha256`, plus boolean
  `triage_enabled`. All documents in one report must identify the same system.
  Configuration identity must cover scanner versions, enabled stages, flags,
  model/prompt identity when enabled, and all effective detection settings.
- `files`: explicit file observations with canonical relative `path`, full
  `source_sha256`, `findings` (including an explicit empty array when none), and
  `stages`. Stage keys are exactly `tier1`, `tier2`, and also `tier3` when enabled;
  each status is `complete`, `partial`, `error`, or `not_attempted`.
- Each finding has nonempty `fingerprint` and `rule_id`, matching `file_path`,
  positive integer `line_start`/`line_end`, and canonical `internal_type`.
  Duplicated file records/fingerprints, malformed findings, mixed identity,
  missing stages, or a different corpus digest are reported as errors.

A hand-review document uses `schema_version: detection-adjudications-v1`, the
same `corpus_sha256`, and an `observations` array. Each review requires
`observation_id`, `verdict` (`true`, `false`, or `uncertain`), `reviewer`, `source`,
and `sampling_unit`. Use the ID emitted by the report: it hashes the entire
finding, source-file digest, repository/ref, and system object. Changing any
of those invalidates the review rather than silently reusing it. Duplicate,
stale, or conflicting judgments are errors; conflicts remain uncertain.

The report distinguishes:

- Precision among label-confirmed or scoped-human-reviewed **accepted alerts**,
  with its numerator/denominator and unresolved-alert count. Bounds over all
  accepted alerts treat every unresolved judgment as false or true respectively.
- Recall of **labeled vulnerabilities**: exact line overlap and expected class
  are required, with one-to-one maximum matching. One broad finding cannot
  satisfy two labels, and duplicate alerts do not automatically become extra
  true positives. A miss requires all enabled stages to complete for that file.
  Unscanned/failed coverage stays unknown; all-label bounds disclose its effect.
- Labeled-file completion, missing trees/files, incomplete stages, invalid
  observations, and language slices. This is not whole-repository coverage:
  the label manifest does not enumerate every source file or vulnerability.
- Two-sided 95% Wilson **IID reference** intervals, explicitly not production
  confidence intervals: repository dependence, selection bias, and independent
  holdout sampling have not been established. Accuracy, true negatives, and F1
  are null, because the corpus is not exhaustively labeled and the two metrics
  use different units. Invalid records are listed separately, not certified or
  silently presented as valid denominator observations.

`production_ready` and `release_admissible` are always false. The default CLI
exits 2, including for perfect fixture results; `--report-only` explicitly permits
diagnostic exit 0 without changing those fields. This check is intentionally
not connected to production readiness or publication. To earn that integration,
collect frozen, independently reviewed, representative holdout evidence with
verified execution/system provenance, complete file/stage coverage, and an
explicit sampling/cluster uncertainty plan. Digest strings assert identity but
do not authenticate an execution. No such evidence is fabricated by this tool.
