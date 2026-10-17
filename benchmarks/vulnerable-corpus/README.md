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
| `adjudications.json` | Hand-read verdicts on findings no label covers, keyed by finding fingerprint. |
| `harvest_cve_labels.py` | Proposes candidate labels from advisories that name their fixing commit. |
| `recall-baseline.json` | Per label, whether it is detected and whether a posting rule detects it. Generated; see below. |
| `fixture-subset/` | The labelled files the baseline holds as hit, with their licences, for the required recall floor. Generated; see below. |
| `adjudicate.py` | Model-proposed verdicts for unjudged findings, kept in `adjudications-model.json`, never in the human file. |

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

## Only the labelled files are committed

The snapshots are downloaded, not vendored: a corpus of intentionally vulnerable
applications inside this repository would be a supply of exploitable code in every clone,
and would drag every upstream licence into the tree. The one exception is
`fixture-subset/`: the 59 files that carry a label the recall baseline holds as hit, each
copied at its pinned ref beside the licence of the repository it came from, so that a check
which needs no download can run on every pull request (see "The recall floor" below). They
are scanned, never installed or executed, and `.mitig8it.yml` keeps them out of review. Every
whole tree stays downloaded. `scripts/replay/corpus.py` downloads
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

# the reading list: every finding at a labelled line under an unexpected class, plus a
# seeded random sample of the findings no label covers
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
the scanner wrapper, `scripts/replay/` or this directory, and every Monday on its own, because
a scanner or dependency change can move a match without touching any of those paths.

## The recall floor

The ratchet downloads 23 trees, so it is path-filtered and cannot be a required check. The
floor is the part that can: `fixture-subset/` holds every labelled file whose label the
baseline holds as hit, from repositories whose licence in `labels.json` is permissive (all
of them today), and the `recall-floor` job in `.github/workflows/ci.yml` scans it on every
pull request and is one of the jobs `Required CI` waits for.

```sh
scripts/replay/fixture_subset.py check    # scan the subset, compare with fixture-subset/expected.json
scripts/replay/fixture_subset.py update   # rewrite expected.json from a complete run
scripts/replay/fixture_subset.py build --gitleaks --snapshots scripts/replay/.cache/snapshots
```

`check` scans the subset the way a snapshot run scans a tree, quarantined rules included and
both tiers' time limits lifted, and compares with `expected.json` using the ratchet's own
comparison. It exits 1 when a label that was hit is no longer hit, when a posting hit is now
quarantined only, or when the hit count falls below the floor `expected.json` records, and 2
when the scanner is missing, a tier failed or the files differ from `manifest.json`.

`build` copies the files out of a local snapshot cache. A secret gitleaks reports is
overwritten with `x` of the same length, so every line number stays as pinned and the
repository's own secret scan stays green; the redactions are listed in `manifest.json`. Run
`build` and then `update` whenever the baseline gains or loses a hit label, and commit both.
`tests/test_recall_floor_subset.py` in the analysis suite fails when the subset no longer
carries every permissive label the baseline holds as hit.

## Model-proposed verdicts

`adjudications.json` is hand-read. `adjudicate.py propose results/*.json` sends findings no
label or person has judged to the model configured for tier 3 (`call_llm`), asking for a
verdict, a quote from the flagged line and one sentence, and writes the answers to
`adjudications-model.json` with `source: model`, the model id and the prompt version. A quote
that is not on the flagged line is recorded as such and never counted. `--calibrate` also
re-judges the 71 findings of the original hand-read sample, and `adjudicate.py report` prints
Cohen's kappa and a confusion table against those. Nothing reaches the human file except
through `adjudicate.py accept <fingerprint>... --reviewer NAME`, which copies only the named
entries and records who read them.

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
