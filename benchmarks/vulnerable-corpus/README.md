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

# the reading list: every finding at a labelled line under an unexpected class, plus a
# seeded random sample of the findings no label covers
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --emit-queue /tmp/queue.json

# precision and recall, once the verdicts are written back
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md
```

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
