# Secrets in the diff, September 2026

The second of the four categories
[community-rules-adoption.md](../architecture/community-rules-adoption.md) ranks above
everything else, and the one the product was worst at. Coverage before this change was one
tier 1 regex, `secret.hardcoded.credential`: a credential-ish identifier, a colon or an equals
sign, and twelve or more characters of anything. No key formats, no structural verification, no
entropy, and it is one of the rules that has fired on documentation prose.

This is the measurement of what replaced it: two signals, on three corpora, with **every finding
of both signals read by hand**. The reading rule was every finding of a signal that fired ten
times or fewer and a seeded random ten otherwise; both signals fired more than ten times and both
were read in full anyway, because forty-two findings is a readable number and a sample would have
left the posting decision resting on less than it had to.

## What is being measured

`services/analysis-service/src/secret_detection.py`, two rule ids:

* **`secret.format.known_key`**: seventeen published key formats, each verified against the
  structure it declares. The table of what is verified per format is in
  [docs/services/analysis-service.md](../services/analysis-service.md#secrets-in-the-diff).
* **`secret.entropy.credential_assignment`**: a high-entropy value assigned to an identifier
  whose name says it is a credential, with twelve named exclusions for the shapes that are
  legitimately high entropy.

Both read the **added lines only**. An existing secret is not this pull request's fault, and
re-reporting it on every change to the file is how a category gets muted; the corpora below
therefore measure snapshot runs, where the whole file is the addition, which is exactly what
production sends tier 1 for a newly added file.

## The three corpora

| Corpus | How it was run | What it answers |
| --- | --- | --- |
| The eleven clean repositories | `scripts/replay/replay.py --repo <r> --prs 15`, 165 merged pull requests, the set in [real-repo-replay-2026-09.md](real-repo-replay-2026-09.md) | does this annoy a maintainer |
| The vulnerable corpus | `scripts/replay/replay.py --snapshot --include-quarantined` over the 23 pinned trees of `benchmarks/vulnerable-corpus/labels.json` | does it find a real one |
| This repository | the detector over every tracked file as a whole-file addition, plus the exact lines of `.gitleaksignore` fetched out of the commits it names | does it fire on our own fixtures |

The third corpus is the one worth explaining. This repository's own secret scanner has caught
nine lines in our fixtures, and a human has cleared every one of them in `.gitleaksignore`.
That file is a ready-made set of known false positives for exactly this category, written down
by somebody who was not thinking about this detector, and it is the hardest of the three.

## Per-signal precision

Two denominators, and the difference between them is the whole result.

**No informational finding is ever posted inline.** A finding in test code is downgraded to
`informational` by `classify_finding`, and both the App and the Action count it in the summary
line ("N informational findings in test code, not posted") and never annotate it; that behaviour
is [security-guardrails.md](../architecture/security-guardrails.md) and it predates this change.
So a signal's precision over every finding it produces and its precision over the findings a
reviewer actually reads are different numbers, and it is the second one the posting policy is
about.

| Signal | Adjudicated | True | False | Precision, all | Posted | Posted true | Precision, posted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `secret.format.known_key` | 19 | 3 | 16 | 0.16 | 3 | 3 | **1.00** |
| `secret.entropy.credential_assignment` | 20 | 5 | 15 | 0.25 | 5 | 5 | **1.00** |

**Forty-two findings were read; the table is over the thirty-nine that remain.** Reading them
turned up two detector defects, described below, and fixing those removed three of the
forty-two: one jwt.io example token and two unsigned JWTs. The three keep their verdicts in the
adjudications file, flagged `no_longer_fires`, because the reading is the record; the table
describes the detector as it now stands, which is the thing that will run on a pull request.

Thirty-nine findings, every one read, eight true. The split is not a rounding artefact: **all
eight true positives are outside test code and all thirty-one false positives are inside it.**
That is not luck, it is the shape of the corpora and probably of software: a repository writes
invented credentials in its tests and real ones in its configuration and its source. The eight
are listed one line each in the next section and anybody can re-read them.

Read the `all` column as the honest cost of the category. Thirty-one lines in these three corpora
are values that look exactly like credentials and are not, and the detector says so about all of
them. It says so in the one place that costs a reviewer almost nothing, a number in a summary
line, and that is the only reason the `posted` column is allowed to govern the decision.

Two caveats on the numbers themselves, in the spirit of the tier 2 write-up's:

* **A snapshot is not a pull request.** The vulnerable corpus is scanned as whole-file additions,
  so every line in a 23-repository tree is "added". A real pull request touching juice-shop's test
  suite would produce a handful of these, not thirty-one.
* **Three posted findings is three.** `secret.format.known_key` clears the policy's three-finding
  floor exactly, and a fourth posted finding of the wrong kind would take it to 0.75. Its claim to
  post does not rest on that count alone; see the posting decision below.

## What the corpora showed

### The eleven clean repositories: silence

165 merged pull requests, 11 findings in total from the whole tier 1 and tier 2 rule set, and
**not one from either secrets signal**. The legacy regex fired twice, both times on
`password: 'old-password'` in sindresorhus/got's tests, which is the shape it was always going to
fire on and the shape the entropy signal refuses on its value.

This is the result the category needed and it is also the least informative of the three: a
maintainer's ordinary pull request does not usually add a key, so silence here is evidence of no
false positives rather than evidence of recall. The recall evidence is the corpus below.

### The vulnerable corpus: one real private key, and two real tokens

23 pinned trees, 2429 findings from the whole rule set, 30 from the two secrets signals across
three repositories. Eight are true, and here is every one of them:

| Signal | Repository | Path and line | Format | Verdict |
| --- | --- | --- | --- | --- |
| format | juice-shop/juice-shop | `lib/insecurity.ts:21` | private key PEM | an RSA private key, complete, inlined into a JavaScript string in production source |
| format | adeyosemanputra/pygoat | `introduction/static/js/a7.js:4` | JWT | a signed session token for user id 1, commented out in shipped frontend JavaScript |
| format | adeyosemanputra/pygoat | `introduction/static/js/a9.js:18` | JWT | the same token, live rather than commented, in the sibling file |
| entropy | OWASP/NodeGoat | `config/env/development.js:6` | high-entropy assignment | a scanner API key as an object property of a committed configuration module |
| entropy | OWASP/NodeGoat | `config/env/test.js:6` | high-entropy assignment | the same key in the second environment config |
| entropy | adeyosemanputra/pygoat | `introduction/views.py:866` | high-entropy assignment | an account password literal written into the database from application code |
| entropy | adeyosemanputra/pygoat | `introduction/views.py:870` | high-entropy assignment | the same, for a second seeded account |
| entropy | adeyosemanputra/pygoat | `introduction/views.py:872` | high-entropy assignment | the same, for a third |

**Every value in that table is redacted and stays redacted.** These are public repositories, and
the repository, the path, the line and the format are the whole of what this document records; no
value appears in a commit, in a case file, in this document or in the report of this work. Where
the benchmark needed one of these shapes as a fixture, the value is locally generated and the case
says so.

The private key is the one worth naming. `lib/insecurity.ts:21` of juice-shop carries an entire
RSA private key as a single-line JavaScript string with `\r\n` escapes, in production source
rather than in a test. Juice-shop is a deliberately vulnerable teaching application and that key
is deliberately leaked, and two of the false positives in this very measurement are its own test
fixtures for the challenge built on it. It is still, on its own terms, exactly the finding this
detector exists for: the highest-severity shape, in the file that ships, found by a structural
check rather than by a substring, reported with no fix offered and the instruction to rotate.
A private key is the one case where the old regex had no chance at all.

The two pygoat tokens are the case that justifies not stripping comments. The same token is
commented out in `a7.js` and live in `a9.js`. Every other tier 1 rule reads the comment-blanked
text, because a commented-out route is not a route; a commented-out credential is still in the
history.

### This repository: nine findings, all informational, and `.gitleaksignore` silent

The detector over every tracked file `.mitig8it.yml` does not exclude (308 files excluded, the
measurement corpus and the recorded fixtures) produces **nine findings, all of them
informational**, and all nine are in test files this branch itself adds: the format table test,
the prose-scope test, and the two rotation-copy tests in the App and the Action. Every one is a
generated fixture or a bare PEM armour marker, which is the irreducible case this design accepts:
a test for a secrets detector has to contain things that look like secrets.

**All nine `.gitleaksignore` entries are silent.** That file is the hardest of the three corpora
and the only one written by somebody who was not thinking about this detector: gitleaks caught nine
lines in our fixtures and a human cleared each one. Three rules are what make them silent, and each
was added because one of them fired.

* **`random_core`**, the entropy measurement reading the longest separator-free segment, not the
  whole string. `sk-live-7f3a91bc44de2210` is 24 characters of which 16 are random; scoring the
  whole string counted `sk` and `live` as entropy, which is what made a hand-typed fixture look
  like a key.
* **The eight-character sequential run**, down from ten, because `1234567890abcdef` ascends nine
  characters and then wraps to zero. A real key contains eight ascending characters with a
  probability around one in ten to the thirteenth per position, so the shorter run costs nothing.
* **The connection-string host check**, because a loopback address, a documentation domain and a bare
  compose alias with no dot in it all reach nothing outside the developer's machine, and
  `devpass123` and `pass123456` joined the placeholder-password vocabulary. Four of the five
  connection strings the detector found in our own tree were that shape, in `.env.example`, in two
  service `.env.example` files and in the environment documentation; a `.env.example` and its
  siblings are now skipped outright.

### Two detector defects the reading found, and fixed

Reading the false positives is the point of reading them, and two of the thirty-four that were
read were the detector's fault rather than the corpus's. Both are fixed in this change, both have
a benchmark case, and both were read before they were fixed.

* **The jwt.io example token**, in juice-shop's `frontend/src/app/app.guard.spec.ts:46`. It is the
  token on jwt.io's front page, signed with `your-256-bit-secret`, which is printed next to it
  there. It passes `_verify_jwt` in full (three segments, a header naming HS256, a JSON payload, a
  real signature), so structural verification cannot refuse it and only the published-example list
  can. It is now in `PUBLISHED_EXAMPLE_BODIES`, and the one fixture in our own test suite that was
  signed with it has been regenerated, because a fixture asserting the opposite of the detector is
  worse than no fixture.
* **The unsigned JWT**, in juice-shop's `test/server/verify.unit.test.ts:283` and `:291`. An
  `alg:none` token with an empty signature, in the fixtures for the unsigned-token challenge.
  `_verify_jwt` refuses it, correctly, and then the entropy signal reported the very same value
  under its own rule id, at 5.4 bits under the identifier `authorization`, and told the author to
  rotate a token anyone can mint. The new `unsigned_jwt` exclusion is the rule that the weaker
  signal does not re-claim what the stronger one examined and rejected.

The other thirty-one false positives are the corpus being a corpus: seeded demo passwords, TOTP
seeds for accounts the application ships, tokens minted by a test to feed the code under test, and
our own fixtures. Nothing was tuned to hide any of them, and each one has a verdict in
`benchmarks/vulnerable-corpus/adjudications.json` with a sentence saying why.

## The posting decision

The policy, unchanged from the tier 1 and tier 2 work: **post at or above 0.8 precision over at
least three adjudicated findings, or as a format match whose structure is self-validating;
quarantine the rest with their evidence.** Both signals post, and they get there by different
routes.

**`secret.format.known_key` posts on both clauses.** Its measured precision over posted findings
is 1.00 over three, which clears the floor exactly; and it is the self-validating clause's central
case, which is why it does not have to lean on a count of three. Every one of the seventeen formats
verifies the structure its own vendor published before it reports: the exact length and charset, a
base64url-decodable JSON header naming a real `alg` for a JWT, a URL parse yielding a real password
at a reachable host for a connection string, a private-key armour marker rather than a public one
for a PEM block. That is the same argument the policy already accepts for a sink-only pattern: the
match is not evidence that something *might* be wrong, it is a decoding of the value that only
succeeds for the thing being looked for.

**`secret.entropy.credential_assignment` posts on the measurement alone**, at 1.00 over five
posted findings, and it is the signal that could have gone the other way. It has no structure to
verify, since the whole point of it is the formats nobody has written down, so the number is all it
has. Five findings is above the floor and is not a lot, and the honest statement of its position
is: it has never yet been wrong about a line a reviewer would read, over two deliberately
vulnerable applications and 165 ordinary pull requests, and the next corpus could change that. If
it does, `POSTING[RULE_ID_ENTROPY]` in `secret_detection.py` is one word, `partition_by_posting_policy`
removes its findings before the response is built, and the benchmark keeps measuring it while it
is quarantined.

**Nothing was quarantined and nothing was tuned to avoid quarantining it.** The two changes the
reading produced, the jwt.io token and the unsigned JWT, both refuse a specific value for a
stated reason, both have a case in `benchmarks/secrets-precision/cases.json` naming the exclusion,
and neither moves a threshold. No finding was silenced without being read: forty-two were produced
and forty-two were read.

What is worth saying plainly is what the `posted` column rests on. It rests on
`is_test_code_path` being right about which files are test files, because that is what separates
the eight true positives from the thirty-one false ones. That function is the product's existing
path model and it is used by every rule, not written for this one; if it were wrong about a
directory, this detector would post fixture keys there. It is the single assumption behind both
precision figures and it is worth naming rather than burying.

## What the legacy regex does now

`secret.hardcoded.credential` is still in `security_rules.py` and still runs. What changed is that
it now defers: `pattern_findings` skips it on any file the detector has already reported, because
two findings on one leaked key is one review conversation too many and `cluster_findings` cannot
merge them (it keys `hardcoded_secret` on the exact snippet, and the two rules quote different
spans of the same line).

The measurement says what the deferral is worth, and also what the regex is still doing. Over the
three corpora it fired **15 times**, and the detector reported none of those lines, so the deferral
never triggered: the two rules are looking at different things. Those 15 lines are, in full:

| Repository | Line, in substance |
| --- | --- |
| sindresorhus/got ×2 | `password: 'old-password'` in two test files |
| adeyosemanputra/pygoat | `app.secret_key = 'your-secret-key-here'` |
| adeyosemanputra/pygoat | a Django `SECRET_KEY` whose value says `insecure-key-for-demonstration-only` |
| adeyosemanputra/pygoat | a commented-out `adminPassword` in an HTML template |
| electerm/electerm ×2 | `const PASSWORD = 'electerm-test'` in two spec files |
| juice-shop/juice-shop | `public testingPassword = 'IamUsedForTesting'` |
| juice-shop/juice-shop | `component.privateKey = 'test-private-key'` |
| juice-shop/juice-shop | a base64 demo password in an oauth spec assertion |
| juice-shop/juice-shop | a hex `privateKey` in an API test payload |
| juice-shop/juice-shop | `password: 'K1f.....................'` |
| juice-shop/juice-shop ×2 | Cypress login passwords for seeded accounts |
| snyk-labs/nodejs-goof | `password: 'SuperSecretPassword'` in a seed script |

Not one of those is a credential. `your-secret-key-here`, `insecure-key-for-demonstration-only`,
`test-private-key`, `IamUsedForTesting`, `SuperSecretPassword` and a row of dots are what "twelve or
more characters of anything" catches, and the entropy signal refuses every one of them on the value:
they are placeholders, or English, or below the length and entropy floors. The regex was not
narrowed and was not quarantined here, because that is a separate decision with its own evidence
requirement; this document is the evidence that it is the thing being superseded rather than
complemented.

## What is not verified, and why it is not

**GitHub's token checksum.** The classic `gh[pousr]_` format carries a CRC32 over its
thirty-character random part, encoded base62 in the last six characters, and verifying it would
be the strongest single check in the whole format table. It is not verified.

The algorithm could not be confirmed on this machine. The only publicly published example
token, from GitHub's own announcement of the format, validates under none of the four plausible
base62 alphabet orderings against any of the four plausible checksum subjects, which is what
you would expect of an illustration rather than a token. The obvious way to get ground truth,
computing the checksum of the real `gho_` token the local `gh` install holds and printing only
whether it matched, was refused by this environment's credential guard, and that refusal was not
worked around.

Verifying a checksum against an unconfirmed algorithm is worse than not verifying it: a wrong
alphabet ordering rejects every real token and the detector's recall on GitHub tokens silently
goes to zero, with a test suite that passes because its fixtures were generated by the same
wrong function. So GitHub tokens are verified by prefix, exact length, charset and an entropy
floor on the random part, and this paragraph is the record of the gap. Closing it needs one real
token, or GitHub's published algorithm, and is a five-line change to `_verify_random_body`'s
neighbour.

**Other formats with no checksum to verify.** Stripe, Google, Slack, SendGrid, OpenAI and
Anthropic keys carry no checksum that is documented. For those, fixed prefix and exact length
*is* the structure, and the published-example and hand-typed-fixture refusals are what stop a
prefix match being a substring search.

## The benchmark

`benchmarks/secrets-precision/cases.json`, run by
`services/analysis-service/src/tests/test_secrets_precision_benchmark.py` in the same suite and
the same CI job as the tier 1 and tier 2 precision gates.

68 cases, 26 true positives and 42 no-finding lines. It holds one true-positive fixture per key
format, so adding a format forces adding its case and a narrowed format cannot stop matching in
silence; a true-positive case for each of the four **shapes** the corpus true positives were found
in, with a generated value and the repository and path in its evidence line; every adjudicated
false positive as a no-finding case naming the exclusion that refuses it; and all nine
`.gitleaksignore` entries, one case per entry, matched against the file itself so that adding a
line to `.gitleaksignore` without adding its case fails the gate. The gate also asserts that every
true positive **reaches a reviewer**, because a finding the posting policy withholds is not a true
positive yet, and that every finding says the credential must be rotated.

**The case file holds no key.** A true-positive fixture for a key format is, by construction,
exactly the shape of a live credential, and the first version of this file stored 26 of them as
literals. GitHub's push protection refused the branch over three, and it was right to: the only
way to keep the literals was an allowlist entry per case, renewed by hand every time a case was
added, in the repository whose own product exists to stop people committing keys. So a case now
names a format and a seed, and `benchmarks/secrets-precision/synthesize.py` builds a value that
satisfies the format's structure, including the content a format checks rather than only its
length: OpenAI's `T3BlbkFJ` marker, a JWT's base64url-JSON header and payload, a PEM armour
marker, a URL that has to parse. This is a stronger test than a literal was, and the gate asserts
why: a generated fixture has to match its format's real pattern and pass its real verification, so
a format narrowed away from its own declared shape now fails at the builder instead of going
quiet, which is the exact failure mode this benchmark exists to catch. Four cases keep an exact
published literal, because the detector refuses Stripe's quickstart key, AWS's two documentation
values and the token on jwt.io's front page *by identity* and no generated value can stand in for
them; each is stored split into parts that match no pattern alone and says so. The gate reads the
case file with the detector itself and fails if anything in it is a key.

## How to re-run this

```sh
PY=~/.pyenv/versions/3.11.6/bin/python   # with services/analysis-service/src/requirements.txt

# the eleven clean repositories, 15 merged pull requests each
for r in encode/django-rest-framework expressjs/express fastify/fastify pallets/flask \
         prettier/prettier psf/requests python/cpython sequelize/sequelize \
         sindresorhus/got tiangolo/fastapi vercel/next.js; do
  $PY scripts/replay/replay.py --repo "$r" --prs 15 --no-remediation --out "results-clean/${r//\//-}.json"
done

# the 23 pinned trees of the vulnerable corpus
$PY scripts/replay/replay.py --snapshot --include-quarantined --no-remediation \
    --repo <repo> --ref <sha> --out "results-corpus/<slug>.json"

# the gate
cd services/analysis-service/src && $PY -m pytest tests/test_secrets_precision_benchmark.py -q
```

The verdicts are in `benchmarks/vulnerable-corpus/adjudications.json` under
`sample.secrets_pass_2026_09_27`, keyed by fingerprint, each with the repository, the path, the
line and a sentence. The GitHub responses and the corpus tarballs cache under
`scripts/replay/.cache`, so a re-run after a detector change costs no API calls and compares like
for like.
