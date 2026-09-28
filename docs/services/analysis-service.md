# Analysis Service

FastAPI service that analyzes changed pull request files.

## Responsibilities

- Accept changed-file PR payloads from the API service.
- Filter scanner rule fixtures. Test code is scanned, not filtered: `src/test_code_scope.py` recognizes `tests/`, `__tests__/`, `test_*`, `*.test.*`, and `*.spec.*`, marks those findings `in_test_code` in `evidence_details.extra`, preserves the scanner's `original_severity`, and reports them as `info` so they are visible without failing a check run.
- Run Tier 1 regex and dependency-risk checks.
- Run Tier 2 OpenGrep rules, in batches bounded by `OPENGREP_BATCH_MAX_FILES` and `OPENGREP_BATCH_MAX_BYTES`. A file larger than the byte budget gets its own batch, and a batch that fails outright raises, so the tier fails closed rather than returning partial results.
- Classify the scanner's own errors instead of failing on all of them. A warning-level parse problem in one file (`Lexical error`, `Syntax error`, `Partial parsing`) or a per-file resource ceiling (`Timeout`, `Out of memory`, `Too many matches`) keeps the findings from every other file and is reported as an entry in `analysis_limitations` naming the file, the kind of gap, and the line. Anything at error level that is not attributable to a file, such as an invalid rule or a config error, still fails the tier closed, now with the error types, paths, message prefixes, and the stderr tail in the raised message.
- Run optional Tier 3 LLM triage when configured. The Gemini default is `gemini-2.5-flash-lite` and the OpenAI default is `gpt-4o-mini`. Triage failure is non-blocking, and every log line and error body on those paths passes through `redact()` so a misconfigured provider call cannot print credentials.
- Build remediation patch metadata when possible. The repairs themselves are the remediation service's job, not this one's.
- Normalize, cluster, and return finding objects.
- Expose health and Prometheus metrics.

The blocking analysis routes are synchronous handlers, so FastAPI runs them in its threadpool and `/health` does not wait behind a scan. `POST /analyze/pr` runs tier 1 and tier 2 concurrently on a two-worker pool and merges by tier rather than by completion order, so fingerprints and clustering stay stable.

## Rule posting policy

A finding the product cannot stand behind must not be posted. Every tier 1 rule in `src/security_rules.py` therefore declares two things:

- `precision`, either `measured` or `unmeasured`. `measured` means someone read this rule's output on a real corpus and wrote down what they found, in `precision_evidence`. `unmeasured` means nobody has, which is the honest default.
- `posting`, either `post` or `quarantine`.

A **quarantined** rule still runs. Its matches are counted in `codesentry_analysis_quarantined_findings_total` and returned as `quarantined_findings` (a count per rule) on the tier 1 and combined responses, so the replay harness and the metrics can keep measuring it. What it does not do is arrive: `partition_by_posting_policy` in `src/main.py` is the single place a quarantined finding is removed, and it removes it before the response is built. Nothing downstream needs to know the policy exists. Nothing is posted to GitHub, nothing reaches the check summary, and nothing is handed to remediation, because the finding is not there.

The quarantine is not a deletion. A rule is re-enabled individually, with evidence, by:

1. fixing it, and showing the fix on the lines that were wrong. The false positives the September 2026 replay read by hand live in `benchmarks/tier1-precision/cases.json`;
2. adding its cases to that set, including the true positives it must keep finding;
3. running the gate, `src/tests/test_tier1_precision_benchmark.py`;
4. flipping `posting` to `post` and writing what was measured into `precision_evidence`.

Two structural rules back this up, both enforced by `src/tests/test_rule_posting_policy.py`:

- **A negative condition goes in `exclusion`, not in a lookahead.** `find_ineffective_lookaheads()` in `security_rules.py` is a static check over every regex tier 1 runs. It flags a negative lookahead that an unbounded greedy quantifier precedes with no required token in between, because the engine can always satisfy such a lookahead by letting the quantifier consume to the end of the line. A rule with that shape silently degrades to its leading alternation. `exclusion` is a second pass over the matched line, where backtracking cannot defeat it.
- **Tier 1 does not read comments.** `src/comment_stripper.py` blanks line comments, block comments, JSDoc, Ruby `=begin` blocks and Python docstrings for JavaScript, TypeScript, Go, Java, C#, PHP, Ruby and Python before any regex runs, keeping line numbers and column offsets so a finding still quotes the author's text. It never strips inside a string literal, and an unmodelled extension is not touched at all. A rule can also opt out of seeing string literal bodies with `reads_string_literals=False`; the credential rule keeps them, because a secret lives in a string.

## Secrets in the diff

A committed credential is the most consequential thing a pull request can carry, and until
this change the product looked for one with a single tier 1 regex: a credential-ish
identifier, a colon or an equals sign, and twelve or more characters of anything. No key
formats, no structural verification, no entropy, and it was one of the rules that had fired on
documentation prose. `src/secret_detection.py` replaces it.

**It reads the added lines only.** An existing secret is not this pull request's fault, and
re-reporting it on every change to the file is how a category gets muted. Only entries whose
`kind` is `add` are scanned, which is also why a context line carrying a key produces nothing.

**Two independent signals, and the finding says which one fired**, in
`evidence_details.extra.signal`. Each is its own rule id, so the posting policy, the metrics
and the precision tables all answer per signal.

### `secret.format.known_key`

Seventeen published key formats, and for each one the structure that format declares is
verified. That verification is the difference between a detector and a substring search, and it is
why this signal posts on the self-validating clause of the posting policy as well as on a number:
the same argument the policy already makes for a sink-only pattern. It also has the number,
**1.00 over three posted findings**, one of which was a complete RSA private key in a public
repository's production source.

| Format | What is verified |
| --- | --- |
| AWS access key id | one of the nine four-character key-type prefixes, exactly 20 base32 characters |
| AWS secret access key | exactly 40 base64 characters under an `aws_secret_access_key` identifier |
| GitHub token | a `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` prefix and exactly 36 base62 characters |
| GitHub fine-grained PAT | `github_pat_`, a 22-character id, an underscore, exactly 59 characters |
| Google API key | the `AIza` prefix and a fixed total length of 39 |
| Slack token | the `xox?-` prefix, the numeric team and installation segments, a 24-to-34 character tail |
| Slack incoming webhook | the host, a `T` team id, a `B` channel id, a 24-character secret tail |
| Stripe live and test keys | the `sk_live_`/`rk_live_`/`sk_test_`/`rk_test_` prefix and at least 24 base62 characters |
| Twilio API key | the `SK` prefix and exactly 32 lowercase hex characters |
| Twilio auth token | exactly 32 hex characters under a Twilio auth-token identifier |
| SendGrid API key | `SG.`, a 22-character key id, a dot, exactly 43 characters |
| OpenAI API key | a `sk-proj-`/`sk-svcacct-`/`sk-admin-` prefix, or the legacy 48-character form carrying the `T3BlbkFJ` marker |
| Anthropic API key | the `sk-ant-api`/`sk-ant-admin` prefix with its two-digit version and an 80-to-120 character body |
| Private key PEM | a `BEGIN … PRIVATE KEY` armour marker, which a public key and a certificate do not carry |
| JWT | three base64url segments, a header that decodes to JSON naming a real `alg`, a payload that decodes to JSON, a non-empty signature |
| Database connection string | a URL parse yielding a password that is neither empty, interpolated nor a placeholder, at a host that is not loopback and not a bare compose alias |
| `.env` file | a `.env` that is not a `.env.example`, carrying a credential-named variable whose value is neither a placeholder nor an interpolation |

Two things the verification refuses that a prefix match accepts. **A published example**: the
AWS documentation key id and secret, and the Stripe quickstart key that `security_rules.py`
quotes in its own comment, are in thousands of repositories and in this one. **A hand-typed
fixture**: a value whose random core runs eight or more characters straight through the
alphabet or the digits, which a real key does with a probability around one in ten to the
thirteenth per position.

GitHub's classic token format also carries a CRC32 checksum over its random part, encoded
base62. It is **not** verified, and the reason is recorded rather than papered over: the
algorithm could not be confirmed on this machine against a token with a known-valid checksum,
because the only publicly published example, from GitHub's own announcement, validates under
none of the four plausible base62 alphabet orderings, and it is an illustration rather than a
token. Verifying a checksum against an unconfirmed algorithm would silently reject every real
token, which is worse than the exact length and charset check that is there.

### `secret.entropy.credential_assignment`

A high-entropy value assigned to an identifier whose name says it is a credential. It is the
signal that catches the formats nobody has written down, and it is the signal that can be
wrong, so it carries a measured precision, **1.00 over five posted findings**, which is above
the policy's floor and is not a lot, and it is bounded on both sides.

The **name** is read as tokens, not as a substring, because a substring list gets this wrong in
both directions: `API_KEY` contains `key`, which has to be disqualifying on its own and must
not disqualify `api_key`, and `password_hash` contains `password` and is not a password. The
identifier is split on separators and camelCase boundaries, and then a disqualifying first
token (`public`), a credential bigram (`connection_string`), `key` with a qualifier in front of
it, a self-standing credential tail (`token`, `secret`, `password`, `dsn`), and a disqualifying
tail (`id`, `name`, `path`, `url`, `header`, `hash`, and thirty more) are asked in that order.

The **value** is measured on its `random_core`, the longest segment carrying no separator,
because a credential's randomness lives in one segment and the rest is structure the vendor put
there. `sk-live-7f3a91bc44de2210`, a fixture this repository's own `.gitleaksignore` records, is
24 characters of which 16 are random, and scoring the whole string counted `sk` and `live` as
entropy. Hex and base62 are scored on separate floors (32 characters at 3.2 bits, 20 at 4.0),
and a base62 core must mix at least two character classes. Twelve named exclusions then refuse
the shapes that are legitimately high entropy: a UUID, a subresource integrity hash, a digest
under a digest name, a path, an interpolation, an environment read, a repeated character, a
placeholder, a base64 asset, a published example, an unsigned JWT, and a value that echoes its
own identifier. The reason is returned rather than swallowed, so a test can name the shape it
protects.

`unsigned_jwt` is the one the September 2026 measurement added, and it is a rule about the two
signals rather than about entropy. A JWT with an empty signature is one anyone can mint, so
`_verify_jwt` refuses it for the format signal; without this exclusion the entropy signal
reported the same value under its own rule id, at 5.4 bits under the identifier `authorization`,
and told the author to rotate a token that was never a credential. The weaker signal does not get
to re-claim what the stronger one examined and rejected.

### Path and context

The path model is the one `src/test_code_scope.py` already owns, not a second one.

- `is_test_code_path` makes a secret in test code informational through `classify_finding`,
  which is how the product already treats test code. A realistic fake key in a fixture is the
  irreducible case, and `info` is the answer.
- `is_lockfile_path` and `is_non_code_text_path` turn the **entropy** signal off. A lockfile is
  nothing but high-entropy strings, and `docs/validation/*.md` has already drawn a critical
  finding for a sentence about someone else's fixture.
- The **format** signal stays on everywhere, for the reason `SecurityRule.scans_prose` already
  gives: a key that passes its own structural verification is a leak in a README and in a JSON
  config as much as in a module.
- `.mitig8it.yml` keeps `benchmarks/**`, `docs/validation/**` and `action/tests/fixtures/**` out
  of our own pull requests, unchanged.
- Comments are **not** stripped before matching. Every other tier 1 rule reads the
  comment-blanked text because its signal is the shape of executable code; a commented-out
  credential is still a committed credential.

At most five findings per file per signal, and a `.env` is one finding rather than one per
variable: a file full of secrets is one review conversation.

### The fix, and the sentence that matters more than a patch

`families.rule_family` in the remediation service derives the repair family from the finding's
CWE, so a CWE-798 finding is already routed into `hardcoded_credential`. What the detector
decides is whether the finding **promises** a fix, and it decides it by mirroring the shapes the
family's templates actually recognize: the two JavaScript shapes in
`remediation-service/src/sites.py` (`_JS_CONSTANT_RE`, `_JS_PROPERTY_RE`) and its module-level
Python assignment. `is_rewritable_credential_shape` is that mirror; if either matcher changes,
change it in the same commit, the way `scripts/replay/prodfilters.py` mirrors the orchestrator.

A rewritable shape gets the existing template's `process.env.NAME` / `os.getenv("NAME")` patch
and this message:

> Rotate this credential now, then replace the literal with a read from the environment or a
> secret manager. Rotating matters as much as removing: the value is in the commit history, so
> deleting the line does not un-leak it.

A key inside a JSON config, a PEM block, a Slack webhook URL and a `.env` file cannot be
rewritten mechanically, so no fix is offered and the message says so:

> Rotate this credential now, then remove it from the repository. Rotating matters as much as
> removing: the value is in the commit history, so deleting the line does not un-leak it. No
> automatic fix is offered for this shape, because the literal is not bound to a constant a
> template can rewrite.

Both are the finding's `remediation`, which is the field the api-service publishes in the pull
request comment and the field the Action renders in its annotation, so the App and the Action
read the same sentence by construction rather than by two copies being kept in step.
`services/api-service/tests/secretRotationCopy.test.js` and
`action/tests/test_secret_rotation_copy.py` assert that neither renderer drops it.

The evidence line quotes a shape, never a whole credential: `sk_l…******… (32 characters)` and
the structure that was verified. `code_snippet` keeps the author's line, because that is what
the suggestion the App publishes has to match and what every other rule does.

### Measurement and the benchmark

Both signals were measured over three corpora (165 merged pull requests from eleven clean
repositories, the 23 pinned trees of the vulnerable corpus, and this repository's own tracked
files), and **every one of the 42 findings they produced was read by hand**. The full write-up,
including
the eight true positives with their values redacted and the two detector defects the reading found
and fixed, is [secrets-in-the-diff-2026-09.md](../validation/secrets-in-the-diff-2026-09.md).

| Signal | Adjudicated | Precision over all | Posted | Precision over posted |
| --- | --- | --- | --- | --- |
| `secret.format.known_key` | 19 | 0.16 | 3 | 1.00 |
| `secret.entropy.credential_assignment` | 20 | 0.25 | 5 | 1.00 |

The two columns differ because **no informational finding is posted inline** and all eight true
positives are outside test code while all thirty-one false positives are inside it. A repository
writes invented credentials in its tests and real ones in its configuration and its source, and
`is_test_code_path` is the one assumption both figures rest on.

`benchmarks/secrets-precision/cases.json` and
`src/tests/test_secrets_precision_benchmark.py` are the gate: one true-positive fixture per key
format, a true-positive case for each shape a corpus true positive was found in with a generated
value, every adjudicated false positive as a no-finding case with the exclusion that refuses it,
and all nine `.gitleaksignore` entries read out of that file itself, so the detector can never
regress onto our own fixtures.

## Tier 1 budget

Tier 1 runs every rule over every changed line, and on the largest payload the caps still allow (200 files of 75 kB) that measured 50 s against the orchestrator's 30 s budget. It is now bounded twice:

- `TIER1_BUDGET_SECONDS` (default 20) is the whole pass;
- `TIER1_FILE_BUDGET_SECONDS` (default 2) is one file.

Exceeding either stops that much of the work, keeps the findings already made, and appends a `{kind: "budget", path, message}` entry to `analysis_limitations` on the response. A partial tier 1 that says how partial it was is worth more than a blown deadline.

## Local Development

```bash
cd services/analysis-service
pip install -r src/requirements.txt
uvicorn src.main:app --reload --port 8001
```

For standalone runs, export the root `.env` first:

```bash
set -a
source .env
set +a
```

## Tests

```bash
cd services/analysis-service/src
pip install -r requirements-test.txt
pytest tests -q
```

## Main Endpoints

- `GET /`
- `GET /health`
- `GET /metrics`
- `POST /analyze/pr`
- `POST /analyze/pr/tier1`
- `POST /analyze/pr/tier2`
- `POST /analyze/pr/tier3`

Analysis requests and metrics require `x-internal-secret`. The expected value is `ANALYSIS_SERVICE_INTERNAL_SECRET` when set, otherwise `GITHUB_SERVICE_INTERNAL_SECRET`.

## Key Environment

- `GITHUB_SERVICE_INTERNAL_SECRET`
- `ANALYSIS_SERVICE_INTERNAL_SECRET`
- `LLM_PROVIDER`
- `LLM_MODEL` / `LLM_TRIAGE_MODEL`
- `LLM_API_KEY`
- `GEMINI_API_KEY` / `OPENAI_API_KEY` provider-specific local fallbacks
- `FRONTEND_URL`
- `ANALYSIS_CACHE_TTL_DAYS`
- `OPENGREP_BATCH_MAX_FILES` / `OPENGREP_BATCH_MAX_BYTES` batch bounds for tier 2
- `TIER1_BUDGET_SECONDS` total tier 1 wall clock, default 20
- `TIER1_FILE_BUDGET_SECONDS` per-file tier 1 wall clock, default 2
- `WORKFLOW_ACTION_DIGEST_LOOKUP` off unless set: allows one GitHub API request per distinct action
  reference, to resolve the commit digest the pinning repair needs
- `WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN` optional bearer token for that lookup

For the full env contract, see [environment.md](../getting-started/environment.md).

## Tier 2: the rule set and the posting policy

The AST rules live in `src/opengrep_rules/*.yml`. JavaScript, TypeScript and Python are covered
by 116 rules: 25 that predate the coverage work, and 91 in `javascript_coverage.yml` and
`python_coverage.yml`. Templates add 9 more in `template_coverage.yml`, and GitHub Actions
workflows add 9 in `workflow_coverage.yml`.

### Where the rules come from

Every rule is written in this repository. No rule is copied or adapted from a public rule
library, because the two obvious ones cannot be used in a paid service: `opengrep-rules` is
LGPL-2.1 **plus the Commons Clause**, which removes the right to sell a service whose value
derives substantially from the rules, and `semgrep-rules` is under the Semgrep Rules License
v1.0, which permits internal business use only and forbids making the rules available as a
service. The reading, with the licence text, is in
[third-party-rules.md](../legal/third-party-rules.md), along with the four steps to follow
before importing a rule from anywhere.

### What a rule must declare

`tests/test_tier2_rule_metadata.py` enforces this on every rule in the two coverage files:

- `cwe`, a `severity` the scanner understands, a `confidence`, and at least one language.
- `internal_type`, from `taxonomy.CANONICAL_INTERNAL_TYPES`. This is what the product groups,
  deduplicates and reports on, so a rule that passes its own check id makes a category of one
  that nothing else can join. Adding a value to that set is a deliberate product decision.
- `family`, when the finding is repairable, and only when the rule's CWE is the one the
  remediation service derives that family from. The engine reads the CWE, not this key, so a
  rule that declared a family its CWE does not produce would be handed to the engine as
  something else.
- `posting`, which is `post` or `quarantine`.
- `precision_evidence`, when someone has measured the rule on a corpus. It must name the
  corpus or the write-up, because a precision claim nobody can re-run is an opinion.

### The posting policy

A rule posts only on evidence. It may post when its labelled precision on a real corpus is at
least 0.8 over at least three labelled findings, or when it produced no findings on the corpus
**and** its pattern is a sink-only match with a clear taxonomy that makes no data-flow
assumption. Everything else is quarantined, and a quarantined rule must carry
`posting_evidence` saying what was measured, because that is what lets the next person
re-enable it.

A quarantined rule still runs and its findings are still counted, in the response's
`quarantined_findings` map and in `codesentry_analysis_quarantined_findings_total`. What it
does not do is reach a reviewer. The removal happens in exactly one place,
`main.partition_by_posting_policy`, which both tiers go through, so the api-service needs no
knowledge of the policy: the findings simply do not arrive, nothing is posted to GitHub,
nothing is counted in the check summary, and nothing is handed to remediation.

The policy is one policy, not a tier 2 one. Tier 1 declares the same states on the rule
object in `security_rules.py` (`precision`, `posting`, `precision_evidence`), and
`main.QUARANTINED_RULE_IDS` is the union of the two declarations, so a suppression, a metric
or a reviewer never has to ask which tier a rule came from.

Seven rules are quarantined today. Two are the workflow rules
`cwe-732.gha-write-permission-under-privileged-trigger`, whose measured precision is 0.00 over ten
hand-read findings, and `cwe-668.gha-self-hosted-runner-fork-trigger`, whose claim holds only if
the repository is public; both are in
[workflow-tampering-2026-09.md](../validation/workflow-tampering-2026-09.md). The other five: four
tier 2 rules, whose measurement is in
[tier2-coverage-2026-09.md](../validation/tier2-coverage-2026-09.md), and the tier 1 rule
`path.traversal.user_path`, whose measurement is in
[vulnerable-corpus-2026-09.md](../validation/vulnerable-corpus-2026-09.md). The same corpus
gave 18 posting tier 2 rules a `precision_evidence` line.

### Re-enabling a quarantined rule

1. Narrow the pattern so the shape it was wrong about no longer matches.
2. Add that exact line to `benchmarks/tier2-precision/cases.json` as a no-finding case, with
   the repository and pull request it came from, and keep the rule's true-positive fixture.
3. Re-run the replay, or the vulnerable-corpus snapshot with `--include-quarantined`, and
   adjudicate what it now produces.
4. Change `posting` to `post` and replace `posting_evidence` with the new measurement.

A rule can also earn its way back without a pattern change, by being measured on code that
contains its shape: `scripts/replay/replay.py --snapshot --include-quarantined` keeps a
quarantined rule's findings, and `scripts/replay/score.py` reports them separately from what
posts. Three adjudicated findings at 0.8 or better is the bar, and it is a real bar:
`cwe-489.py-debug-constant-true` has two, both confirming the quarantine reason was wrong,
and it still cannot come back.

### Workflow tampering, and how it is scoped

`workflow_coverage.yml` holds nine rules for GitHub Actions workflows: an untrusted checkout under
`pull_request_target` or `workflow_run`, a build or test step under `pull_request_target`, an
interpolation of attacker-controlled event data inside a `run:` script, a third-party action
referenced by tag or branch rather than a commit digest, `permissions: write-all`, a write scope
under a privileged trigger, `persist-credentials: true` on an untrusted checkout, a repository
secret handed to a job that has checked out untrusted code, and a self-hosted runner in a workflow
a fork can trigger. Seven post and two are quarantined; the measurement is in
[workflow-tampering-2026-09.md](../validation/workflow-tampering-2026-09.md).

This is the first category whose scope is a **path** rather than an extension, and the reason is
worth stating because it is the whole of the design.

`.yml` is the most common configuration extension there is. A repository's Kubernetes manifests,
its Helm values, its `docker-compose.yml`, another provider's CI config and its own `.mitig8it.yml`
are all YAML, and `run:`, `ref:` and `permissions:` mean something different in every one of them.
Admitting `.yml` to `SUPPORTED_EXTENSIONS` would have put nine rules over all of that, and would
also have made the product fetch the content of every YAML file in every pull request in order to
find the handful that are workflows.

So the gate is `is_tier2_scannable_path` in `src/test_code_scope.py`: a source extension, a
template extension, or `.yml`/`.yaml` under a `.github/workflows/` path segment. `WORKFLOW_EXTENSIONS`
is deliberately disjoint from `SUPPORTED_EXTENSIONS`, and `tests/test_supported_extension_parity.py`
asserts that it stays that way.

The scope is written down four times, because four runtimes need it and none can import the others:
here, in `prAnalysisOrchestrator.js`, in `scripts/replay/prodfilters.py`, and in
`action/orchestrator/pr_scope.py`. The parity test compares all four on the literals and on the
behaviour, over a workflow, ordinary YAML, and a directory that merely ends in `github/workflows`.
Two dependencies that used to be invisible are asserted there too: the github-service's
changed-file filter has no extension list, only a status filter and two path exclusions, and a
workflow survives all three; and `scripts/replay/corpus.py` used to skip every dotted directory,
which would have made a snapshot report zero workflow findings however many a tree contained.

The rules are then scoped a second time, independently. They are `generic` rules, and a `generic`
rule with no `paths: include` reads every file in the batch, so each one includes exactly
`.github/workflows/*.yml` and `.github/workflows/*.yaml`.
`tests/test_workflow_rules_are_path_scoped.py` asserts the includes and then runs the whole file
through the real scanner over a document that carries every shape, at a workflow path and at two
ordinary YAML paths, because a metadata assertion would not catch a scanner whose glob semantics
changed.

Most of the patterns are a single `pattern-regex`, which is unusual here and deliberate. What these
rules express is a relation between a trigger at the top of the document and a step forty lines
below it, and a YAML pattern cannot state "this key is in the same document as that key". Each
pattern names the trigger, skips forward, and uses PCRE's `\K` to move the reported match onto the
step, so the finding lands on the line a reviewer has to change rather than on the `on:` block.
`pattern-inside: "run: ..."` was tried and is recorded at the top of the rule file as the wrong
tool: in `generic` mode `...` has no notion of a YAML block, so it ran past a single-line
`- run: npm i` into the next step's `if:` line and produced ten false findings.

One finding carries a fact the repair side cannot get for itself. The pinning repair needs the
commit an action's tag currently resolves to, and the repair sandbox has no egress by design, so
`src/workflow_action_digest.py` resolves it here and puts it on the finding as
`evidence_details.extra.resolved_action_digest`. The lookup is off unless
`WORKFLOW_ACTION_DIGEST_LOOKUP` is set, because a scanner that quietly makes an outbound request
per finding is one nobody can reason about and the Action's contract is that nothing leaves the
runner. Every failure -- unreachable API, rate limit, deleted tag -- produces no digest rather than
a guess, and the repair service refuses that case by name.

### Rule ids are resolved, not taken as given

Pointed at a directory, the scanner names a rule after the path it loaded it from relative to
the working directory, so the same rule arrives as `opengrep_rules.<id>` from one caller and
`services.analysis-service.src.opengrep_rules.<id>` from another. `canonical_check_id` resolves
the id back to the one the rule file declares. Without it a rule id could not key the posting
policy, a suppression, or a fingerprint.
