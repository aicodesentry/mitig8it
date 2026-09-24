# Real-repository replay, September 2026

165 merged pull requests from 11 public repositories, replayed through the analysis and
remediation pipeline exactly as production would send them, to find out how the pipeline
behaves on code it has never seen before a customer does.

The harness is `scripts/replay/` (see its README for how to run it and what it records).
Two full passes were run over the same cached GitHub responses: a baseline at commit
`c8e85b5e` (the harness, no service fixes) and a second pass at `c963e9d3` (all four
fixes). Because the GitHub responses are cached, the two passes saw byte-identical input.

## What did not run

* **Tier 3 never ran.** There is no model key on this machine, so the replay sets the
  service's own `LLM_TRIAGE_ENABLED=false`. Every finding count below is pre-triage; tier 3
  would filter some of them and adjust severities on others.
* **The remediation model path never ran.** The engine's template path ran for real,
  against the real verifier and the local sandbox driver. The provider is a stub that
  refuses every call, so a repair that would have needed the model is counted under
  `agent_needed` rather than attempted.
* **Verification is `development_unverified`.** `allow_development_verification` is on and
  no sandbox image digest is set, which is the same level every result in
  `docs/architecture/agentic-remediation-progress.md` carries. This measures pipeline
  integrity, not repair quality.

## Summary

Findings, limitations and durations are from the second pass; the exceptions column shows
both. Reproduce with:

```sh
scripts/replay/summarize.py results-after/*.json --baseline results-before/*.json
```

| Repo | PRs | Files | Findings (T1/T2) | Limitations | Exceptions (before/after) | Supported family | Candidates | Verified | Agent needed | p50 ms | p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| encode/django-rest-framework | 15 | 28 | 3 (3/0) | 2 | 0 / 0 | 0 | 0 | 0 | 0 | 290 | 2385 |
| expressjs/express | 15 | 26 | 4 (4/0) | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 271 | 1997 |
| fastify/fastify | 15 | 27 | 2 (2/0) | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 1956 | 2775 |
| pallets/flask | 15 | 57 | 7 (7/0) | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 2169 | 2741 |
| prettier/prettier | 15 | 60 | 1 (1/0) | 2 | 0 / 0 | 0 | 0 | 0 | 0 | 1946 | 2032 |
| psf/requests | 15 | 22 | 0 (0/0) | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 284 | 308 |
| python/cpython | 15 | 49 | 2 (2/0) | 4 | 0 / 0 | 0 | 0 | 0 | 0 | 1951 | 2197 |
| sequelize/sequelize | 15 | 76 | 24 (24/0) | 10 | 1 / 0 | 0 | 0 | 0 | 0 | 2142 | 2604 |
| sindresorhus/got | 15 | 94 | 44 (44/0) | 2 | 0 / 0 | 0 | 0 | 0 | 0 | 2161 | 2576 |
| tiangolo/fastapi | 15 | 275 | 0 (0/0) | 2 | 0 / 0 | 0 | 0 | 0 | 0 | 337 | 397 |
| vercel/next.js | 15 | 102 | 47 (47/0) | 6 | 0 / 0 | 0 | 0 | 0 | 0 | 2057 | 2175 |
| **total** | 165 | 816 | 134 (134/0) | 28 | 1 / 0 | 0 | 0 | 0 | 0 | | |

Total input: 9.46 MB of patch and head content across 816 changed files. The largest single
pull request was sequelize/sequelize#18432 at 931 kB.

Findings fell from 142 to 134 between the passes; the eight that disappeared were all
raised on documentation and changelog files (fix 4 below). No finding was lost from a
source file.

Durations are wall clock for the whole worker process, which pays one interpreter start and
one scanner start per pull request. Tier 1 itself has a p50 of 3 ms and a maximum of 568 ms
over this corpus; the seconds in the table are almost entirely the scanner subprocess.

### Findings by rule (second pass)

| Rule | Count |
| --- | ---: |
| `null.pointer.deref` | 85 |
| `authz.missing_function_level` | 19 |
| `integer.overflow` | 14 |
| `concurrency.shared_state` | 6 |
| `ssrf.untrusted_url_fetch` | 4 |
| `rate_limit.missing` | 2 |
| `secret.hardcoded.credential` | 2 |
| `config.tls_disabled` | 2 |

By severity: 14 `high`, 31 `medium`, 89 `info`. The `info` findings are all in test code, which
the test-code classifier downgrades without dropping. So 45 findings over 165 pull requests
would have been posted as blocking review comments, all of them from tier 1 heuristics, and
the sample read below says almost none of them are real.

### Limitations

| Limitation | Count | What it means |
| --- | ---: | --- |
| `files_filtered_out` | 16 | The github-service's `dist/` and `node_modules` filters, or a non added/modified/renamed status, dropped a changed file before analysis. Expected. |
| `file_without_patch` | 8 | GitHub returned no patch for a changed file: a binary blob, or a diff too large for the API. Tier 1 has nothing to match on, and tier 2 has nothing unless head content was fetched. |
| `content_skipped:content_over_500kb` | 4 | The head blob exceeded the 500 kB cap in `fetchFileContents`, so tier 2 fell back to the patch reconstruction. This is the path fix 2 below repairs. |

No pull request hit the 200-file cap, the 300-file analysis cap, or the 300-second per-PR
wall clock. No timeouts and no worker crashes occurred in either pass.

### Tier 2 found nothing

Zero tier 2 findings over 816 files is the most striking number here and it is not a
harness artifact: `scripts/replay/selftest.py` puts an obvious SQL injection through the
same worker and gets a finding, a template candidate and a passing sandbox check. The
custom taint rules in `src/opengrep_rules` simply do not match anything in 165 merged pull
requests of mature libraries. That is consistent with the analyzer-coverage gap already
recorded in `docs/architecture/agentic-remediation-progress.md`: coverage of the detection
tiers is unmeasured, and this replay measures only that it is low on ordinary code, not
whether it misses real vulnerabilities.

### Remediation reached nothing

No finding in the corpus mapped to a repairable family and language. The two
`secret.hardcoded.credential` findings are the closest: `hardcoded_credential` is a Python
family only (`families.py:34`), and both were in TypeScript test files. So candidates,
verified and `agent_needed` are all zero, and the `agent_needed` counter was never
exercised against real input. The engine path itself is exercised by `selftest.py`, which
produces one candidate and one passing `development_unverified` sandbox check.

## Bugs found and fixed

Every fix ships with a test that reproduces the input shape and fails against the pre-fix
code. Line numbers are in the pre-fix tree at `c8e85b5e`.

### 1. Tier 2 failed closed when the scanner could not parse one file

`services/analysis-service/src/opengrep_runner.py:523` treated any entry in the scanner's
`errors` array as an incomplete analysis and raised, which `main.py:394` turns into
`Required OpenGrep analysis failed` and the orchestrator turns into a failed run.

The scanner reports a syntax error at **warning** level against the one file it happened
on, finishes the batch, and covers every other target in its results. So one file the
parser dislikes silenced the security analysis of every other file in the pull request.

Found on sequelize/sequelize#18432: `packages/core/src/associations/helpers.ts:293` is
`let as: string;`, valid TypeScript that semgrep 1.165.0's parser rejects (`` `:` was
unexpected ``). That one line cost the other 33 changed files their analysis. After the
fix, the same pull request scans and reports the file as a coverage gap.

Fix commit `a878d36e`. Test: `tests/test_opengrep_unparseable_files.py`. A configuration
or engine error, or any error without a target inside the scan directory, still fails
closed.

### 2. A patch-only file was scanned at the wrong line numbers, and Python not at all

`services/analysis-service/src/opengrep_runner.py:70` rebuilt the new side of a file from
its diff by concatenating the hunks and keeping the diff's leading marker on context lines.

Two consequences. A finding at line 501 of the file was reported at line 3 of the
reconstruction, so the inline review comment would land on an unrelated line. And every
context line sat one column right of the added lines around it, which makes a Python file
unparseable on its own; combined with bug 1, a patch-only Python file failed the whole
tier. The reconstruction also treated ``\ No newline at end of file`` as a line of the file.

This is the path taken by a file over the 500 kB content cap (4 in this corpus) and by any
`.min.js`, because `shouldFetchFullFileContent` never fetches content for either.

Fix commit `2a5c6b46`. Test: `tests/test_patch_reconstruction_line_numbers.py`, which
asserts the scanner reports line 501 for a hunk at line 501.

### 3. `/analyze/pr` and `/analyze/pr/tier2` disagreed on the same pull request

`services/analysis-service/src/main.py:330` forwarded only `{path, patch}` to the scanner,
while the tier 2 endpoint at `main.py:383` forwarded `content` and `reviewable_line_spans`
too. The combined endpoint therefore analyzed a reconstruction of the diff where the split
endpoint analyzed the real file, and reported different findings and different line
numbers for the same input. The orchestrator uses the split endpoints, so this did not
affect pull request reviews, but it is what the playground route and any single-call
caller gets.

Fix commit `183068b0`. Test: `tests/test_combined_endpoint_payload.py`, which asserts the
two endpoints build the same scanner payload.

### 4. Tier 1 code-shape rules fired on prose

`is_analyzable_path` (`test_code_scope.py:47`) admits every path except the scanner's own
rule assets, so the tier 1 rule loop at `main.py:287` ran all 35 regexes over changelogs,
READMEs, docs and translation catalogues.

On expressjs/express#7466 that produced two **high** severity access-control findings
against `History.md:3036`, because a 2010 changelog entry quotes the example
``app.get('/user/:id').remove();``. A changelog entry is not a route. Eight of the 142
baseline findings came from prose files.

Code-shape rules now skip prose paths. A rule that looks for committed data rather than a
code shape opts in with `scans_prose` and keeps scanning them, which is why a secret pasted
into a README is still reported. No rule pattern changed, and an unrecognized extension is
not treated as prose, so nothing a rule used to find in source is hidden.

Fix commit `c963e9d3`. Test: `tests/test_prose_path_scope.py`.

## Not fixed, and why

| Item | Evidence | Why not fixed |
| --- | --- | --- |
| `null.pointer.deref` is a method-chain detector | `security_rules.py:611`. 85 of 134 findings (63%). See observation 1. | Rule semantics. Changing the pattern changes what the product detects and is a rule decision, not a robustness fix. |
| Four rules carry a negative lookahead after `.*`, which excludes nothing | `security_rules.py:594`, `:611`, `:305`, `:627`. See observation 2. | Same. The repository has fixed this exact shape once before, in `auth.bypass.missing_check` (`security_rules.py:39-42`), so the correction is known; it belongs in a rule-quality change with its own before/after measurement, not in a robustness pass. |
| `integer.overflow` matches `int(` without a word boundary | `security_rules.py:602`. Matched `UniqueConstraint(` and `fingerprint(`. | Same. It is a one-character change but it removes findings, and the brief for this pass forbids narrowing rules. |
| Tier 1 has no notion of a comment | 6 of the 30 read findings were on a comment or a docstring example, two at `high`. | Needs a per-language comment model; tier 1 is deliberately a line regex pass. Tier 2 already ignores comments because it parses. |
| Tier 1 can exceed the orchestrator's 30-second budget on a large pull request | Measured: 200 files of 75 kB each (15 MB, inside the 200-file and 200 kB-per-file caps) takes **50 s** in tier 1. Cost is spread evenly over the 35 rules at about 2.5 ms per rule per 75 kB, not one pathological regex. The worst legal payload, 300 files at 200 kB, is about 200 s against a 30 s budget in `prAnalysisOrchestrator.js:1021`. | Every option changes behaviour that needs a decision: raise the tier 1 timeout, add an aggregate byte budget that reports skipped files as a limitation, or move the rule loop to processes (Python's `re` holds the GIL, so threads do not help). No pull request in this corpus came close: the largest was 931 kB and the slowest tier 1 was 568 ms. |
| A patch-only Go fragment is wrapped in a 6-line preamble, shifting its line numbers | `opengrep_runner.py:129` | Fix 2 gives every other language the file's real line numbers; the Go wrapper still offsets them. Correcting it means rethinking how unparseable fragments are scanned, which is larger than this pass. Recorded here so the offset is not mistaken for correct. |
| Coverage gaps are logged but not returned | `run_opengrep` takes an optional out-parameter; `analyze_tier2_payload` does not pass one. | The tier 2 response shape is a proto message shared by four services (`proto/common.proto`). Adding a field is a cross-service change; the gap is printed for now and the replay harness reads it directly. |
| `tests/test_python_harness.py::test_python_load_check_records_missing_dependencies_and_environment_reads_as_limitations` fails on this machine | The test asserts `No module named 'flask'`, but Flask 3.1.0 is installed in this interpreter. | Pre-existing and environment-dependent; unrelated to anything in this pass. It fails identically on the branch base. |

## False positives: 30 findings read by hand

The sample is every fifth finding of the 142 in the baseline pass, in repository then pull
request order, plus the last one. Of the 30, **29 are false positives**. The one that is
not is a `password: 'old-password'` literal in a got test fixture: a correct pattern match
on a value that is not a secret, already non-blocking because the test-code classifier
downgrades it to `info`.

### Observation 1: `null.pointer.deref` detects method chaining, not null dereference

It is 85 of 134 findings, and every one of the 19 in the sample is wrong. Its pattern
(`security_rules.py:611`) is `\.\w+\s*\(.*\)\s*\.\w+\s*` plus an exclusion: any `a.b().c`.
That is ordinary code in every language the pipeline scans.

* `connection.removeAllListeners('error').on('error', …)` (sequelize, `packages/oracle/src/connection-manager.ts:150`). Both Node methods return `this` by contract; the chain cannot be null.
* `await expect(next.start()).rejects.toThrow()` (next.js). This one Jest idiom accounts for **27 of the 142** baseline findings, five of them in the sample, spread over three pull requests (#98847, #98848, #98849) that each touched many test files. One assertion style in one monorepo produced a fifth of the corpus.
* `chunking_context.unused_references().await?` (next.js, `turbopack/crates/turbopack-ecmascript/src/references/esm/export.rs:682`). This is Rust. The rule's own remediation text tells the author to "use optional chaining (`?.`)", which Rust does not have.
* `encoding.toLowerCase().replace('-', '')` (got, `source/core/index.ts:74`) is guarded on the same line by `encoding === undefined ||`. The rule's exclusion list contains `!=\s*null`, so it was meant to catch exactly this, and did not.

That last case is not just a weak heuristic: the exclusion is defeated by backtracking. The
lookahead sits after `\.\w+\s*`, and `\w+` can give back characters until the lookahead
finds a position where none of the excluded tokens follow. The rule cannot suppress itself.

### Observation 2: four rules share one broken exclusion shape, and degrade to substring search

`integer.overflow`, `authz.missing_function_level`, `rate_limit.missing` and
`concurrency.shared_state` all end with `.*(?!alternatives)`. A negative lookahead placed
after a greedy `.*` can always be satisfied, because `.*` can consume to end of line and
the lookahead then looks at nothing. Each of these rules is therefore just its leading
alternation.

The repository already knows this. `auth.bypass.missing_check` carries a comment at
`security_rules.py:39-42` saying that a lookahead after a greedy `.*` "excluded nothing and
the rule fired on guarded routes", and that rule was re-anchored. The four siblings were
not.

What is left is a substring search, and the substrings are not anchored either:

* `integer.overflow` reduces to "the line contains `parseInt`, `Number(`, `int(`, …". `int(` has no word boundary, so it matched `models.UniqueConstraint(` in django-rest-framework docs and `function fingerprint(snapshot: Snapshot): string {` in a next.js CI script.
* `rate_limit.missing` reduces to "the line contains `/login`, `/auth`, …". It matched `location: '/login'` in a got redirect test, ` *    res.location('../login');` in an express JSDoc example, and, in next.js#99122, the string `@octokit/auth-token` in a vendored `licenses.txt`. Those three were the whole of the rule's output over 165 pull requests.
* `authz.missing_function_level` reduces to "the line contains `.destroy(` or `.remove(`". It produced 19 findings, **13 of them at severity `high`** and the rest downgraded only because they are in test code. All are stream, socket and connection-pool teardown: `result.destroy()`, `session.destroy()`, `void this.sequelize.pool.destroy(connection)`.
* `concurrency.shared_state` reduces to `global\s+\w+`, which matches English. It fired on the comment `// If agent.http2 is unset, use the global agent for connection pooling.` and on the changelog line `Fix a global leak when multiple subnets are trusted`.

### Observation 3: tier 1 reads comments and non-code files as code

Tier 1 is a line-oriented regex pass with no notion of a comment, a docstring or a file
that is not source. Six of the 30 sampled findings are on text that never executes, and two
of those carry severity `high`:

* `packages/core/src/abstract-dialect/connection-manager.ts:74`, severity `high`: the matched line is a JSDoc line, `* Calling \`pool.destroy()\` on the connection from here does not throw, but it does not`. The finding is raised on documentation explaining why the call is there.
* `lib/response.js:787` in express, `rate_limit.missing`: the matched line is ` *    res.location('../login');`, a usage example in a JSDoc block.
* `packages/mariadb/src/connection-manager.ts:30`: `// Replaced by Sequelize's global option`.
* `History.md:3036` in express, two findings at `high` from a 2010 changelog entry.
* `.github/actions/pr-stack-ci-gate/dist/licenses.txt:96`: the package name `@octokit/auth-token` in a vendored licence file. The github-service's `dist/` filter does not catch this one, because the prefix check is anchored at the start of the path and this `dist/` is nested.

Fix 4 removes the four prose cases here, and eight across the corpus: the changelog, the
docs pages and the licence text. The comment cases remain, and they are the more
interesting half: tier 2 does not have this problem because it parses, so the gap is
specific to the regex tier. A per-language comment stripper would be the cheapest
improvement available to tier 1.

## Suites after the fixes

| Suite | Command | Result |
| --- | --- | --- |
| analysis-service | `python -m pytest tests -q` in `services/analysis-service/src` | 417 passed |
| remediation-service | `python -m pytest tests -q` in `services/remediation-service` | 293 passed, 1 failed (`test_python_harness.py`, pre-existing, fails because Flask is installed in this interpreter) |
| replay self-test | `scripts/replay/selftest.py` | ok: findings=1 candidates=1 verified=1 agent_needed=0 |
