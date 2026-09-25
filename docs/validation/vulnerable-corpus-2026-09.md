# Vulnerable corpus, September 2026

`docs/validation/tier2-coverage-2026-09.md` widened tier 2 to 116 rules and then said the
uncomfortable thing about the measurement behind them: 87 of those rules post because they
matched nothing on 165 clean pull requests, and *nothing* is what a good rule and a rule
that never matches both produce on code with no vulnerabilities in it.

This is the corpus that tells them apart. 171 labelled vulnerabilities in 23 repositories,
1819 findings, and a per-rule decision made from the numbers rather than from an argument
about the pattern.

## What changed

* **1 tier 1 rule quarantined.** `path.traversal.user_path`, precision 0.43 over 7
  adjudicated findings, with the pattern defect named.
* **18 tier 2 coverage rules gained a `precision_evidence` line**, each naming the findings
  it was measured on. Before this run not one tier 2 rule had a measured precision.
* **2 quarantined tier 2 rules were re-measured.** Both stay quarantined; one is a single
  measured hit short of the threshold to come back.
* **27 corpus true positives were added to `benchmarks/tier2-precision`**, so the rules that
  this corpus proved cannot stop matching silently.
* **1 remediation template case added**, for the credential shape the corpus found four
  times and the template refused four times.
* **A snapshot mode and a scorer were added to the replay harness**, so this measurement can
  be repeated against a fixed corpus rather than re-argued.

## The corpus

Two kinds of source, because they fail differently. Every licence was read in the downloaded
tree, not taken from the API field; `benchmarks/vulnerable-corpus/labels.json` records the
sentence that was checked for each. No source tree is committed:
`benchmarks/vulnerable-corpus/README.md` says how to refetch.

### Intentionally vulnerable applications

Their own documentation says where each vulnerability is, so the ground truth is written
down. They are also written to be found, so a rule that works only on them has proved little.

| Repository | Ref | Licence | Labels | Ground truth |
| --- | --- | --- | ---: | --- |
| `juice-shop/juice-shop` | `1618a611` | MIT | 43 | `data/static/challenges.yml` and the app's own `vuln-code-snippet vuln-line` markers |
| `adeyosemanputra/pygoat` | `19d17cc8` | MIT | 25 | the per-lab documentation under `introduction/` |
| `stamparm/DSVW` | `9ca3c9ac` | Unlicense | 18 | the `CASES` table in `dsvw.py` |
| `OWASP/NodeGoat` | `c5cb68a7` | Apache-2.0 | 16 | the OWASP Top 10 tutorial in `artifacts/` |
| `snyk-labs/nodejs-goof` | `add14ba5` | Apache-2.0 | 16 | the README vulnerability list |
| `appsecco/dvna` | `9ba473ad` | MIT | 14 | the README category table and `docs/` |
| `anxolerd/dvpwa` | `a1d8f89f` | MIT | 8 | the README vulnerability list |

`we45/Vulnerable-Flask-App` was considered and dropped: it carries no licence file, so it
grants no permission. `anxolerd/dvpwa` took its place.

### CVE fix commits

The commit that fixed a published advisory, replayed against its **parent** tree, which
still contains the vulnerability. The lines the fix deleted are the vulnerable lines.

| Repository | Ref (parent) | Licence | Labels | Advisory |
| --- | --- | --- | ---: | --- |
| `scitokens/scitokens` | `66b075c3` | Apache-2.0 | 5 | GHSA-rh5m-2482-966c / CVE-2026-32714, CWE-89 |
| `kepano/defuddle` | `19520add` | MIT | 4 | GHSA-jg4p-g6xj-4qmf / CVE-2026-61824, CWE-79 |
| `electerm/electerm` | `fde153d6` | MIT | 3 | GHSA-v5ff-xmfp-p245 / CVE-2026-49255, CWE-78 |
| `zamotany/logkitty` | `e1e22968` | MIT | 2 | GHSA-v8v8-6859-qxm4 / CVE-2020-8149, CWE-78 |
| `dicebear/dicebear` | `efe62f27` | MIT (per package) | 2 | GHSA-gcr2-9v8m-gq45 / CVE-2026-68921, CWE-79 |
| `webcomics/dosage` | `f2817cca` | MIT | 2 | GHSA-75mw-h36v-2jv7, CWE-79 |
| `masci/banks` | `3ab65bac` | MIT | 2 | GHSA-x8wg-4xgc-vr54 / CVE-2026-71492, CWE-22 |
| `google/slo-generator` | `50ce1bf8` | Apache-2.0 | 2 | GHSA-j28r-j54m-gpc4 / CVE-2021-22557, CWE-94 |
| `tadashi-aikawa/owlmixin` | `409c30c0` | MIT | 2 | GHSA-ccmq-qvcp-5mrm / CVE-2017-16618, CWE-502 |
| `sebhildebrandt/systeminformation` | `da1cbf5e` | MIT | 1 | GHSA-5xpp-75jx-m839 / CVE-2026-50289, CWE-78 |
| `commenthol/serialize-to-js` | `a1e8140e` | MIT | 1 | GHSA-mm62-wxc8-cf7m / CVE-2017-5954, CWE-502 |
| `commenthol/safer-eval` | `74e5bb84` | MIT | 1 | GHSA-hgch-jjmr-gp7w / CVE-2019-10760, CWE-94 |
| `Morgan-Phoenix/EnroCrypt` | `d0205026` | MIT | 1 | GHSA-35m5-8cvj-8783 / CVE-2021-39182, CWE-327 |
| `Stranger6667/pyanyapi` | `aebee636` | MIT | 1 | GHSA-vg8g-jpm9-jh8r / CVE-2017-16616, CWE-502 |
| `illagrenan/django-make-app` | `e42d3bf3` | MIT | 1 | GHSA-9pv8-q5rx-c8gq / CVE-2017-16764, CWE-94 |
| `benbusby/whoogle-search` | `8830615a` | MIT | 1 | GHSA-3q6g-qmpx-rqw4 / CVE-2024-22205, CWE-22 |

`benchmarks/vulnerable-corpus/harvest_cve_labels.py` proposed the candidates from the GitHub
advisory database; every one was read before it became a label. Most were not usable, and the
reason is worth recording: **a modern CVE fix usually tightens a sanitizer rather than
deleting a sink.** The fix for GHSA-mm62-wxc8-cf7m deletes
`new Function('return ' + str)`, which is a sink a pattern can match; the fix for
GHSA-qfrw-5rxm-mhh2 adds two schemes to a URL blocklist, which is not. Of the 375 candidates
harvested across nine CWEs and two ecosystems, 16 fix commits carried a sink the corpus could
label. The corpus therefore has no CWE-798 fix commit at all: the hardcoded-credential
advisories that were harvested fix configuration or rotate a key, not a line of code.

### What was deliberately left out

A label is a line range, so it can only describe a vulnerability that lives on a line. These
were documented, real, and not labelled, in every case because the defect is the **absence**
of something:

* Missing CSRF middleware, missing authorization checks, IDOR, missing rate limiting, missing
  security headers. Labelling the closest line would measure nothing and would make recall
  look worse than the rule set deserves.
* Weak passwords and guessable security answers in seed data (`data/static/users.yml`), and
  vulnerable dependencies. The first is data and the second is an SCA question.
* Classes with no entry in `taxonomy.CANONICAL_INTERNAL_TYPES`: XPath injection, ReDoS,
  header injection, clickjacking, LLM prompt injection. A label that expects a class the
  product cannot name is a label nothing can satisfy.

## How a number here is made

`scripts/replay/score.py` joins a finding to a label when the repository, the ref and the
path agree and the line ranges overlap within two lines.

**Recall** comes straight out of that join: a label no finding of an expected class overlaps
is a vulnerability the rule set missed on the line a reviewer would have been shown.

**Precision does not.** These repositories contain far more vulnerabilities than anybody has
labelled, so an unlabelled finding is unknown, not wrong. Precision is computed over the
adjudicated findings only: the ones a label confirms, plus the ones read by hand. The reading
list was every finding that landed on a labelled line under a class the label did not expect
(31 of them) plus a seeded random sample of 40 of the 1687 findings no label covers. All 71
verdicts, with a sentence each, are in `benchmarks/vulnerable-corpus/adjudications.json`.

The criterion used for a hand verdict: **a finding is true when it names a defect a reviewer
would act on in a security review of that line.** A speculative runtime failure in code that
cannot reach the claimed state is false. That criterion is doing real work in this table and
somebody could reasonably draw it elsewhere, so it is written down rather than implied.

## Precision, before and after

The run analysed every analysable file of each tree (2,456 files, both tiers, quarantined
rules included and reported separately), and produced 1819 findings.

| | Findings | Adjudicated | True | False | Precision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Everything | 1819 | 172 | 115 | 57 | 0.67 |
| What posted before this change | 1816 | 171 | 114 | 57 | 0.67 |
| What posts after this change | 1730 | 164 | 111 | 53 | **0.68** |
| What posts once PR 441 also lands | 378 | 113 | 110 | 3 | **0.97** |

The third row is the honest headline for this branch and the fourth is the honest headline
for the product, and the gap between them is the whole story of this measurement: **five
tier 1 rules produce 1352 of the 1819 findings and 50 of the 57 false positives, at a
measured precision of 0.02.** Those five are `null.pointer.deref`, `integer.overflow`,
`authz.missing_function_level`, `rate_limit.missing` and `concurrency.shared_state`, and they
are exactly the five that `fix/tier1-rule-precision` (PR 441) quarantines on its own
evidence. This corpus is an independent second measurement that agrees with that branch, and
nothing here re-implements it: those five are left alone so the two branches do not collide.

With PR 441's set applied as well, by language:

| Language | Findings | True | False | Precision |
| --- | ---: | ---: | ---: | ---: |
| Python | 148 | 60 | 1 | 0.98 |
| JavaScript | 105 | 30 | 1 | 0.97 |
| TypeScript | 125 | 20 | 1 | 0.95 |

and by tier: tier 1 0.96 over 57 adjudicated, tier 2 **0.98 over 56 adjudicated**. That last
number is the one the tier 2 coverage work was missing. 87 rules posted on an argument about
their patterns; the argument now has a measurement behind the 18 of them that this corpus
reached.

### Per class

| Class | Findings | True | False | Precision |
| --- | ---: | ---: | ---: | ---: |
| `unsafe_deserialization` | 33 | 20 | 0 | 1.00 |
| `hardcoded_secret` | 45 | 11 | 1 | 0.92 |
| `dynamic_code_execution` | 26 | 13 | 0 | 1.00 |
| `sql_injection` | 24 | 12 | 0 | 1.00 |
| `command_injection` | 37 | 8 | 1 | 0.89 |
| `weak_password_hash` | 9 | 8 | 0 | 1.00 |
| `open_redirect` | 15 | 7 | 0 | 1.00 |
| `nosql_injection` | 23 | 5 | 0 | 1.00 |
| `server_side_request_forgery` | 32 | 5 | 0 | 1.00 |
| `weak_cipher_algorithm` | 8 | 4 | 0 | 1.00 |
| `insecure_randomness` | 23 | 4 | 0 | 1.00 |
| `csrf_protection_disabled` | 30 | 3 | 0 | 1.00 |
| `debug_mode_enabled` | 10 | 3 | 0 | 1.00 |
| `insecure_cookie_flags` | 7 | 3 | 0 | 1.00 |
| `xml_external_entity` | 8 | 2 | 0 | 1.00 |
| `cross_site_scripting` | 17 | 1 | 1 | 0.50 |
| `path_traversal` | 92 | 4 | 4 | 0.50 |

The full per-rule, per-class and per-language tables, and the list of every missed label, are
reproducible with the command in `benchmarks/vulnerable-corpus/README.md`.

## Recall

69 of 171 labelled vulnerabilities produced a finding of the expected class on the labelled
lines: **0.40**. A further 18 had the expected class reported elsewhere in the same file and
10 were reported on the right lines under a different class, so 97 of 171 labels (0.57) got a
comment a reviewer could follow to the vulnerability.

The "in file" column is not a consolation prize, it is a real property of tier 1: **a tier 1
rule produces one finding per file.** `enrocrypt/hashing.py` offers MD5, SHA-1 and six other
digests; `crypto.weak.hash` reports the first one, at line 16, and the CVE is at line 70. The
reviewer is told the file has a weak hash, which is right, and is not told about the second
one, which is the limitation. Nine of the 18 "in file" labels are this.

### By class

| Expected class | Labels | Hit | In file | Wrong class | Missed | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `unsafe_deserialization` | 11 | 11 | 0 | 0 | 0 | **1.00** |
| `dynamic_code_execution` | 10 | 9 | 1 | 0 | 0 | **0.90** |
| `insecure_randomness` | 5 | 4 | 0 | 0 | 1 | 0.80 |
| `sql_injection` | 14 | 10 | 3 | 0 | 1 | 0.71 |
| `server_side_request_forgery` | 3 | 2 | 0 | 0 | 1 | 0.67 |
| `command_injection` | 11 | 7 | 1 | 0 | 3 | 0.64 |
| `nosql_injection` | 5 | 3 | 0 | 0 | 2 | 0.60 |
| `open_redirect` | 6 | 3 | 0 | 0 | 3 | 0.50 |
| `hardcoded_secret` | 18 | 7 | 4 | 0 | 7 | 0.39 |
| `insecure_cookie_flags` | 7 | 2 | 0 | 1 | 4 | 0.29 |
| `weak_password_hash` | 11 | 3 | 0 | 4 | 4 | 0.27 |
| `server_side_template_injection` | 4 | 1 | 1 | 0 | 2 | 0.25 |
| `xml_external_entity` | 4 | 1 | 0 | 0 | 3 | 0.25 |
| `path_traversal` | 14 | 2 | 4 | 1 | 7 | 0.14 |
| `cross_site_scripting` | 32 | 1 | 3 | 3 | 25 | **0.03** |
| `error_detail_exposure` | 6 | 0 | 0 | 0 | 6 | 0.00 |

### The three gaps worth naming

> Both of the gaps named below were closed on 24 September 2026. The measurement is in
> **The follow-up** at the end of this document; the two subsections here are left as they
> were written, because they are what the follow-up was answering.

**Cross-site scripting: 1 of 32.** This is the largest single hole in the product and it has
two separate causes. Eleven of the missed labels are in `.html`, `.ejs`, `.pug`, `.dust` and
`.jinja2` files, and tier 2 does not analyse those extensions at all: `TIER2_SUPPORTED_EXTENSIONS`
has no template language in it, so NodeGoat's `layout.html`, dvna's `products.ejs` and goof's
`about_new.dust` are never scanned. That is a coverage decision, not a pattern defect, and it
cannot be fixed by editing a rule. The rest are HTML assembled in JavaScript, TypeScript or
Python by string interpolation, which is what all four defuddle labels, both dicebear labels
and both dosage labels are:

```ts
return `<img src="${this.upgradeImageSrc(src)}" alt="${alt}">`;   // defuddle, CVE-2026-61824
```

```python
description += '<br/>%s' % comic.text                              # dosage, GHSA-75mw-h36v-2jv7
```

No rule in either tier looks for HTML built out of an interpolated string. Adding one is a
new rule with its own precision question, not a narrowing of an existing pattern, so it is
recorded here rather than done in this change.

**Path traversal: 2 of 14, at precision 0.43.** The one rule that covers the class broadly is
the one this change quarantines; the tier 2 path rules are narrow and correct and cover a
handful of shapes. Both of the masci/banks labels are `path / f"{name}.{version}.jinja"`, a
`pathlib` join, which no rule matches.

**Command injection: 7 of 11, and every miss is one variable away.** systeminformation and
all three electerm labels build the command string on one line and run it on the next:

```js
const cmd = `rm -rf "${localFolderPath}"`
return isWin ? runWinCmd(cmd) : run(cmd)
```

`cwe-78.js-exec-interpolated` requires the template literal to be inside the `exec` call, and
it is right to: matching `exec($VAR)` for any variable is how a rule gets a precision of
0.02. This needs one hop of data flow, which the AST pattern engine does not give it. Recorded.

## The posting decisions

The policy is the one PRs 441 and 445 set: a rule with at least three adjudicated findings
and precision below 0.8 is quarantined with its evidence; a quarantined rule with at least
three adjudicated findings at 0.8 or better may come back with the evidence line.

"At least three hits" is read here as three **adjudicated** findings, not three findings that
a label confirmed. A rule with three false positives and no true one has been measured just
as surely as a rule with three true ones, and reading it the other way would mean a rule can
only ever be quarantined by first being right.

### Quarantined: `path.traversal.user_path`

86 findings over 23 repositories, 7 adjudicated, 3 true and 4 false, precision **0.43**.

The four false positives all arrive through one alternative of the pattern:

```
(\bopen\(|\bsend_file\(|\bFile\(|\breadFile\(|\breadFileSync\(|\bcreateReadStream\().*(\.\./|req\.|input\(|\+|f"|\{)
```

The trailing `\{` was meant to catch an f-string or a template interpolation. What it
actually matches most of the time is the brace of an options object:

| Line | Why it is not path traversal |
| --- | --- |
| `fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })` | a constant path; the `{` is the options object |
| `fs.readFileSync(svgPath, { encoding: 'utf-8' })` | a test reading its own fixture |
| `this.snackBar.open(\`…${language.lang}\`, 'Force page reload', {` | a snackbar, not a file |
| `gzip.open(_file(f'{name}.{ext}.gz'))` | a test helper over names the test supplies |

The obvious narrowing, dropping `\{`, was tried and rejected: it also removes the rule's own
true positive on DSVW's `open(params["include"], "rb") … {"__builtins__": None}`, whose only
signal on that line is the same brace. The rule cannot be narrowed without a data-flow answer
about where the path came from, which is why this is a quarantine and not a pattern change.
The evidence is on the rule in `security_rules.py`.

This is the first tier 1 rule to carry a posting state, so `security_rules.py` gains the
three fields PR 441 defines (`precision`, `posting`, `precision_evidence`) and
`main.QUARANTINED_RULE_IDS` becomes the union of the two tiers' declarations. PR 441 changes
five different rules, so the two branches meet only in the dataclass and in that one union.

### Not quarantined, and why

| Rule | Findings | Adjudicated | Precision | Decision |
| --- | ---: | ---: | ---: | --- |
| `xss.unsafe_html_render` | 16 | 2 | 0.50 | 2 adjudicated is under the threshold. Recorded, not acted on. |
| `auth.bypass.missing_check` | 8 | 1 | 0.00 | 1 adjudicated. Recorded, not acted on. |
| `opengrep.cwe-798.hardcoded-secret-js` | 5 | 2 | 0.50 | 2 adjudicated. The false one is `let password = ''`, an empty initialiser. Recorded. |
| `concurrency.shared_state` | 46 | 0 | n/a | The random sample reached none of them. PR 441 quarantines it on its own evidence. |

Three rules that this corpus could not decide is not a failure of the corpus; it is what a
sample of 40 out of 1687 buys. A larger sample is the obvious next increment.

### Re-measured and still quarantined

| Rule | Findings | What the corpus showed |
| --- | ---: | --- |
| `opengrep.cwe-489.py-debug-constant-true` | 2 | Both are `DEBUG = True` in a real Django settings module, and one is confirmed by a label. That is exactly the shape the quarantine doubted ("not a settings module"), so the quarantine reason is now wrong; the rule is one adjudicated hit short of the three the policy requires to re-enable it. |
| `opengrep.cwe-79.py-jinja-autoescape-off` | 1 | A Jinja `Environment` that renders **Python source files** in django-make-app. That is precisely the false positive the quarantine predicted, so it stays. |
| `opengrep.cwe-79.js-dangerously-set-dynamic` | 0 | Not reached by this corpus. |
| `opengrep.cwe-1275.js-cookie-samesite-none` | 0 | Not reached by this corpus. |

Nothing is re-enabled. That is the policy working rather than the policy failing: the one
rule with a good case is short by one reading, and inventing the reading to get it over the
line would make the threshold meaningless.

### What the 18 measured tier 2 rules are

Each now carries a `precision_evidence` line naming its findings. The ones with the most
behind them:

| Rule | Findings | Adjudicated true | Repositories |
| --- | ---: | ---: | ---: |
| `cwe-89.py-execute-concat-direct` | 7 | 7 | 2 |
| `cwe-798.js-credential-config-key` | 7 | 3 | 3 |
| `cwe-916.py-password-weak-hash-usedforsecurity` | 3 | 3 | 2 |
| `cwe-352.py-csrf-exempt` | 25 | 2 | 1 |
| `cwe-78.js-exec-interpolated` | 15 | 2 | 3 |
| `cwe-943.js-mongo-where-operator` | 7 | 2 | 1 |
| `cwe-601.js-redirect-request-value` | 2 | 2 | 2 |
| `cwe-798.js-session-secret-literal` | 2 | 2 | 2 |

Not one of the 18 produced an adjudicated false positive. `cwe-78.js-exec-interpolated` is
worth singling out: PR 445 narrowed it after all six of its findings on the clean corpus
turned out to be `RegExp.prototype.exec`, and the open question was whether the narrowing had
removed the rule. It had not. The rule found logkitty's `execSync(\`${adbPath} logcat -c\`)`,
which is CVE-2020-8149.

## The benchmark additions

`benchmarks/tier2-precision/cases.json` grows from 94 cases to 121. The 27 new ones are
labelled true positives, taken out of the corpus files rather than written: for each rule the
generator tried the finding's own lines, then those lines with the file's imports, then the
enclosing block, then both, scanned each with the real scanner, and kept the first that
reproduced the finding. Three could not be reproduced in isolation and were left out rather
than adjusted until they passed:

| Rule | Where | Why it needs its file |
| --- | --- | --- |
| `cwe-22.path-traversal-fs` | juice-shop `routes/vulnCodeSnippet.ts:90` | a top-level `await` that only parses inside the module |
| `cwe-352.py-csrf-exempt` | pygoat `introduction/apis.py:22` | the decorator needs the view it decorates, which pulls in the module |
| `cwe-918.ssrf-axios` | juice-shop `routes/profileImageUrlUpload.ts:24` | the fetch is a statement in an async handler |

Each of those three still has its authored fixture, so the rule is still covered.

## Family reach on real vulnerabilities

Every finding in a supported repair family was run through the real `RepairEngine` with the
local sandbox driver and a provider that refuses every call, so the template path runs for
real and anything needing the model is counted rather than made.

| | Before | After |
| --- | ---: | ---: |
| Findings in a supported family and language (all rules) | 214 | 214 |
| Candidates produced end to end | 5 | **8** |
| Candidates whose sandbox check passed | 5 | **8** |
| Model calls needed | 0 | 0 |
| Sites where the deterministic template can build a patch (posting rules only) | 20 | **25** |

The dominant reason a template declines is structural, not a bug: **52 of the 103 refusals
are `enclosing_route_not_found`.** The JavaScript templates for SQL, command and path
families rewrite inside an Express route handler, because that is where they know a 400 can
be returned. A CLI, a library and an Electron main process have no route, and most of this
corpus is one of those. That is a real limit on where automated repair applies, and it is
better stated than measured away.

One shape recurred and was fixable. Both `templates._js_credential` and the proof generator
in `proofs.py` looked for the literal on the finding's first line only, and a rule that
matches a multi-line object literal reports the line the *pattern* opens on:

```js
app.use(session({          // <- cwe-798.js-session-secret-literal reports here
  secret: 'keyboard cat',  // <- the credential is here
  resave: true,
}))
```

Four sites in two repositories (`OWASP/NodeGoat` `config/env/all.js`, `development.js`,
`test.js`, and `appsecco/dvna` `server.js`) were refused as
`string_literal_assignment_not_found` while the rule was right about every one. Both now use
one shared `sites.js_literal_assignment_in_span`, which never leaves the finding's own line
range and so can only find a literal the rule already matched. Three of the four sites now
produce a verified repair; `appsecco/dvna` `server.js` still does not, because its proof has
to load a module that requires `express`, and the harness snapshot is the source files
without `node_modules`. That is the replay's documented snapshot caveat rather than a defect
in the repair.

`benchmarks/remediation/fixtures/js-session-secret-object` is the fixture, in the shape the
corpus found it in, and the seed benchmark goes from 13 cases and 9 verified repairs to 14
and 10, precision 1.00, no failures, no unsafe abstentions.

## What this does not measure

* **Tier 3 never runs.** `LLM_TRIAGE_ENABLED=false`, so every finding here is pre-triage.
  Triage would filter some of the 1687 unread findings, and this measurement cannot say how
  many.
* **A snapshot is not a pull request.** Production analyses changed lines; this analyses whole
  files. Findings in code nobody touched would never be posted, so the precision here is a
  property of the rule set rather than of a reviewer's inbox.
* **The sample is 40 of 1687.** Three rules could not be decided because of it, and every
  per-rule precision in this document has a wide interval around it. The numbers are strong
  enough to separate 0.02 from 0.97 and are not strong enough to separate 0.9 from 0.95.
* **The corpus has no CWE-798 fix commit, and no Java, Go, Ruby, PHP or C#.** Recall for the
  rules covering those is unmeasured, exactly as tier 2's recall was before this. It did have
  template languages all along, in `.html` and `.ejs`; what it did not have was a tier 2 that
  read them, which is what the follow-up below changed. `.erb`, `.svelte` and `.dust` are in
  the extension set and no repository here uses them, so those three rules remain unmeasured.
* **Labels are sinks.** Every missing-control vulnerability in these applications is absent
  from the denominator, so the recall here is recall over the vulnerabilities a pattern
  scanner could in principle find, not over the vulnerabilities the applications have.

## The follow-up: the two gaps, 24 September 2026

The run above named three gaps and said which two were worth acting on. This is what acting
on them produced, measured the same way, on the same corpus, at the same pinned refs.

| | Before | After |
| --- | ---: | ---: |
| Labels hit on the labelled lines | 69 / 171 (0.40) | **100 / 171 (0.58)** |
| `cross_site_scripting` | 1 / 32 (0.03) | **26 / 32 (0.81)** |
| `path_traversal` | 2 / 14 (0.14) | **8 / 14 (0.57)** |
| Findings | 1819 | 2568 |
| Precision of what posts | 0.68 | **0.74** |

**Recall and posted recall are not the same number, and the gap is the honest part.** Of the
26 cross-site scripting labels now reached, 8 are reached only by a rule this change
quarantined, so 18 of 32 reach a reviewer. For path traversal it is 7 of 14. Both are still
several times what they were, and neither is what the first row claims.

### What was added

**Sixteen template extensions.** `.html`, `.htm`, `.ejs`, `.erb`, `.hbs`, `.handlebars`,
`.mustache`, `.dust`, `.njk`, `.jinja`, `.jinja2`, `.j2`, `.twig`, `.vue`, `.svelte` and
`.pug` now reach tier 2, in `opengrep_rules/template_coverage.yml`, which holds 9 rules.

They are read in the scanner's `generic` mode rather than by a parser, and that was measured
rather than assumed. `languages: [html]` claims only `.html` and `.htm`, so it cannot cover
the set, and it reports `PartialParsing` on server-side tags, which books a coverage gap on
exactly the files the rules exist to read. `languages: [vue]` returned a syntax error and
zero results on a standard single-file component. Nothing is lost: `{{{ }}}`, `<%- %>`,
`| safe`, `v-html`, `{@html}` and `!{ }` are lexical, not nodes in an HTML tree.

The cost of `generic` is that it has no notion of a language, so a rule without
`paths: include` reads every file in the batch, `.py` and `.ts` alongside the templates.
Every rule in that file carries one and `tests/test_template_rules_are_path_scoped.py` fails
if one does not, or if an include names an extension outside the template set.

**The extension list is written down three times** and now asserted. It is in
`opengrep_runner`, in `prAnalysisOrchestrator.js` and in `scripts/replay/prodfilters.py`, and
a divergence is silent in all three directions: an extension only in the scanner scans
nothing because no content arrives, one only in the orchestrator pays to fetch files the
scanner drops, and one only in the replay makes the harness report recall the product cannot
deliver. `tests/test_supported_extension_parity.py` fails on any of the three.
`fetchPullRequestFiles` in the github service is deliberately not a fourth copy: it filters
on status and on `dist/`/`node_modules`, never on extension.

**Five rules added and three widened.**

| Rule | Findings | Adjudicated | Precision | Posting |
| --- | ---: | ---: | ---: | --- |
| `cwe-79.js-angular-bypass-security-trust` | 14 | 12 | 1.00 | post |
| `cwe-79.py-html-percent-format` | 14 | 12 | 0.92 | post |
| `cwe-79.tpl-inline-script-inner-html` | 15 | 5 | 1.00 | post |
| `cwe-79.tpl-ejs-unescaped-output` | 4 | 4 | 1.00 | post |
| `cwe-22.js-sendfile-request-path` (widened) | 4 | 4 | 1.00 | post |
| `cwe-22.py-pathlib-join-interpolated` | 2 | 2 | 1.00 | post |
| `cwe-22.js-archive-entry-write` (widened) | 1 | 1 | 1.00 | post |
| `cwe-79.js-template-autoescape-disabled` | 1 | 1 | 1.00 | post |
| `cwe-79.tpl-mustache-triple-brace` | 1 | 1 | 1.00 | post |
| `cwe-79.tpl-pug-unescaped-interpolation` | 1 | 1 | 1.00 | post |
| `cwe-79.tpl-vue-v-html` | 1 | 1 | 1.00 | post |
| `cwe-79.tpl-unescaping-filter` | 12 | 10 | 0.70 | **quarantine** |
| `cwe-79.js-html-string-interpolated` | 678 | 17 | 0.47 | **quarantine** |

The Angular sanitizer bypass was the single largest share of the cross-site scripting gap and
is not in the original write-up above: 7 of the 32 labels are juice-shop calling
`bypassSecurityTrustHtml`, which no rule in either tier looked for.

### Quarantined: `cwe-79.js-html-string-interpolated`

678 findings over 23 repositories, the largest of any tier 2 rule and second largest of any
rule in either tier. It reaches all six labelled interpolated-HTML vulnerabilities, which is
exactly what the write-up above asked for, and it cannot post at precision 0.47.

The false positives are two classes, and neither is a pattern defect that can be narrowed
away:

| Line | Why it is not an injection |
| --- | --- |
| `` `<circle fill="${escape.xml(`${colors.skin}`)}"/>` `` | dicebear escapes every interpolation; the rule cannot see the wrapper |
| `` html += `<a href="${escapeHtml(href)}"><img src="${escapeHtml(src)}" /></a>` `` | defuddle does the same |
| `` return `<article>${parts.join('\n')}</article>` `` | composition: the value is already-built markup, not data |
| `` return `<!DOCTYPE html>…${buildTimeConstant}…` `` | a static marketing page |

Separating any of these from a real injection needs a data-flow answer about where the value
came from and whether anything escaped it on the way, which the AST pattern engine does not
give. This is the same reason `cwe-79.js-dangerously-set-dynamic` is quarantined.

### Quarantined: `cwe-79.tpl-unescaping-filter`

12 findings, 10 adjudicated, 7 true and 3 false, precision 0.70. This one is quarantined
against its own true positives: it reaches both pygoat XSS labels, whoogle's proxied search
response and a Django form field, and all three false positives are one shape, `{{ logo|safe }}`
on markup the application itself builds. The policy quarantines at three adjudicated findings
below 0.8 and this is ten, so it is quarantined; reading it the other way would make the
threshold mean nothing the first time a rule found something real.

### Two false-positive classes that only real code showed

Both were found by adjudicating the run, not by the fixtures, and both had passed every
fixture written for them.

`<%- include(...) %>` is how EJS composes partials and `<%- body %>` is how
express-ejs-layouts renders a child view. Both are unescaped output tags and neither is a
place user input is written. Four of the eight findings of `cwe-79.tpl-ejs-unescaped-output`
were these; excluding them takes it from 0.50 to 1.00.

`generic` mode is whitespace-insensitive, so the pattern `{{{ ... }}}` also matches
`{ {{ ... }} }` -- which is what Angular's `@if (cond) { {{ x }} } @else {` block looks like.
Two of the three findings of `cwe-79.tpl-mustache-triple-brace` were juice-shop Angular
templates matched that way. The rule is now a `pattern-regex`, which is whitespace-exact.

### A tier 1 defect this surfaced

Tier 1 has never been extension-gated: the orchestrator hands `analyze_tier1_payload` every
changed file, so its regexes have been reading templates in production since templates have
existed. Nothing here changed that, but widening tier 2 made it visible, because the replay's
snapshot walk selects files with the tier 2 filter.

What it was doing: thirteen findings across seven `.html` files in `OWASP/NodeGoat` alone,
including `rate_limit.missing` on `signup.html` and `nosql.injection`,
`code.injection.eval`, `authz.missing_function_level`, `redirect.open`, `integer.overflow`
and `null.pointer.deref` on the tutorial pages, which quote vulnerable code as documentation.
A template declares no route, holds no handler and dereferences nothing, so none of them can
be true.

The fix is the mechanism that already existed for prose. `is_non_code_text_path` is
`is_prose_path` or `is_template_path`, and `pattern_findings` skips a rule on those paths
unless it declares `scans_prose` -- so `secret.hardcoded.credential` keeps scanning
templates, because a credential in a template is as real as one anywhere else. NodeGoat goes
from 72 findings to 59 with none on a template.

### What is still missed

Five cross-site scripting labels and six path traversal labels survive.

* **Three NodeGoat labels are plain `{{ }}` in swig templates.** They are unescaped only
  because `server.js` sets `autoescape: false`, which is a different file.
  `cwe-79.js-template-autoescape-disabled` reports that line, and a finding in `server.js`
  cannot join to a label in `layout.html`, so the reviewer is told the right thing and the
  join scores it as a miss.
* **`anxolerd/dvpwa`'s `setup_jinja(..., autoescape=False)` is deliberately not matched.**
  A rule for it would duplicate `cwe-79.py-jinja-autoescape-off`, which is quarantined
  because a Jinja environment without autoescaping is cross-site scripting only when the
  templates render HTML, and Jinja is widely used for configuration, SQL and email where
  autoescaping would be wrong. Writing a broader version under a new id would have undone
  that decision quietly.
* **Pug's `!= expr` is not matched.** In `generic` mode `!=` is indistinguishable from the
  inequality operator in the inline JavaScript these files carry, so the pattern would
  report every comparison in the file. Only `!{ }` is matched.
* **Four DSVW labels build HTML with no interpolation on the labelled line**, such as
  `content += "<div><span>Comment(s):</span></div><table>"`, and `%s%s%s` formats with no
  tag in the format string. Both are invisible to a pattern that keys on a tag opener.

## After generalised sites

The refusal above said the JavaScript templates need an Express route. They no longer do:
`sites.js_site_for_line` prefers the enclosing route and falls back to the enclosing function,
method, or `exports.name` binding, on both languages. The same 23 snapshots were replayed
before and after over one cache, and the two generators were also called directly over every
finding, because the replay's provider refuses every call and a finding the template does not
prove ends at `provider_budget_reservation_denied` whatever the template said.

238 of the 1819 findings are in a supported family with their file in the cached tree.

| | Before | After |
| --- | ---: | ---: |
| `enclosing_route_not_found`, template | 123 | **0** |
| `enclosing_route_not_found`, proof | 123 | **0** |
| Findings the template builds a patch for | 25 | **30** |
| Findings the service writes a proof for | 29 | **37** |
| Findings with both halves, so a deterministic candidate is possible | 22 | **23** |
| Findings with neither | 206 | **194** |
| Candidates produced and verified end to end | 8 | 8 |

**The route requirement is gone and the reach barely moved.** 123 refusals disappeared and five
more findings got a patch. That is the honest result, and the reason is in where the refusals
went rather than in the totals: they moved down to the next obstacle, one finding at a time.

| Reason the site model exposed | After |
| --- | ---: |
| `enclosing_function_not_found` (template) | 67 |
| `module_not_loadable_by_node` (proof) | 52 |
| `path_module_not_required` | 17 |
| `function_parameters_not_plain_names` | 17 |
| `path_join_not_found_in_scope` (proof) | 16 |
| `command_name_not_literal` | 11 |

Three of those are worth naming. `enclosing_function_not_found` is 67 findings in code at module
scope, where there is no function to call and so nothing a generated test can drive; that is a
bigger group than the route requirement ever was. `module_not_loadable_by_node` is 52 findings in
TypeScript, which plain `node` cannot `require`, and which this replay found only because the
site model made the proof reachable enough to hit that wall. `path_module_not_required` is 17
path findings whose file joins with string concatenation rather than `path.join`.

**End to end the corpus is unchanged at 8.** The one extra complete pair did not survive
verification, and the eight that do are all `hardcoded_credential`, exactly as before. Nothing
here measures the model path: 184 of the 245 attempts stop at the refusing provider by design.

What this does buy, and what the 23-to-1 gap between reachable sites and shipped candidates
says, is that the site model is a precondition rather than a fix. The fixtures under
`benchmarks/remediation/fixtures` now carry six shapes it reaches (a module function, an
`exports.name` assignment, a class method, an `exec` helper, a path helper that throws, and a
Python path helper that raises), and five of the six produce a template patch and a proof that
match their reference repair exactly. On this corpus the binding constraint has moved to
module-scope code and to snapshots without their dependency tree.

Five Python SQL findings raise `AttributeError` in the direct-generator measurement because the
harness stub for that measurement does not implement `Snapshot.paths`, which `_py_driver` reads
to find a local module. The count is identical in both runs, so the comparison is unaffected;
the engine itself passes a real snapshot and does not hit it.

## After TypeScript and module scope

The two obstacles the section above named are gone. TypeScript loads in the sandbox, through
Node's own type stripper rather than a toolchain: the pinned runtime moved from 20.20.2 to the
current 22 LTS, every generated test and derived syntax check runs with
`--experimental-strip-types`, and the harness resolves the `.ts` sources Node's own resolver will
not find. Code at module scope is a repair site: the template rewrites the sink in place exactly
as it would inside a function, and the proof drives it by setting what the module reads before
importing it.

The same 23 snapshots were replayed once and both generators were then called directly over every
finding, against this branch and against the base branch's service source over that one cache.
The direct call is what measures the two halves: the replay's provider refuses every call, so a
finding the template does not prove ends at `provider_budget_reservation_denied` whatever the
template said.

245 of the 1819 findings are in a supported family with their file in the cached tree. The sites
run above reported 238 for the same corpus; every other row of the before column below reproduces
its numbers exactly, so the difference is in that run's bookkeeping rather than in the reach.

| | Before | After |
| --- | ---: | ---: |
| `enclosing_function_not_found`, template | 67 | **9** |
| `enclosing_function_not_found`, proof | 58 | **9** |
| `module_not_loadable_by_node`, proof | 59 | **0** |
| Findings the template builds a patch for | 30 | **33** |
| Findings the service writes a proof for | 37 | 37 |
| Findings with both halves, so a deterministic candidate is possible | 23 | 23 |
| Findings with neither | 201 | **198** |
| Candidates produced and verified end to end | 8 | 8 |

**Both walls came down and the reach did not move.** That is the honest result, and it is the
second time this corpus has said it. 126 refusals disappeared, three more findings got a patch,
and not one more finding got a proof. The refusals moved down to the next obstacle again, one
finding at a time, and this time the next obstacle is named rather than structural.

| Reason the site model exposed | Before | After |
| --- | ---: | ---: |
| `module_scope_source_not_controllable` (proof) | 0 | 60 |
| `path_module_not_required` (template) | 17 | 65 |
| `path_join_not_found_in_scope` (proof) | 16 | 27 |
| `function_parameters_not_plain_names` (proof) | 2 | 23 |
| `function_parameters_not_plain_names` (template) | 22 | 22 |
| `eval_argument_not_an_identifier` (both) | 18 | 18 |
| `string_literal_assignment_not_found` (both) | 17 | 17 |
| `sql_sink_not_in_scope` (proof) | 2 | 14 |
| `command_name_not_literal` (template) | 11 | 13 |
| `no_untrusted_parameter` (proof) | 9 | 12 |

`module_scope_source_not_controllable` is 60 of the 67 findings that used to be
`enclosing_function_not_found`. The sink runs at import and the value reaching it comes from a
call no test can set, so there is no test that fails on the vulnerable code and passes on the
repair. Refusing is the correct answer for those 60, not a gap: a proof that cannot fail before
the fix proves nothing after it. The seven that are drivable moved on, and `path_module_not_required`
went from 17 to 65 because most of them are path findings in files that build a path by string
concatenation rather than with `path.join`, which the template needs by name.

The nine `enclosing_function_not_found` that remain are all `code_injection_eval`:
`sites.js_eval_site` needs the function whose parameter carries the value it compiles, and module
scope has no parameter.

### What the corpus's TypeScript actually is

88 of the 245 findings are in `.ts` files, across 73 distinct files. Every one of those 73 files
is strippable: not one `enum`, `namespace`, or constructor parameter property anywhere in them, so
`typescript_syntax_not_strippable` never fired on this corpus. 73 of the 88 findings are in modules
written with `import`/`export` and 15 in CommonJS modules.

The TypeScript proof count did not change, at 9 before and 9 after, and the reason is worth
naming. In the base branch the loadability check ran *after* the `hardcoded_credential` and
`code_injection_eval` generators returned, so those two families wrote proofs for `.ts` modules
that the sandbox could not have loaded: nine proofs that would have failed on both trees. The
check now runs once, before every family. The same nine findings get proofs, and those proofs can
now run. The other 79 TypeScript findings stop at a refusal that has nothing to do with the
language.

One TypeScript shape is not reached even now, and it is the majority one: the built-in fakes are
injected through the CommonJS loader, so a module written with `import`/`export` gets the real
`express` or `pg`, which is not installed, and its proof fails rather than passing. That is safe
and it is a ceiling. `contracts/test-harness-v1.md` records it.

### The benchmark

Four seed fixtures that `docs/architecture/known-debt.md` recorded as one adapter defect
(`js-path-readfile-join`, `js-path-sendfile`, `js-session-secret-object`,
`python-path-helper-raises`) were four separate defects in the generated proofs, each found by
running its own proof against its own reference repair. The adapter was where the symptom
surfaced: its scripted provider raised when the engine asked for an action it did not have, which
ended the execution as `inconclusive` with an engine error that said nothing about the fixture. It
now abstains with a reason and counts how often it happened. The seed suite is 55 fixtures under
both adapters with no unexpected failures.

## Suites

| Suite | Command | Result |
| --- | --- | --- |
| analysis-service | `python -m pytest tests -q` in `services/analysis-service/src` | 1373 passed, 1 skipped, on the integration branch |
| remediation-service | `python -m pytest tests -q` in `services/remediation-service` | 503 passed, on the integration branch. Fails by one (`test_python_harness.py`) in an interpreter that has Flask installed, which is pre-existing and environment-dependent |
| tier 2 precision benchmark | `python -m pytest tests/test_tier2_precision_benchmark.py -q` | 140 passed, on the integration branch |
| remediation benchmark | `benchmarks/remediation/evaluate.py --suite seed` and `--adapter engine-local` | 55 cases, 43 repairs verified, 12 safe abstentions, no unexpected failures under either adapter |
| sandbox harness spec | `node --test-reporter=tap services/remediation-service/tests/harness_spec.js` | 16 passed |
| remediation benchmark harness | `python -m pytest benchmarks/remediation/tests -q` | 23 passed |
| replay self-test | `scripts/replay/selftest.py` | ok: findings=2 candidates=2 verified=2 agent_needed=0 |
