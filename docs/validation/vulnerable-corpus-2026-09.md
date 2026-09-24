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
* **The corpus has no CWE-798 fix commit, no Java, Go, Ruby, PHP or C#, and no template
  language.** Recall for the rules covering those is unmeasured, exactly as tier 2's recall
  was before this.
* **Labels are sinks.** Every missing-control vulnerability in these applications is absent
  from the denominator, so the recall here is recall over the vulnerabilities a pattern
  scanner could in principle find, not over the vulnerabilities the applications have.

## Suites

| Suite | Command | Result |
| --- | --- | --- |
| analysis-service | `python -m pytest tests -q` in `services/analysis-service/src` | 1016 passed |
| remediation-service | `python -m pytest tests -q` in `services/remediation-service` | 339 passed, 1 failed (`test_python_harness.py`, pre-existing, fails because Flask is installed in this interpreter) |
| tier 2 precision benchmark | `python -m pytest tests/test_tier2_precision_benchmark.py -q` | 121 passed |
| remediation benchmark | `benchmarks/remediation/evaluate.py --suite seed` and `--adapter engine-local` | 14 cases, 10 repairs verified, 4 safe abstentions, no failures |
| replay self-test | `scripts/replay/selftest.py` | ok: findings=2 candidates=2 verified=2 agent_needed=0 |
