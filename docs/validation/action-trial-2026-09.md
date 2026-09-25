# GitHub Action trial on ten real repositories, September 2026

The Mitig8it action, installed on private copies of ten real repositories, run on a pull request
in each, and read as the maintainer of those repositories would read it. Nobody was asked for
permission and nothing was staged: the action ran from
`aicodesentry/mitig8it/action@integration/2026-09-24` on GitHub's own runners, with the
workflow's own token, against code it had never seen.

Every repository is a disposable private copy under the `nebullii` account, named
`mitig8it-trial-<repo>`. They are listed at the end for deletion.

## What was run

Each trial repository holds the upstream tree at a pinned commit, pushed as a single root commit
on `main`, with the upstream's own workflows disabled so nothing but the review ran. One pull
request per repository adds `.github/workflows/mitig8it.yml`:

```yaml
name: Security review
on: pull_request
permissions:
  contents: read
  pull-requests: write
  checks: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aicodesentry/mitig8it/action@integration/2026-09-24
```

No `.mitig8it.yml`, no model key, no inputs beyond the defaults, so this measures the
deterministic half of the product only.

The same pull request appends one trailing comment to each line under review, which is what puts
those lines in the diff. That choice is load-bearing and section "Findings with nowhere to go"
explains why. For the five corpus repositories the lines under review are the ones
`benchmarks/vulnerable-corpus/labels.json` labels; for the five clean-replay repositories they
are ten evenly spaced code lines in each of the ten most recently changed source files, a rule
fixed in advance so the sample is not chosen for what it would find.

Then a second commit changed one README line and nothing else, to see whether the re-run
converges. On one repository a third commit fixed a reported finding for real, to see whether the
thread it opened is retired.

Two artefacts of the trial itself, neither of them the action's doing. juice-shop ships a
compliance workflow that rated the trial pull request as spam and closed it before the upstream
workflows could be disabled; it was reopened, which cost one extra review run on the same head and
incidentally showed the re-run posting no duplicates. And the corpus labels for
`app/views/error-template.html:11` fall inside a multi-line tag, so that one line was left
untouched rather than have the annotation break the markup.

### Pinned refs and licences

The corpus records a ref for every vulnerable repository. The replay does not record one for the
clean repositories: it replayed 15 merged pull requests each, not a tree, so there is no snapshot
commit to reuse. Those five are pinned at the default branch head on the day of the trial and the
sha is recorded here instead.

| Trial repository | Upstream | Ref | Licence (read in the snapshot) |
| --- | --- | --- | --- |
| `mitig8it-trial-nodegoat` | OWASP/NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | Apache-2.0 (`LICENSE`, verbatim Apache 2.0) |
| `mitig8it-trial-juice-shop` | juice-shop/juice-shop | `1618a611b173b4bf114028e6e02549950606e29d` | MIT (`LICENSE`, Bjoern Kimminich and the OWASP Juice Shop contributors) |
| `mitig8it-trial-pygoat` | adeyosemanputra/pygoat | `19d17cc8874861142b330636d068bbde54e86b85` | MIT (`LICENSE.md`) |
| `mitig8it-trial-nodejs-goof` | snyk-labs/nodejs-goof | `add14ba59e98240d9e00a235dd7d42cd61ae9912` | Apache-2.0 (`LICENSE`, verbatim Apache 2.0) |
| `mitig8it-trial-dvna` | appsecco/dvna | `9ba473add536f66ac9007966acb2a775dd31277a` | MIT (`LICENSE`, Appsecco Ltd) |
| `mitig8it-trial-express` | expressjs/express | `9a34acf03cb818ff3f8bc40e44176e277a25cbb9` | MIT (`LICENSE`, TJ Holowaychuk and others) |
| `mitig8it-trial-fastify` | fastify/fastify | `09b4a17a12a67407a4131d48c26a0dc309c55ecf` | MIT (`LICENSE`, The Fastify team) |
| `mitig8it-trial-flask` | pallets/flask | `d73fa1cdcbd8b1465c151db8924ba58b1dd14e35` | BSD-3-Clause (`LICENSE.txt`, Pallets) |
| `mitig8it-trial-got` | sindresorhus/got | `e1d87d2ced01d5b7d855a7dc8b091bf7b014a1e4` | MIT (`LICENSE`, Sindre Sorhus) |
| `mitig8it-trial-sequelize` | sequelize/sequelize | `4b6aa9d6eddd70426ed98b8008ddcff751fe2954` | MIT (`LICENSE`, Sequelize Authors) |

All ten are permissive and all ten allow the copy made here.

## Results

Run 1 is the first run on the review pull request, run 2 the re-run after the README commit.
Findings are what the log counted; comments are what a maintainer can actually click on.

| Repository | Duration 1 → 2 | Image build 1 → 2 | Files in scope 1 → 2 | Findings (crit/high/med) | Comments | Suggestion blocks | Verified lines | TP | FP | Unsure | Recall on labelled lines in the diff |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| nodegoat | 114s → 75s | 89s → 53s | 14 → 15 | 6 (6/0/0) | 4 | 0 | 0 | 4 | 0 | 0 | 4/15 (27%) |
| juice-shop | 209s → 129s | 110s → 65s | 32 → 33 | 27 (22/2/3) | 26 | 0 | 0 | 25 | 0 | 1 | 24/43 (56%) |
| pygoat | 137s → 79s | 85s → 42s | 7 → 8 | 37 (12/20/5) | 16 | 0 | 1 | 16 | 0 | 0 | 14/25 (56%) |
| nodejs-goof | 130s → 73s | 99s → 43s | 8 → 9 | 9 (5/2/2) | 8 | 0 | 0 | 8 | 0 | 0 | 8/16 (50%) |
| dvna | 126s → 103s | 88s → 55s | 6 → 7 | 12 (8/3/1) | 10 | 0 | 0 | 10 | 0 | 0 | 10/14 (71%) |
| express | 110s → 66s | 89s → 42s | 11 → 12 | 1 (0/0/1) | 0 | 0 | 0 | - | - | - | not labelled |
| fastify | 111s → 67s | 89s → 41s | 11 → 12 | 0 | 0 | 0 | 0 | - | - | - | not labelled |
| flask | 113s → 64s | 93s → 43s | 11 → 12 | 1 (0/0/1) | 1 | 0 | 0 | 0 | 1 | 0 | not labelled |
| got | 155s → 95s | 111s → 58s | 11 → 12 | 0 runtime, 2 informational | 0 | 0 | 0 | - | - | - | not labelled |
| sequelize | 127s → 60s | 103s → 36s | 11 → 12 | 0 | 0 | 0 | 0 | - | - | - | not labelled |
| **total** | | | | **93 runtime, 2 informational** | **65** | **0** | **1** | **63** | **1** | **1** | **60/113 (53%)** |

The image is 745 MB on every run. The first build on a repository takes 85 to 111 seconds because
the layer cache is empty; `actions/cache` then makes the second build 36 to 65 seconds. Publishing
is the other cost: juice-shop spent 39 of its 209 seconds posting 26 comments, one API round trip
each.

### Precision and recall

Every one of the 64 comments on the five corpus repositories landed on a line the corpus labels as
vulnerable. Not one landed anywhere else. Judged against the labels the action's precision on this
corpus is 64/64; judged by reading each comment against the code I call 63 true positives and one
unsure (see the appendix).

Recall is the other half and it is the weaker one: of the 113 labelled lines the pull requests put
in the diff, 60 got a comment. The 53 that did not are dominated by classes the deterministic
tiers do not cover:

| Class missed | Count | Examples |
| --- | ---: | --- |
| `hardcoded_secret` | 11 | `config/env/all.js:8-9`, `typeorm-db.js:11-12`, `routes/checkKeys.ts:10` |
| `weak_password_hash` | 6 | `app/data/user-dao.js:20-25`, `models/user.ts:73`, `lib/utils.ts:80` |
| `cross_site_scripting` in templates | 6 | `app/views/memos.html:31`, `xss_lab.html:27`, `routes/videoHandler.ts:71` |
| `path_traversal` | 5 | `routes/dataErasure.ts:104`, `introduction/views.py:925-927` |
| `insecure_cookie_flags` | 4 | `server.js:78-82`, `lib/insecurity.ts:192` |
| `error_detail_exposure` | 3 | `app/routes/error.js:10-12`, `core/appHandler.js:128-129` |
| `xml_external_entity` | 3 | `lib/xml.ts:35`, `introduction/views.py:258-260` |
| `sql_injection` / `nosql_injection` | 4 | `routes/login.ts:34`, `introduction/views.py:864` |
| JWT, CORS, SSRF, prototype pollution, SSTI, others | 11 | `lib/insecurity.ts:52,56`, `server.ts:182-183`, `routes/index.js:360` |

The pattern is that a rule fires on one spelling of a weakness and not the next. Hardcoded
secrets are found in `config/env/development.js` and missed two files away in `config/env/all.js`;
weak password hashing is found as `md5(password.encode())` in pygoat and missed in
`app/data/user-dao.js`. A maintainer who read this review and concluded the file was clean would
be wrong about half the time.

## Findings with nowhere to go

This is the thing a first user meets first, and it is worth stating separately because it changed
how this trial had to be run.

The first pull request on each corpus repository appended its trailing comment at the end of the
file rather than on the vulnerable line. On nodejs-goof the action reported **6 findings, 5 of them
critical, and posted no inline comment at all**: the review body said "Mitig8it - 6 findings
detected" with a severity table, the check said "6 critical/high findings", and there was nothing
anywhere naming a file or a line. pygoat reported 27 findings the same way, nodegoat 5.

The behaviour is deliberate and documented in `action/orchestrator/run.py`: GitHub will not accept
an inline comment on a line the pull request did not touch, and pointing at the nearest changed
line would point at the wrong code. But the review as published gives a maintainer a count of
critical findings and no way to act on it, and no sentence explaining why. The pull requests in
this trial were rebuilt to touch the labelled lines themselves, which is the only reason there is
anything below to read.

It does not go away on a realistic diff. Across the rebuilt pull requests the action reported 93
runtime findings and posted 65 comments; 28 findings, including 12 on pygoat alone, exist only as
a number.

## What a first user would find confusing or wrong

Ordered by how much it costs the reader.

**1. A fix is never a suggestion block.** The action produced one fix in the whole trial
(pygoat `pygoat/settings.py:25`, a Django `SECRET_KEY` literal) and rendered it as a fenced diff
with the line "Shown as a diff: the fix cannot be expressed as a line replacement." It is a
one-line replacement. `fix_sections` in `action/orchestrator/remediation.py:282-313` fills
`unified_diff` and never fills `hunk`, and `suggestionFor` at
`services/github-service/src/services/githubInternalOperations.js:802` returns the
`no_line_change` reason (line 792) whenever `hunk` is absent. So the action cannot emit a suggestion block at
all, while `action/README.md` says "A fix arrives as a GitHub suggestion block under the finding it
repairs" and `action/action.yml` says fixes "are posted as GitHub suggestion blocks, which apply
only when a human clicks Commit suggestion". *Fix:* build `hunk` from the candidate's change in
`action/orchestrator/remediation.py`; until then, correct the two documents.

**2. Findings counted but never shown.** 28 of 93 findings produced no comment and no location.
*Fix:* list the unanchored findings in the review body as `path:line` with their severity, and say
they are not inline because the pull request does not touch those lines. `action/orchestrator/run.py`
builds the review payload; the body is rendered in
`services/github-service/src/services/githubInternalOperations.js`.

**3. Three different numbers for one review.** On pygoat the check title says "32 critical/high
findings", the check summary underneath it says "Mitig8it found 37 runtime findings", the review
body says "Mitig8it - 37 findings detected", and 16 comments exist on the diff. Each number is
arithmetically explicable (32 is critical plus high) and no two of them agree. *Fix:* one total
everywhere, with the breakdown beside it, in `action/orchestrator/run.py`.

**4. Two thirds of comments say the same sentence three times.** 40 of 65. For example the whole
body of `views/admin.ejs:17` is the sentence "EJS unescaped output tag. `<%-` writes raw HTML; use
`<%=` so the value is escaped" as the bold title, again as the description, and a third time after
"Remediation:". `render_finding_comment` at `action/orchestrator/run.py:219-265` appends
description and remediation unconditionally, and the OpenGrep rules set all three fields to the
rule message. *Fix:* skip a field that repeats the title.

**5. One GitHub review event per comment.** juice-shop's pull request shows 28 "github-actions
reviewed" entries in its timeline for 26 comments, because each inline comment is posted through
its own API call. It also makes publishing the slowest phase of the job. *Fix:* post the comments
as a single review with a `comments` array, replacing the per-finding `postInlineComment` loop at
`action/publisher/publish.js:296-307`.

**6. Duplicate comments on one line.** Four pairs: pygoat `introduction/mitre.py:161` and
`introduction/views.py:1026` each carry a critical "Password hashed with weak algorithm" and a
medium "Weak cryptographic hash used for security context" for the same `md5(password.encode())`;
juice-shop `routes/fileUpload.ts:109` and `routes/vulnCodeSnippet.ts:90` each carry two.
*Fix:* collapse findings sharing path, line and weakness family, keeping the highest severity, in
`build_inline_comments` at `action/orchestrator/run.py:103`.

**7. The one false positive is in a docstring.** flask `src/flask/views.py:158` is flagged
"Potential open redirect" on `return redirect(url_for("counter"))`, which is inside a
`.. code-block:: python` example in the `MethodView` docstring and redirects to a hard-coded
endpoint. It is not user input and it is not executable code. The prose-scope fix recorded in
`docs/validation/real-repo-replay-2026-09.md` keeps rules off documentation *files*; it does not
keep them out of documentation *regions*. *Fix:* extend the prose scope to Python docstrings and
the code blocks inside them, in the analysis service's prose scope (the module covered by
`tests/test_prose_path_scope.py`).

**8. The check is always neutral.** All 26 runs concluded `neutral`, including the five where
there was nothing to report. A repository with a clean review and a repository with 22 critical
findings both show a grey check; only the title distinguishes them. *Fix:* conclude `success` when
nothing blocking was found and keep `neutral` for findings held back by `fail-on: none`, in
`action/orchestrator/run.py`.

**9. "1 runtime findings".** The summary is not pluralised, and "runtime finding" is internal
vocabulary: nothing tells a first user that it means "not in test code". *Fix:* pluralise and say
"findings outside test code", in `action/orchestrator/run.py`.

**10. The repair path cannot verify JavaScript inside the action image.** One run logged, at
ERROR, "the sandbox test harness needs Node features this runtime does not provide:
module.stripTypeScriptTypes, module.registerHooks, --experimental-strip-types,
--disable-warning=ExperimentalWarning. `node` here reports v20.20.2; the supported runtime is the
one services/remediation-service/Dockerfile pins in ARG NODE_VERSION." Zero fixes were produced on
any of the four JavaScript or TypeScript repositories, including findings in the supported
`command_arguments` and `path_containment` families. *Fix:* pin the same `NODE_VERSION` in
`action/Dockerfile` as `services/remediation-service/Dockerfile`.

**11. A 403 in the log on every run.** `HTTP Request: GET https://api.github.com/user "HTTP/1.1 403
Forbidden"` is logged at INFO on every run. It is harmless (a `GITHUB_TOKEN` has no user
identity) but it is the only status code in the log and it looks like the failure a reader is
scanning for. *Fix:* expect the 403 and do not log it, in `action/publisher/tokenProvider.js`.

**12. "Files in scope" counts things nobody reviewed, and exclusions are never reported.** The
clean repositories report 12 files in scope on the second run: ten source files, the workflow YAML
the pull request adds, and the README the second commit touched. Nothing says which files were
dropped or why. `action/README.md` says "The check summary says how many files were excluded", but
`excluded_file_count` at `action/orchestrator/run.py:475` only counts `.mitig8it.yml` matches, so
with no config file the line never appears. *Fix:* report changed, reviewed and dropped with
reasons, or correct the README.

**13. One anchor is off by a line.** nodejs-goof `app.js:42` reads "Session signing secret is a
literal. Read it from process.env instead" while pointing at `app.use(session({`; the literal is on
line 43. *Fix:* anchor `cwe-798.js-session-secret-literal` on the property, in the rule.

**14. A retired thread is collapsed but not resolved.** After a real fix the log said "0 resolved,
1 minimized" and the thread shows `isResolved=false`, `isOutdated=true`. The conversation still
counts as unresolved on the pull request, so a repository with "all conversations must be resolved"
is now blocked by a finding the author fixed. *Fix:* resolve as well as minimize, in the
reconciliation in `action/publisher/publish.js`.

Nothing in any of the 26 run logs was an error in the action's own execution: all 26 jobs concluded
`success`, the permission check passed on every repository, and the only ERROR line in any log is
item 10.

## Re-running converges

The second commit changed one README line on all ten repositories.

* No duplicates. Comment counts were identical before and after on all ten: 4, 26, 16, 8, 10, 0, 0,
  1, 0, 0.
* Nothing was rewritten. The comment IDs are the same objects and their `updated_at` timestamps did
  not move, so the second run recognised that nothing had changed and wrote nothing.
* The summary line is in every run: `Review threads: N seen, N with our marker, 0 resolved,
  0 minimized, 0 failed.`, with `seen` and `ours` equal on all ten, which is what says the marker
  matching is working.
* Collapsing works. The second commit retires nothing because nothing was fixed, so a third commit
  on nodejs-goof changed `<%- redirectPage %>` to `<%= redirectPage %>`. Findings fell from 9 to 8,
  no new comment was posted, and the log read `Review threads: 8 seen, 8 with our marker, 0
  resolved, 1 minimized, 0 failed.` The thread is minimized as outdated but still unresolved, which
  is item 14 above.

## Would I keep it installed

On the five intentionally vulnerable applications I would keep it without hesitation: it found real
command injection, real SQL and NoSQL injection, real deserialization sinks and real hardcoded
secrets, and in 64 comments it never once pointed at code that was not already labelled vulnerable,
which is the rarest property a tool like this can have. On the five mature libraries I would keep it
too, because it is genuinely quiet, two findings in fifty files with one of them a false positive is
a cost a maintainer can absorb, and a neutral check costs nothing at merge time. What I would not do
on any of the ten is treat a clean review as evidence: recall on lines known to be vulnerable is
53%, the counts in the summary do not match the comments on the diff, and the one fix it offered
could not be applied with a click, so it is worth installing as a second pair of eyes and worth
nothing as a gate.

## Repositories to delete

Ten private repositories under `nebullii`, all disposable:

* `nebullii/mitig8it-trial-nodegoat`
* `nebullii/mitig8it-trial-juice-shop`
* `nebullii/mitig8it-trial-pygoat`
* `nebullii/mitig8it-trial-nodejs-goof`
* `nebullii/mitig8it-trial-dvna`
* `nebullii/mitig8it-trial-express`
* `nebullii/mitig8it-trial-fastify`
* `nebullii/mitig8it-trial-flask`
* `nebullii/mitig8it-trial-got`
* `nebullii/mitig8it-trial-sequelize`

```sh
for r in nodegoat juice-shop pygoat nodejs-goof dvna express fastify flask got sequelize; do
  gh repo delete "nebullii/mitig8it-trial-$r" --yes
done
```

`gh repo delete` needs the `delete_repo` scope, which the token used for this trial does not carry:
`gh auth refresh -h github.com -s delete_repo` first, or delete them from the settings page.

## Appendix: every comment posted

Suggestion and Verified are what the comment actually carried. The verdict is mine, reading the
comment against the code.

| Rule | Severity | CWE | Path and line | Suggestion | Verified | Verdict | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cwe-95.eval-injection` | critical | CWE-95 | `app/routes/contributions.js:32` | no | no | true positive | `eval(req.body.preTax)` evaluates a request field. |
| `cwe-601.js-redirect-request-value` | critical | CWE-601 | `app/routes/index.js:72` | no | no | true positive | `res.redirect(req.query.url)` with no allowlist. |
| `secret.hardcoded.credential` | critical | CWE-798 | `config/env/development.js:6` | no | no | true positive | A ZAP API key literal in a checked-in config. |
| `cwe-79.js-template-autoescape-disabled` | critical | CWE-79 | `server.js:137` | no | no | true positive | `autoescape: false` turns escaping off for every template. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/about/about.component.ts:120` | no | no | true positive | `bypassSecurityTrustHtml` on a user-supplied feedback comment. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/administration/administration.component.ts:74` | no | no | true positive | User email interpolated into trusted HTML. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/administration/administration.component.ts:92` | no | no | true positive | Feedback comment marked trusted unsanitized. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/last-login-ip/last-login-ip.component.ts:40` | no | no | true positive | A header-controlled IP interpolated into trusted HTML. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/search-result/search-result.component.ts:111` | no | no | true positive | The line carries juice-shop's own `vuln-line` marker. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/search-result/search-result.component.ts:144` | no | no | true positive | The search query is marked trusted, the local XSS challenge. |
| `cwe-79.js-angular-bypass-security-trust` | critical | CWE-79 | `frontend/src/app/track-result/track-result.component.ts:49` | no | no | true positive | Order id interpolated into trusted HTML. |
| `cwe-798.hardcoded-secret-js` | critical | CWE-798 | `lib/insecurity.ts:21` | no | no | true positive | An RSA private key literal in the source. |
| `code.injection.eval` | critical | CWE-95 | `routes/b2bOrder.ts:23` | no | no | true positive | `vm.runInContext('safeEval(orderLinesData)')` on request data. |
| `code.injection.eval` | critical | CWE-95 | `routes/captcha.ts:22` | no | no | true positive | `eval(expression)` on a generated expression string. |
| `cwe-22.js-sendfile-request-path` | critical | CWE-22 | `routes/fileServer.ts:32` | no | no | true positive | `res.sendFile(path.resolve('ftp/', file))` with `file` from the request. |
| `code.injection.eval` | critical | CWE-95 | `routes/fileUpload.ts:109` | no | no | unsure | The script passed to `vm.runInContext` is a constant; the risk is the YAML, which the comment below already names. |
| `deserialize.untrusted_data` | critical | CWE-502 | `routes/fileUpload.ts:109` | no | no | true positive | `yaml.load` on uploaded data. |
| `cwe-22.js-sendfile-request-path` | critical | CWE-22 | `routes/keyServer.ts:14` | no | no | true positive | Request-chosen file served from `encryptionkeys/`. |
| `cwe-22.js-sendfile-request-path` | critical | CWE-22 | `routes/logfileServer.ts:14` | no | no | true positive | Request-chosen file served from `logs/`. |
| `cwe-22.js-sendfile-request-path` | critical | CWE-22 | `routes/quarantineServer.ts:14` | no | no | true positive | Request-chosen file served from `ftp/quarantine/`. |
| `cwe-89.sql-template-literal` | critical | CWE-89 | `routes/search.ts:23` | no | no | true positive | Search term interpolated into raw SQL, juice-shop's `vuln-line`. |
| `cwe-943.js-mongo-where-operator` | critical | CWE-943 | `routes/showProductReviews.ts:36` | no | no | true positive | `$where: 'this.product == ' + id` runs JavaScript server side. |
| `cwe-943.js-mongo-where-operator` | critical | CWE-943 | `routes/trackOrder.ts:18` | no | no | true positive | `$where` with the order id interpolated. |
| `code.injection.eval` | critical | CWE-95 | `routes/userProfile.ts:65` | no | no | true positive | `eval(code)` where `code` comes from the profile. |
| `deserialize.untrusted_data` | critical | CWE-502 | `routes/vulnCodeSnippet.ts:90` | no | no | true positive | `yaml.load` on a file chosen by a request key. |
| `cwe-918.ssrf-axios` | high | CWE-918 | `routes/profileImageUrlUpload.ts:24` | no | no | true positive | `fetch(url)` with the URL from the profile form. |
| `cwe-22.path-traversal-fs` | high | CWE-22 | `routes/vulnCodeSnippet.ts:90` | no | no | true positive | The same line concatenates a request key into a read path. |
| `crypto.insufficient_entropy` | medium | CWE-330 | `lib/insecurity.ts:53` | no | no | true positive | `Math.random()` used as a JWT secret. |
| `crypto.insufficient_entropy` | medium | CWE-330 | `routes/captcha.ts:14` | no | no | true positive | `Math.random()` generates the CAPTCHA, a security control. |
| `redirect.open` | medium | CWE-601 | `routes/redirect.ts:18` | no | no | true positive | `res.redirect(toUrl)` on a request-supplied target. |
| `cwe-327.weak-hash-password` | critical | CWE-916 | `introduction/mitre.py:161` | no | no | true positive | `md5(password.encode())` as the password hash. |
| `code.injection.eval` | critical | CWE-95 | `introduction/mitre.py:218` | no | no | true positive | `eval(expression)` on lab input. |
| `cmd.injection.shell_true` | critical | CWE-78 | `introduction/mitre.py:233` | no | no | true positive | `subprocess.Popen(command, shell=True)`. |
| `cwe-502.pickle-loads` | critical | CWE-502 | `introduction/views.py:214` | no | no | true positive | `pickle.loads(token)` on a cookie value. |
| `code.injection.eval` | critical | CWE-95 | `introduction/views.py:460` | no | no | true positive | `eval(val)` on request input. |
| `cwe-338.py-random-module-secret` | critical | CWE-338 | `introduction/views.py:496` | no | no | true positive | `randint` generates a one-time password. |
| `cwe-502.yaml-unsafe-load` | critical | CWE-502 | `introduction/views.py:560` | no | no | true positive | `yaml.load(file, yaml.Loader)` allows object construction. |
| `cwe-327.weak-hash-password` | critical | CWE-916 | `introduction/views.py:1026` | no | no | true positive | The second `md5` password hash. |
| `cwe-798.py-framework-secret-key-literal` | critical | CWE-798 | `pygoat/settings.py:25` | no (diff block) | yes | true positive | Django `SECRET_KEY` literal; the only fix in the trial, and it could not be clicked. |
| `cwe-352.py-csrf-exempt` | high | CWE-352 | `introduction/mitre.py:177` | no | no | true positive | `@csrf_exempt` on a state-changing handler. |
| `sql.injection.raw_query` | high | CWE-89 | `introduction/views.py:158` | no | no | true positive | Login SQL built by concatenating name and password. |
| `ssrf.untrusted_url_fetch` | high | CWE-918 | `introduction/views.py:963` | no | no | true positive | `requests.get(url)` on a user-supplied URL. |
| `crypto.weak.hash` | medium | CWE-327 | `introduction/mitre.py:161` | no | no | true positive | Correct, but a duplicate of the critical comment on the same line. |
| `session.insecure_cookie` | medium | CWE-614 | `introduction/views.py:291` | no | no | true positive | `set_cookie(..., samesite=None, secure=False)`. |
| `crypto.weak.hash` | medium | CWE-327 | `introduction/views.py:1026` | no | no | true positive | Correct, but a duplicate of the critical comment on the same line. |
| `config.debug_enabled` | medium | CWE-489 | `pygoat/settings.py:30` | no | no | true positive | `DEBUG = True` in the committed settings. |
| `cwe-798.js-session-secret-literal` | critical | CWE-798 | `app.js:42` | no | no | true positive | The session secret is a literal, though anchored one line above it. |
| `cwe-798.js-credential-config-key` | critical | CWE-798 | `mongoose-db.js:52` | no | no | true positive | An admin password literal in the seed; "config value" is the wrong noun. |
| `cwe-78.child-process-exec` | critical | CWE-78 | `routes/index.js:174` | no | no | true positive | `exec('identify ' + url)` concatenates request input into a shell. |
| `cwe-79.tpl-ejs-unescaped-output` | critical | CWE-79 | `views/admin.ejs:17` | no | no | true positive | `<%- redirectPage %>` writes raw HTML into an input value. |
| `cwe-79.tpl-ejs-unescaped-output` | critical | CWE-79 | `views/index.ejs:20` | no | no | true positive | `<%- marked(todo.content) %>` writes stored content raw. |
| `nosql.injection` | high | CWE-943 | `routes/index.js:52` | no | no | true positive | Login query passes `req.body` fields straight to `User.find`. |
| `cwe-22.js-archive-entry-write` | high | CWE-22 | `routes/index.js:270` | no | no | true positive | `zip.extractAllTo` on an uploaded archive, no entry check. |
| `crypto.insufficient_entropy` | medium | CWE-330 | `routes/index.js:330` | no | no | true positive | `Math.random().toString(32)` is the admin password. |
| `cwe-78.child-process-exec` | critical | CWE-78 | `core/appHandler.js:39` | no | no | true positive | `exec('ping -c 2 ' + req.body.address)`. |
| `cwe-601.js-redirect-request-value` | critical | CWE-601 | `core/appHandler.js:188` | no | no | true positive | `res.redirect(req.query.url)`. |
| `code.injection.eval` | critical | CWE-95 | `core/appHandler.js:197` | no | no | true positive | `mathjs.eval(req.body.eqn)` evaluates request input. |
| `cwe-502.js-node-serialize-unserialize` | critical | CWE-502 | `core/appHandler.js:218` | no | no | true positive | `serialize.unserialize` on an uploaded file runs embedded functions. |
| `cwe-79.tpl-inline-script-inner-html` | critical | CWE-79 | `views/app/adminusers.ejs:40` | no | no | true positive | `innerHTML` assignment from server data in an inline script. |
| `cwe-79.tpl-ejs-unescaped-output` | critical | CWE-79 | `views/app/products.ejs:20` | no | no | true positive | `<%- output.searchTerm %>` reflects the search term raw. |
| `cwe-79.tpl-ejs-unescaped-output` | critical | CWE-79 | `views/app/products.ejs:49` | no | no | true positive | `<%- output.products[i].id %>` writes stored data raw. |
| `sql.injection.raw_query` | high | CWE-89 | `core/appHandler.js:10` | no | no | true positive | Login SQL concatenates `req.body.login`. |
| `cwe-614.insecure-cookie` | high | CWE-614 | `server.js:27` | no | no | true positive | `cookie: { secure: false }` on the session. |
| `crypto.weak.hash` | medium | CWE-327 | `core/authHandler.js:49` | no | no | true positive | `md5(req.query.login)` compared as a reset token. |
| `redirect.open` | medium | CWE-601 | `src/flask/views.py:158` | no | no | false positive | Inside a docstring `code-block`, redirecting to a hard-coded `url_for("counter")`. |
