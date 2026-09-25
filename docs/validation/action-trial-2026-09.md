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

## After the trial fixes

Everything below was changed on `fix/action-trial-findings` in response to the fourteen items
above. Nothing here has been re-run against a real repository: these are the changes and what a
re-run would have to show for each of them to count as confirmed.

### What changed

**1. A fix can be a suggestion block.** `action/orchestrator/inline_fixes.py` is `computeRegions`
and `primaryRegion` from `services/api-service/src/services/remediationInlineFixes.js`, ported
rather than re-derived, and `fix_sections` fills `hunk` and `extra_hunks` from it. The
`not_suggestable_reason` values follow the App's order of precedence, so a fix that cannot be a
suggestion gives the same sentence in both products. `proof` and `evidence` are read from the keys
the App reads: `evidence.summary` is a list, and stringifying it into `proof` put a Python repr
into the pull request. `action/tests/test_inline_fix_parity.py` executes the Node functions and
compares them against the port on the same inputs, including the pygoat `SECRET_KEY` shape and a
two-region fix.

**2. Findings with nowhere to go are named.** The review body carries a section, **Findings on
lines this pull request did not change**, listing severity, rule, path and line with a permalink
to the head sha, and the check summary counts them separately. A finding past the inline cap is
listed there too. The App dropped them the same way and is fixed with the same heading and the
same row cap, compared by `test_node_parity.py`.

**3. One set of numbers.** `review_totals` in `action/orchestrator/run.py` is the only arithmetic;
it travels in the publish request as `totals` and the check title, the check summary and the
review body render it rather than recompute it. The title states the same total the other two do,
with the blocking share beside it rather than in place of it.

**4. No sentence three times.** A description that repeats the title, or a remediation that
repeats the description, is dropped.

**5. One review per run.** New inline comments travel inside the review's `comments` array with
one COMMENT event. Which comments are new is answered by the review-thread survey the stale-thread
reconciliation already performs, so it costs no extra request; a comment that exists and would be
written identically is skipped outright. On the fake-server test, 26 comments at 500 ms per round
trip: publishing falls from 27.2 s to 1.1 s and the service calls from 28 to 2. At 60 ms per round
trip, 3.42 s to 0.25 s.

**6. Duplicates folded at the source.** `canonicalize_internal_type` now names a weak hash of a
credential `weak_password_hash` whichever rule found it, using the vocabulary
`cwe-327.weak-hash-password` uses in its own metavariable regex, so the clusterer folds it and
keeps the worse severity. A weak hash of something that is not a credential, such as dvna's
`md5(req.query.login)`, keeps `weak_cipher_algorithm`. The two findings on
`routes/fileUpload.ts:109` and `routes/vulnCodeSnippet.ts:90` are genuinely different weaknesses
and still produce two comments, which is the intended behaviour.

**7. The docstring false positive.** The comment stripper already understood Python docstrings;
what it could not do was know that a hunk began inside one, because it scanned each hunk alone.
Given the file at the head revision, which both products already fetch for the semgrep tier, it
classifies the whole file and each line takes its own mask, falling back to the per-hunk scan
whenever the file's text at that line number is not exactly the patch's. The flask case is in
`benchmarks/tier1-precision/cases.json` as `fp.redirect.docstring-code-block.flask`.

**8. The check conclusion.** `success` when nothing was found or nothing met `fail-on`, `neutral`
when there is something to report and `fail-on` is `none`, `failure` when `fail-on` is met.

**9. Plurals and vocabulary.** "1 runtime findings" is gone, and so is "runtime finding": the
check summary says "findings outside test code".

**10. Node in the image.** `action/Dockerfile` pins the remediation service's `NODE_VERSION` and
both SHA-256 arguments, repeats that image's capability probe so a wrong pin fails the build, and
`test_action_definition.py` compares the two Dockerfiles. `test_node_runtime.py` asks the
interpreter on PATH for the three features, which is what the in-image run proves. The host CI job
moves to Node 22 so it cannot pass what the image fails.

**11. The 403.** The `GET /user` call stays, because a repository that passes an App token does
get a login from it, but the transport logger is quiet for that one call.

**12. Scope.** `scope_report` separates analysed, excluded, skipped and vendored, and the check
summary states all four. "Skipped" is not called unreviewed: the regex tier still reads those
patches.

**13. The anchor.** `cwe-798.js-session-secret-literal` matches the `secret:` property rather than
the `session({ ... })` call that contains it. Measured against a synthetic file, the reported line
moves from 5 to 6 and from 12 to 14.

**14. Stale threads.** Resolution is tried first; when the token may not resolve, the action
deletes its own comment through github-service's `retireInlineComments` rather than minimizing it,
because a minimized thread is still an unresolved conversation. A comment carrying a published fix
is kept. The summary line replaces `minimized` with `retired` and `kept for a published fix`.

Not changed: recall. The 53 labelled lines the review missed are missed for the same reasons, and
the table in "Precision and recall" still describes what the deterministic tiers cover.

### What a re-run would need to confirm

The trial's own method is the method: ten disposable copies, one pull request each that touches
the labelled lines, then a second commit that changes one README line, then a third that fixes one
finding for real. Against that, a re-run confirms these fixes if it shows:

* **A clickable fix.** pygoat `pygoat/settings.py:25` renders as a suggestion block with the
  Verified line, not as a fenced diff. This is the one number the trial could not produce at all:
  suggestion blocks went from 0 to 1 in the table, and a re-run should move that column.
* **Fixes on the JavaScript repositories.** Zero were produced on nodegoat, juice-shop,
  nodejs-goof and dvna. Any number above zero, on findings in the `command_arguments` or
  `path_containment` families, is what says the Node pin took effect; the absence of the
  `stripTypeScriptTypes` ERROR line is the weaker version of the same evidence.
* **Every finding accounted for.** 93 runtime findings and 65 comments, with the remaining 28
  named in the review bodies with a path, a line and a working permalink. The counts on the check
  title, the check summary and the review body agree, on pygoat especially, where four numbers
  disagreed.
* **One review per run.** juice-shop's timeline shows one "github-actions reviewed" entry per run
  rather than 28 for 26 comments, and the publishing phase of its job is a fraction of the 39
  seconds it took. The fake-server measurement predicts roughly a 25 to 1 reduction in API calls;
  the real number depends on the runner's latency to api.github.com.
* **A converged re-run writing nothing.** Comment counts identical, `updated_at` unmoved, and the
  publisher reporting `unchanged` equal to the comment count with `posted` and `edited` at zero.
* **A retired thread actually gone.** The third commit on nodejs-goof fixed `<%- redirectPage %>`.
  The thread for that finding should no longer exist on the pull request, and the log line should
  read `0 resolved, 1 retired, 0 kept for a published fix, 0 failed` rather than `0 resolved,
  1 minimized`.
* **One comment on the md5 lines.** pygoat `introduction/mitre.py:161` and
  `introduction/views.py:1026` carry one comment each, critical, not two.
* **No comment on `src/flask/views.py:158`.** flask's only finding was the trial's only false
  positive; the repository should now come back with none. Note that this depends on the file
  content being fetched, which it is for `.py`, so a re-run that still reports it means the
  fallback path was taken and the reason is worth finding.
* **A green check on the quiet repositories.** fastify, got and sequelize found nothing and should
  conclude `success`. express and flask, with one medium each under `fail-on: none`, stay
  `neutral` if they still report anything at all.
* **Honest file counts.** The clean repositories reported 12 files in scope; they should now
  report 10 analysed and 2 read as a patch only, naming the workflow YAML and the README as the
  two.
* **A quiet log.** No `GET /user` 403, and no status code at all in a healthy run.

Two things a re-run cannot confirm on its own. The one-review timing depends on the runner's
network, so the fake-server numbers are the controlled measurement and the trial number is the
sanity check. And the suggestion geometry for a multi-region fix has no example in this corpus:
every fix the trial produced was a single line, so a two-region fix has only the parity test
behind it until one appears in a real repository.

## Re-run on the fixed Action

The same ten private repositories, the same pull requests, one commit each changing the workflow
to `uses: aicodesentry/mitig8it/action@fix/action-trial-findings`. Then a second commit changing
one README line, and a third commit on two of them. Twenty-three runs, all `success`.

The previous section listed what a re-run would have to show. Eleven of the fourteen fixes are
confirmed, two are half done, and one cannot be confirmed because nothing in this corpus exercises
it. Against that, the re-run found three regressions, three rough edges in the surfaces the fixes
added, and two pre-existing false positives that the new listing made visible for the first time.

Two deviations from the brief, both forced by what the fixed Action produced. The suggestion
block was applied on **pygoat**, not nodejs-goof, because `pygoat/settings.py:25` is the only
suggestion block in the trial: no fix was produced on any JavaScript repository, so nodejs-goof
had nothing to click. nodejs-goof still got its third commit, fixing `views/index.ejs:20` by hand,
which is what tests thread retirement there. Neither commit went through GitHub's **Commit
suggestion** button, which `gh api` cannot press; the suggested text was written by hand, byte for
byte. The button would have added a `Co-authored-by:` trailer naming the comment's author, and
these commits have none. That is the only difference between them and a clicked suggestion.

### Before and after

Duration and build are the first run on each ref, which pays a cold layer cache both times; the
fix changes the Dockerfile, so the cache key changed and the first run on the fixed Action built
from scratch again. The README commit then built in 37 to 59 seconds.

| Repository | Findings before → after | Inline comments | Named, not inline | Suggestions | Verified | Check conclusion | Duration | Build | Recall |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- |
| nodegoat | 6 → 6 | 4 → 4 | 0 → 2 | 0 → 0 | 0 → 0 | neutral → neutral | 114s → 117s | 89s → 88s | 4/15 → 4/15 |
| juice-shop | 27 → 27 | 26 → 26 | 0 → 1 | 0 → 0 | 0 → 0 | neutral → neutral | 209s → 143s | 110s → 85s | 24/43 → 24/43 |
| pygoat | 37 → 33 | 16 → 13 | 0 → 20 | 0 → 1 | 1 → 1 | neutral → neutral | 137s → 140s | 85s → 112s | 14/25 → 13/25 |
| nodejs-goof | 9 → 8 | 8 → 7 | 0 → 1 | 0 → 0 | 0 → 0 | neutral → neutral | 130s → 151s | 99s → 108s | 8/16 → 8/16 |
| dvna | 12 → 12 | 10 → 11 | 0 → 1 | 0 → 0 | 0 → 0 | neutral → neutral | 126s → 126s | 88s → 85s | 10/14 → 11/14 |
| express | 1 → 1 | 0 → 0 | 0 → 1 | 0 → 0 | 0 → 0 | neutral → neutral | 110s → 118s | 89s → 86s | not labelled |
| fastify | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | neutral → **success** | 111s → 114s | 89s → 81s | not labelled |
| flask | 1 → **0** | 1 → **0** | 0 → 0 | 0 → 0 | 0 → 0 | neutral → **success** | 113s → 130s | 93s → 86s | not labelled |
| got | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | neutral → **success** | 155s → 129s | 111s → 87s | not labelled |
| sequelize | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | neutral → **success** | 127s → 108s | 103s → 80s | not labelled |
| **total** | **93 → 87** | **65 → 61** | **0 → 26** | **0 → 1** | **1 → 1** | | | | **60/113 → 60/113** |

Adjudication of the 61 inline comments: 60 true positives, 0 false positives, 1 unsure, the same
`routes/fileUpload.ts:109` as before. The image is 772 MB, up from 745 MB.

The two counts that matter most both check out on every repository: **inline plus named equals the
summary total** on all ten (6=4+2, 27=26+1, 33=13+20, 8=7+1, 12=11+1, 1=0+1, and 0 for the four
quiet ones), and **each run adds exactly one review event** to the pull request timeline, against
26 for 26 comments before.

nodejs-goof's before column is not quite like for like: the first trial ended by fixing
`views/admin.ejs:17`, so this re-run started one finding down.

### What is now right

**Item 1, the suggestion block.** pygoat `pygoat/settings.py:25` renders as a real
` ```suggestion ` block containing `SECRET_KEY = os.environ["SECRET_KEY"]`, with the Verified line
underneath and the evidence and limitations in a `<details>`. It applied cleanly. This is the
column that was 0 out of 1 before and is now 1 out of 1.

**Item 2, findings with nowhere to go.** Every one of the 26 is named, with severity, rule and a
permalink to the reviewed sha. I opened four of the permalinks and they resolve. This turned 28
invisible numbers into 26 readable rows and immediately paid for itself: nodejs-goof
`app.js:84`, `console.log('token: ' + token)` on a line holding a real secret, was invisible
before and is a true positive.

**Item 3, one set of numbers.** The check title, the check summary and the review body now agree
everywhere. pygoat, which showed 32, 37 and 37 with 16 comments, now reads "33 findings, 31
critical or high" on the title and the same 33 on both the summary and the body.

**Item 5, one review per run.** Confirmed on all ten and on all three rounds. juice-shop's
publishing phase is no longer visible as a distinct cost in the job: its whole job fell from 209s
to 143s with the build about the same.

**Item 6, the md5 duplicates.** pygoat `introduction/mitre.py:161` and `introduction/views.py:1026`
now carry one critical comment each, with `Supporting detections: crypto.weak.hash, ...` folded
into it. dvna's `md5(req.query.login)` correctly kept its own `crypto.weak.hash` comment, which is
the distinction the fix claimed to draw.

**Item 7, the docstring false positive.** flask reports nothing at all. It was the trial's only
false positive and it is gone.

**Item 8, the check conclusion.** fastify, flask, got and sequelize now conclude `success` with
the title "No security findings". express stays `neutral` on one medium, which is the stated rule.

**Item 11, the 403.** No `GET /user` 403, and no 4xx or 5xx status in any of the thirty logs.

**Item 12, scope.** Every run reports "N files analysed, 2 read as a patch only (the scanner has
no deep rules for those file types)".

**Item 13, the anchor.** `cwe-798.js-session-secret-literal` moved from the `app.use(session({`
line to the `secret:` property: nodejs-goof `app.js` went from 42 to 43, and on dvna it now fires
at `server.js:24` where it did not fire at all before. That is a labelled line the first trial
missed, and it is the one recall gain in the whole re-run.

**Item 14, stale threads.** Deleted, not minimized, and counted. nodejs-goof's re-run after the
hand fix logged `7 seen, 7 with our marker, 0 resolved, 1 retired, 0 kept for a published fix, 0
failed`, and the `views/index.ejs:20` thread is gone from the pull request rather than sitting
collapsed and unresolved. flask's old false-positive comment was retired the same way on the first
fixed run.

**Convergence, on nine of ten.** The README-only commit created nothing, edited nothing and
deleted nothing on nodegoat, juice-shop, nodejs-goof, dvna, express, fastify, flask, got and
sequelize.

### What is still wrong

**1. A true positive was lost.** pygoat `introduction/views.py:963`,
`ssrf.untrusted_url_fetch`, CWE-918, on `response = requests.get(url)` two lines below
`url = request.POST["url"]`. It is a corpus-labelled line, the previous Action reported it, and the
fixed Action does not: its comment was deleted, it is not in the "did not change" list, and the
total fell accordingly. I eliminated the obvious suspect: running `parse_patch_entries` from this
branch over the real patch and the real head file gives byte-identical `scan_text` for line 963
with and without the head content, so the new whole-file comment mask is not blanking it. The
cause is elsewhere in the branch and is worth finding before merge, because this is the only
labelled line the fixes cost. *Fix:* start from `services/analysis-service/src/main.py`
`pattern_findings`, which now passes `content` into every rule's scan options, and from the
clustering that `canonicalize_internal_type` feeds.

**2. The findings are not stable between runs on identical code.** pygoat did not converge: the
README-only commit **deleted** the `introduction/views.py:291` comment and **rewrote** two others.
The rewrites say why. `pygoat/settings.py:25` changed its fix marker from
`sha256:fd7f59c4...` to `sha256:ab437627...` and its evidence digest from `sha256:1c59d` to
`sha256:d6075` with the suggestion text identical, so a fix comment is rewritten on every run
forever. `introduction/views.py:1026` lost `auth.weak_password_hash` from its supporting
detections between two runs over the same file. Together with the lost SSRF finding, that is three
results that vary run to run, all in the one repository with a large Python file and the only fix.
*Fix:* make the fix digest a function of the fix, not of the run, in the remediation evidence
that `action/orchestrator/remediation.py` reads; sort the supporting-detection list; and log per
file whether head content was used, so a fallback is visible rather than silent.

**3. The thread survey under-counts on the run that changes most.** pygoat's first fixed run
logged `12 seen, 12 with our marker, 0 resolved, 0 retired, 0 kept for a published fix, 0 failed`
while 16 of its own comments existed at the start of the run and 4 of them disappeared during it.
Every other repository's numbers reconcile exactly. The one line a maintainer has to trust about
what happened to their threads said nothing happened. *Fix:* count the comments removed by a
fingerprint change under `retired` too, in the reconciliation in `action/publisher/publish.js`.

**4. Item 4 is half done.** The duplicated description is gone; the duplicated remediation is not.
40 of 61 comments still end with `Remediation:` followed by the exact words of the bold title. The
dedupe compares the remediation against the description, and when the description has already been
dropped for repeating the title there is nothing left for it to match. *Fix:* compare the
remediation against the title as well, in `render_finding_comment` in
`action/orchestrator/run.py`.

**5. A new grammar bug in the new sentence.** "1 are on lines this pull request did not change"
appears on juice-shop, nodejs-goof, dvna and express, four of the ten. The plural fix reached
"1 finding" and not this. *Fix:* same sentence builder in `action/orchestrator/run.py`.

**6. The new section is not folded the way the comments are.** 17 of pygoat's 20 rows are
`opengrep.cwe-352.py-csrf-exempt`, one per decorator. The fold that collapsed the md5 pair does not
apply here, so the section that exists to make findings readable is, on the repository with the
most of them, one rule repeated seventeen times. *Fix:* roll identical rules up to one row naming
the line count, in the review body builder.

**7. The anchor fix reached one rule and not its siblings.** Three rows point at the enclosing
call rather than the property: nodegoat `config/env/all.js:5` and `config/env/development.js:1`
(both `module.exports = {`, where the credentials are on lines 8, 9 and 6) and dvna `server.js:23`
(`app.use(session({`, where the insecure cookie is on line 27). Two of those also duplicate an
inline comment that has the line right, so the same weakness is reported twice at two different
line numbers, which is why the duplicate fold does not catch them. *Fix:* apply the item 13 change
to `cwe-798.js-credential-config-key` and `cwe-614.js-session-cookie-insecure`.

**8. Two false positives are now visible that were invisible before.** express
`lib/response.js:814` is `redirect.open` on `res.redirect = function redirect(url) {`, which is
express's own definition of the redirect primitive. juice-shop `lib/xml.ts:38` is
`code.injection.eval` on `vm.runInContext('libxml2.XmlDocument.fromString(data, { option })', ...)`,
whose script is a constant string; three lines above it, the real XXE that the corpus labels at
`lib/xml.ts:35` is still missed. Naming the hidden findings did not create these, it revealed
them, and the honest reading of the trial's precision is now 60 true positives and 1 unsure on the
diff, plus 2 false positives among the 26 named elsewhere. *Fix:* exclude a `vm.runInContext` whose
script argument is a literal from `code.injection.eval`, and a redirect helper's own definition
from `redirect.open`.

**9. Item 10 cannot be confirmed.** No `stripTypeScriptTypes` ERROR line appears in any log, which
is the weak half of the evidence. The strong half is missing: still **zero fixes on all four
JavaScript and TypeScript repositories**, including findings in the `command_arguments` family
(nodejs-goof `routes/index.js:174`, dvna `core/appHandler.js:39`) and `path_containment`
(nodejs-goof `routes/index.js:270`). The Node pin may well be right; nothing in this trial
exercises it. *Fix:* none proposed. Point the repair engine at one of those four findings in CI
and assert a candidate comes out, or the pin stays unverified.

**10. A fix that was applied still reads as an open critical finding.** After the suggestion was
committed, pygoat logged `0 resolved, 0 retired, 1 kept for a published fix` and the finding left
the count, 33 to 31. The comment stays, by design, but it is unchanged: a critical header, "Framework
signing key is a literal. Read it from the environment", and a suggestion block whose content is
now identical to the line it sits on. A maintainer reading that pull request sees an open critical
finding on `SECRET_KEY = os.environ["SECRET_KEY"]`, and clicking Commit suggestion again would
produce an empty commit. Keeping the comment is right; keeping it word for word is not. *Fix:* when
a comment is kept for a published fix, replace its body with a line saying the fix was applied and
drop the suggestion block, in the retirement path in `action/publisher/publish.js`.

### Would I keep it installed now

**fastify, got, sequelize:** yes, without reservation. Three clean repositories, three green
checks, nothing posted, one review event per run, and a job that costs about a minute once the
layer cache is warm. There is nothing to weigh against it.

**flask, express:** yes. flask's only false positive is gone and it now passes green. express
reports one finding and, now that findings are named, I can see it is a false positive on
express's own `res.redirect`, which is a five-second dismissal rather than the unanswerable "1
finding" it used to be.

**nodegoat, juice-shop, dvna, nodejs-goof:** yes. 47 of the 48 comments on these four are true
positives and the 48th is the one I cannot call either way, the anchors are better than they were, stale threads now disappear instead of
lingering, and the findings that cannot be commented on are listed with working links. The
outstanding complaint is that none of them ever gets a fix, so the product is a very good reader
and not yet a writer on JavaScript.

**pygoat:** not yet, and it is the one repository where the fixes made things worse as well as
better. It is the only repository that produced a clickable fix, and it is also the one that lost
a true positive, that rewrites comments on a commit that changed only the README, and whose thread
summary did not describe what the run did to its own comments. Until findings are stable between
runs on identical code I would not want this posting to a repository I maintain, because a review
that changes its mind without the code changing teaches maintainers to stop reading it.

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
