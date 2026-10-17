# Authorization and IDOR by handler review, October 2026

The vulnerable corpus left broken authorization and IDOR out because the defect is an absence
and a line label cannot describe it. This document sets up the measurement that can: a model
reads one whole route handler, with its registration line and the middleware on it, and says
whether the authorization decision the handler needs is made. It adds 30 hand-labelled
handlers, a runner, and its tests.

**No number is reported here.** No provider key the analysis service reads
(`OPENAI_API_KEY`, `GEMINI_API_KEY`, `LLM_API_KEY`) was present when this was written, so the
live run has not happened. The section "Running it" gives the exact command. Nothing in the
product changed: no rule, no posting policy, no tier 1 or tier 2 decision.

## Why a line label cannot do this

`scripts/replay/score.py` joins a finding to a label when the path agrees and the line ranges
overlap within two lines. That works when the vulnerability is a sink on a line. In
`OWASP/NodeGoat`'s allocations handler the defect is that `req.params.userId` reaches the DAO
and nothing compares it to `req.session.userId`. There is no line for a missing comparison.
Labelling the nearest line, the DAO call, would reward any rule that flags DAO calls and
penalise any rule that reported the handler instead. The corpus document said this in "What
was deliberately left out", and it is also why `authz.missing_function_level` failed. It was a
line regex, and once its broken lookahead was removed it matched `.destroy(` and `.remove(`. On
real code every one of those was stream or socket teardown (see `docs/architecture/known-debt.md`,
"Quarantined tier 1 rules").

A handler is the smallest unit that can carry the label. Whether the control exists depends on
what the handler reads, what it writes, what it compares, and what middleware ran first. Each
case here therefore has a verdict and a missing control (`ownership_check`, `role_check` or
`none`) instead of a line.

## The 30 cases

`benchmarks/authz-handlers/cases.json`. All four repositories are corpus repositories at the
refs already pinned in `benchmarks/vulnerable-corpus/labels.json`, so no new licence or source
was introduced. A handler is **vulnerable** when the repository's own tutorial, challenge list or
solution notes names it as an access-control defect. It is **safe** when it reads or writes
per-user or privileged data and the decision is made from the authenticated identity, or when it
touches nothing that needs a decision. The safe cases were chosen to look like the vulnerable
ones: the same repository, often the same file, the same DAO, an id in the URL. Every line range
was printed from the snapshot before it was written down.

15 vulnerable (7 `ownership_check`, 8 `role_check`) and 15 safe.

| Case | Handler | Label | Control | Why |
| --- | --- | --- | --- | --- |
| `nodegoat-allocations-display` | `app/routes/allocations.js:11-31` | vulnerable | ownership | `userId` from `req.params` goes straight to the DAO (tutorial A4) |
| `nodegoat-benefits-display` | `app/routes/benefits.js:13-27` | vulnerable | role | admin benefits page behind `isLoggedIn` only (tutorial A7) |
| `nodegoat-benefits-update` | `app/routes/benefits.js:29-54` | vulnerable | role | updates any user's benefits from `req.body.userId`, no role check (A7) |
| `nodegoat-profile-display` | `app/routes/profile.js:13-38` | safe | none | id from `req.session` |
| `nodegoat-profile-update` | `app/routes/profile.js:40-107` | safe | none | updates the row for `req.session.userId` |
| `nodegoat-contributions-display` | `app/routes/contributions.js:12-26` | safe | none | looks up `req.session.userId` only |
| `nodegoat-contributions-update` | `app/routes/contributions.js:28-76` | safe | none | own row; its `eval` is A1, a different class |
| `juiceshop-basket-retrieve` | `routes/basket.ts:15-36` | vulnerable | ownership | basket by `req.params.id`, never compared (View Basket) |
| `juiceshop-basketitems-add` | `routes/basketItems.ts:19-56` | vulnerable | ownership | check reads the first `BasketId`, save uses the last (Manipulate Basket) |
| `juiceshop-basketitems-update-check` | `routes/basketItems.ts:65-83` | vulnerable | ownership | runs before PUT and checks stock only (Manipulate Basket) |
| `juiceshop-reviews-update` | `routes/updateProductReviews.ts:14-30` | vulnerable | ownership | updates the review named by `req.body.id`, author unchecked (Forged Review) |
| `juiceshop-reviews-create` | `routes/createProductReviews.ts:14-35` | vulnerable | ownership | stores `req.body.author` as the author (Forged Review) |
| `juiceshop-authentication-details` | `routes/authenticatedUsers.ts:10-35` | vulnerable | role | every user to any authorized caller; feeds the admin page (Admin Section) |
| `juiceshop-address-get-by-id` | `routes/address.ts:16-25` | safe | none | scoped by `UserId` that `appendUserId()` sets from the token |
| `juiceshop-address-delete` | `routes/address.ts:27-36` | safe | none | `destroy` scoped by id and token `UserId` |
| `juiceshop-card-delete` | `routes/payment.ts:68-77` | safe | none | `destroy` scoped by id and token `UserId` |
| `juiceshop-wallet-balance` | `routes/wallet.ts:10-19` | safe | none | token `UserId` only |
| `juiceshop-order-history-own` | `routes/orderHistory.ts:11-23` | safe | none | caller resolved from the bearer token |
| `juiceshop-order-history-all` | `routes/orderHistory.ts:25-30` | safe | none | returns every order, but `isAccounting()` on the route checks the role |
| `juiceshop-order-delivery-toggle` | `routes/orderHistory.ts:32-39` | safe | none | any order by id, behind `isAccounting()` |
| `dvna-admin-users-api` | `core/appHandler.js:206-213` | vulnerable | role | every user behind `isAuthenticated` only (DVNA a5 solution) |
| `dvna-user-edit-submit` | `core/appHandler.js:144-184` | vulnerable | ownership | user selected by `req.body.id`, never compared to `req.user.id` (a5) |
| `dvna-user-edit-form` | `core/appHandler.js:136-142` | safe | none | renders from `req.user` only |
| `pygoat-ba-lab-cookie` | `introduction/views.py:342-381` | vulnerable | role | admin secret released when cookie `admin` is `1` |
| `pygoat-a1-lab1-cookie` | `introduction/views.py:747-780` | vulnerable | role | admin branch chosen by cookie |
| `pygoat-a1-lab2-user-agent` | `introduction/views.py:783-820` | vulnerable | role | admin branch chosen by the `User-Agent` header |
| `pygoat-a1-lab3-secret` | `introduction/views.py:837-841` | vulnerable | role | admin-only page for any logged-in user |
| `pygoat-a1-lab3-login` | `introduction/views.py:822-835` | safe | none | admin flag decided server side; its hardcoded credentials are another class |
| `pygoat-ba-index` | `introduction/views.py:336-340` | safe | none | static lab description |
| `pygoat-a10-lab2-logging` | `introduction/views.py:645-674` | safe | none | logs a login attempt; no object or role |

Six of the safe cases put the decision on the registration line rather than in the handler:
`appendUserId()` on four and `isAccounting()` on two. That is deliberate.
A reviewer that reads only the handler body calls `allOrders` vulnerable, and that reviewer
should lose points here.

## Method

`benchmarks/authz-handlers/run.py`, one request per case, temperature 0, cases in id order.

**What the model sees.** The handler at its labelled range, 20 lines on each side (40 lines of
context at most), the route registration line found by a literal pattern stored in the case, any
`app.use(prefix, ...)` line in the same file whose prefix covers the route, the first 12 lines
of the definition of every middleware named on those lines, and a grep count of `passport`,
`isAuthenticated`, `login_required` and `@permission_required` across the tree. On the dry run
all 30 registration lines were found and 21 cases resolved at least one middleware definition.
The nine that did not are the seven Django views, which use decorators that appear in the
context instead of on the route, and two juice-shop routes with no middleware on them.

**What is removed first.** These are teaching applications and they label their own bugs.
Before anything reaches the prompt, the runner strips comments containing words such as
`insecure`, `vulnerable`, `IDOR`, `access control`, `no checking` or `challenge`, juice-shop's
`vuln-code-snippet` markers, its `challengeUtils.solveIf(...)` calls (multi-line, matched by
parenthesis depth) and their imports. Without this the run would measure comment reading. 16
of 30 cases had something removed: 10 vulnerable, 6 safe. Two leftovers were kept and are known.
juice-shop's security module is literally `lib/insecurity.ts`; the name appears in safe and
vulnerable juice-shop cases alike, so it does not separate them. NodeGoat's profile handlers keep
comments about their XSS and ReDoS lessons; those appear only in safe cases, so any pull they
have is toward a false positive and against the model.

**What the model must answer.** One JSON object: `verdict` (`vulnerable`, `safe`, `uncertain`),
`missing_control`, `evidence`, `reasoning`. The parse is strict. Fences are tolerated, nothing
else is. A vulnerable verdict needs a control other than `none` and a safe verdict needs `none`.
The evidence has to be a verbatim quote of at least 12 characters (whitespace normalised) from
the handler block shown, not from the context or the registration line. Anything else is
recorded as `rejected` with the reason. A model that is right for a reason it cannot point at in
the handler does not count as right.

**Scoring.** Precision is vulnerable verdicts on labelled-vulnerable handlers over all vulnerable
verdicts. Recall is the same numerator over the 15 labelled-vulnerable handlers. `uncertain`,
`rejected` and transport `error` all count as not vulnerable: never a false positive, always a
miss. Both get Wilson 95 percent intervals. On true positives the report also gives how often
the model named the same missing control as the label.

**Repeatability.** Each response is cached under `benchmarks/authz-handlers/.cache/`, keyed by
model, system-prompt digest, case and the full user prompt; the directory is git-ignored. The
report records the fixture and prompt digests (`44c1051c67ad`, `a875b690dc5a` at this commit) and
is rewritten after every case. A rerun keeps finished rows and retries error rows. `--max-cost`
reserves a deliberately high estimate before each request and refuses the request that would
cross the budget. The run then stops with status `stopped:budget`, and the unrun cases count as
misses. A live run refuses to start without a configured provider and positive
`--input-price`, `--output-price` and `--max-cost`.

**Untrusted trees.** `--fetch` downloads the four pinned tarballs through
`scripts/replay/corpus.py`, which refuses archive members that escape the extraction root, into
a directory the runner refuses if it is inside the repository. The runner reads the trees as text
and imports or executes nothing from them.

## Running it

```sh
PY=~/.pyenv/versions/3.11.6/bin/python
TREES=/tmp/authz-trees   # any empty directory outside the repository

$PY -I benchmarks/authz-handlers/run.py --trees $TREES --fetch
$PY -I benchmarks/authz-handlers/run.py --trees $TREES --dry-run --show-prompts \
    --output /tmp/authz-dry.json

# live: the provider and key come from the analysis service's own variables
LLM_PROVIDER=openai LLM_MODEL=gpt-4o-mini OPENAI_API_KEY=... \
$PY -I benchmarks/authz-handlers/run.py --trees $TREES \
    --input-price 0.15 --output-price 0.6 --max-cost 1.0
```

The report goes to `benchmarks/results/authz-handlers.json`, which is git-ignored. On the dry run
the 30 prompts total 144,493 characters, 3,616 to 7,444 each. At gpt-4o-mini's list price that
is an estimated 0.02 USD for the whole set, so the default `--max-cost 1.0` is a guard, not a
limit anyone should hit.

Tests, with a fake provider and a synthetic tree, no network and no key:

```sh
$PY -I -m unittest discover -s benchmarks/authz-handlers -p 'test_*.py'
```

They cover extraction (range, context cap, registration, path-scoped middleware, middleware
resolution, hint redaction), quote rejection and every other parse rejection, the Wilson
interval against reference values and the confusion arithmetic with `uncertain`, `rejected` and
`error`, the cost guard, the cache, resume, the budget stop, the dry run, `--fetch` refusing a
path inside the repository, and the committed `cases.json` (30 cases, 15 and 15, every ref
pinned in `labels.json`).

## What this does not measure

* **Any model.** The numbers do not exist yet.
* **Real code.** All four repositories were written to be found. Their access-control bugs are
  textbook shapes: an id in the URL, a cookie called `admin`. A model that does well here has
  shown that it can read a textbook. Production IDOR usually sits behind an ORM scope, a policy
  object or a tenant filter two files away, and the 40-line window may not reach it.
* **Finding the handler.** Each case says which handler to read. A product rule would first have
  to decide which changed functions in a pull request are route handlers, and that step has its
  own miss rate.
* **Label independence.** One person labelled all 30 cases from the repositories' documentation.
  The vulnerable side follows that documentation. The safe side is a judgement, and every reason
  is written in `cases.json` so it can be disputed.
* **Sample size.** With 15 vulnerable cases, a perfect 15 of 15 gives a precision lower bound of
  0.80 (0.7961). This set can disqualify an approach; it cannot qualify one.

## The bar for a posting rule

The rule set's posting policy is precision of at least 0.8 over at least three adjudicated
findings. That bar fits a pattern rule that either matches or does not. A model judging an
absence fails in more ways, and the cost of a false accusation of broken access control in a
review comment is high. A future authz posting rule should therefore meet all of the following
before anything posts:

1. **Precision with a Wilson 95 percent lower bound of at least 0.8**, not a point estimate of
   0.8. At a 0.925 point estimate that takes about 40 vulnerable verdicts (37 of 40 gives a lower
   bound of 0.801). At 0.95 it takes about 20.
2. **At least 40 labelled-vulnerable handlers and at least as many safe lookalikes**, of which
   at least half come from code that was not written to be found: CVE fix commits for CWE-639,
   CWE-862 and CWE-863 replayed against their parent tree, the same way the corpus took its CVE
   cases.
3. **Held out from the prompt.** The cases used to write or tune the prompt do not count toward
   (1) or (2). This set's 30 have been read by whoever writes the prompt, so they are a
   development set from now on.
4. **Recall is reported, not gated.** A low-recall reviewer that is right when it speaks is
   postable; a high-recall one that is wrong one time in four is not.
5. **Rejected and uncertain answers stay silent.** They are misses in the score and never
   comments.

This run measures (1) on a set too small to pass (2) or (3) by construction. Its value is the
fixture, the runner and the first number, once a key is available. If precision on these 30 is
under 0.8 even as a point estimate, there is no reason to build the larger set.
