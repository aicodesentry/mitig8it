# Known engineering debt

Items an engineering review raised that remain deliberately open. Eight items from the same review were fixed in [PR 421](https://github.com/aicodesentry/mitig8it/pull/421): the blocking analysis handlers moved off the event loop, the repair lease stays alive while candidates combine, GitHub writes are sent once and only reads retry, the policy timeout became the one verification deadline, the auth-bypass rule's exclusion was anchored, OpenGrep scan paths were contained, the analysis internal secret is compared in constant time, and webhook unregister requires it. Completed follow-up items are removed from this register rather than left looking current.

Each entry states what the issue is, where it is, and why it was left. None of these is a correctness defect under the loads this system has seen; they are cost, clarity, and drift risks that were not worth taking alongside the hot-path fixes.

## Pinned pool connection

**What.** `claimNextQueuedRun` checks a client out of the pg pool, takes a session-scoped `pg_try_advisory_lock`, commits the claim transaction, and hands the caller a `releaseLease()` closure. The connection stays checked out for the whole analysis, which is minutes, because a session advisory lock dies with its session. Maximum analysis concurrency is therefore bounded by pool size rather than by worker capacity.

**Where.** `services/api-service/src/db/analysisRuns.js`, `claimNextQueuedRun`.

**Why deferred.** It is the property that makes the lease correct: a crashed connection releases its lease and a slow live worker cannot be reclaimed. The concurrency cost is already bounded explicitly in the orchestrator and covered by `tests/analysisQueueConcurrency.test.js`, and it is recorded as accepted residual risk in `HARDENING-TRACKER.md` rows 19 and 20. Replacing it means moving to an advisory lock held in a separate connection or to a lease table with heartbeats, which changes the recovery semantics and needs its own test pass.

## N+1 persistence

**What.** Findings are persisted one at a time. `persistAndFilter` loops over findings calling `upsertFinding`, and each call issues a select then an update or insert, so a 200-finding pull request is more than 200 sequential round trips. The same shape remains when persisting remediation evidence, one insert per record. Suppression updates no longer share this debt: they are sent as one `UPDATE ... FROM jsonb_to_recordset` batch.

**Where.** `services/api-service/src/services/prAnalysisOrchestrator.js` (`persistAndFilter`), `services/api-service/src/db/findings.js` (`upsert`), and `services/api-service/src/db/remediation.js` (`persistEvidence`).

**Why deferred.** Finding counts per pull request are small in practice and each round trip is on a pooled local connection. The suppression path demonstrated the batched form without touching identity semantics. Batching `persistAndFilter` still changes the dedup and fingerprint path, which is the part of the system with the most behavioural tests; evidence persistence has a separate transactional ordering constraint.

## Failure classifiers remain separate

**What.** Five mappings still classify failures independently. This is intentional: they decide whether to retry one GitHub read, reconcile one ambiguous GitHub write, retry one metadata-token fetch, return one remediation job to its durable queue, or restart an entire analysis run. Their accepted failure sets differ because the cost of a false positive differs.

**Where.** `services/api-service/src/services/prAnalysisOrchestrator.js` (`isTransientServiceError`, `isTransientInfrastructureError`), `services/api-service/src/services/remediationWorkflow.js` (`isTransientRepairFailure`), `services/api-service/src/clients/grpcConnection.js` (`isRetryableMetadataError`), and the read/write split in `services/github-service/src/services/githubInternalOperations.js`.

**Why deferred.** Each function now documents its caller, the question it answers, and the consequence of a wrong answer in either direction. A shared module would hide those different semantics behind one name. The remaining debt is duplication: adding a new transport status still requires checking five explicitly different policies.

## Contracts package

**What.** The repair request and policy shape is declared twice: as Pydantic models in the repair service and again as `DEFAULT_POLICY` plus a hand-built wire payload in the control plane. Tests reach across the service boundary to the exported JSON Schema and now assert both schema validity and that every shared control-plane limit is no looser than the repair service's limit.

**Where.** `services/remediation-service/src/models.py` and `contracts/repair-request.schema.json` on the Python side; `services/api-service/src/services/remediationPolicy.js` and `src/services/remediationWorkflow.js` on the Node side; `services/api-service/tests/repairRequestContract.test.js` is the sync mechanism.

**Why deferred.** Drift is already real, and it is bounded drift rather than breakage. The two copies disagree on `max_snapshot_files` (120 in `DEFAULT_POLICY`, 500 in `RepairPolicy`), `max_file_bytes` (500000 against 512000), `max_snapshot_bytes` (500000 against 10000000), and `max_output_chars` (64000 against 2000000), and `max_context_tokens` sits on the Node policy but on the Python `RepairLimits` rather than on `RepairPolicy`. In every case the control plane's value is the tighter one. A shared package means a published artifact and a release process for two languages, which is not worth it while one repository holds both; the directional contract test now catches unsafe drift.

## Module splits

**What.** Several modules carry more than one responsibility and are large enough that a reader cannot hold them.

**Where.** By line count, excluding generated protobuf: `services/github-service/src/services/githubInternalOperations.js` (1,821), `services/remediation-service/src/patches.py` (1,418), `services/api-service/src/db/remediation.js` (1,405), `services/api-service/src/services/prAnalysisOrchestrator.js` (1,288), `services/remediation-service/src/agent/loop.py` (1,190), `services/remediation-service/src/engine.py` (977), `services/remediation-service/src/executions.py` (955), `services/remediation-service/src/templates.py` (946).

**Why deferred.** These are the files under the most active change. Splitting them during the remediation work would have made every concurrent branch conflict, and a split that only moves code makes history harder to read for no behavioural gain. `templates.py` and `engine.py` in particular are still growing per family.

## RLS cast

**What.** Every tenant-scope row-level security policy casts the column rather than the setting: `installation_id::text = current_setting('app.tenant_id', true)` and `ra.user_id::text = current_setting('app.user_id', true)`. Coercing the row's key to text means the b-tree indexes on `installation_id` and `repository_access(user_id)` cannot serve the policy predicate, and a malformed `app.tenant_id` silently matches nothing instead of raising.

**Where.** `services/api-service/migrations/0013_remediation_control_plane.sql` (the ten tenant-scoped tables), `0014_remediation_control_plane_hardening.sql` (writer leases), `0022_remediation_job_evidence.sql`, and `services/remediation-service/migrations/0001_remediation_executions.sql`.

**Why deferred.** Silently matching nothing is the safe direction for a security predicate, and the row counts are small enough that the lost index has not shown up. Changing it means rewriting policies across four migrations, which must be a new migration rather than an edit, and it changes the failure mode from "returns nothing" to "raises", which needs a deliberate decision about what a malformed tenant setting should do.

## Quadratic work

**What.** Six loops whose cost is quadratic in an input this system does not currently make large.

**Where.**

| Location | Symbol | Shape |
| --- | --- | --- |
| `services/analysis-service/src/finding_quality.py` | `cluster_findings` | Each deduped finding is compared against every member of every existing cluster. Runs on every analysis. |
| `services/remediation-service/src/patches.py` | `combine_patch_bundles` | Per path, per patch, per changed range, scanning all previously accepted ranges. |
| `services/remediation-service/src/patches.py` | `bundles_conflict`, `_bundle_ranges` | Recomputes a line-by-line diff for every already-accepted bundle on every call. |
| `services/remediation-service/src/engine.py` | the candidate acceptance loop | Calls `bundles_conflict` once per pass, so the accepted set's diffs are re-derived from scratch. |
| `services/remediation-service/src/patches.py` | `_occurrences` | Naive substring search over file lines, used by `locate_hunk`. |
| `services/remediation-service/src/splitting.py` | `is_import_only`, `attribute_hunks` | List scans inside list comprehensions, and findings by hunks by prerequisites. |

**Why deferred.** Every input is bounded by policy: `max_files` is 5, `max_changed_lines` is 200, and a job carries a handful of findings, so the largest of these runs over single-digit collections. `cluster_findings` is the one that scales with something a user controls, the number of findings in a pull request, and it is the one to fix first if analysis latency becomes a complaint. PR 421 moved the combine loop onto a worker thread so it stops starving the lease heartbeat; the quadratic work itself was left in place deliberately, because the heartbeat was the defect and the cost was not.

## Quarantined tier 1 rules

**What.** Six tier 1 rules were measured on real code and found wrong often enough that their output cannot be posted. They are quarantined rather than deleted: they still run and are still counted, so they can be re-measured, but nothing they produce reaches a reviewer. The mechanism is `precision` and `posting` on `SecurityRule`, filtered in one place by `partition_by_posting_policy` in `services/analysis-service/src/main.py`.

**Where.** `services/analysis-service/src/security_rules.py`. Each rule carries its own `precision_evidence` string.

**Evidence.** The September 2026 real-repository replay, `docs/validation/real-repo-replay-2026-09.md` on `feat/real-repo-replay`: 165 merged pull requests from 11 public repositories, 134 tier 1 findings, 30 read by hand, 29 of them false.

| Rule | Replay volume | Why it was quarantined |
| --- | ---: | --- |
| `null.pointer.deref` | 85 of 134 | It is a method-chain detector, not a null check. It fired on `connection.removeAllListeners('error').on('error', ...)`, on the Jest idiom `await expect(next.start()).rejects.toThrow()` (27 findings by itself), and on Rust `chunking_context.unused_references().await?`, where its advice to use optional chaining names a construct the language does not have. All 19 sampled were wrong. Fixing the exclusion shape was mechanical; the semantics are not |
| `authz.missing_function_level` | 19, 13 at `high` | Reduced to "the line contains `.destroy(` or `.remove(`". Every sampled finding was stream, socket or connection-pool teardown. Moving the dead lookahead into an `exclusion` pass changes nothing, because none of those lines carries an auth token either |
| `integer.overflow` | 14 | `int(` had no word boundary, so it matched `models.UniqueConstraint(` and `function fingerprint(snapshot: Snapshot)`. The boundary and the relocated exclusion clear both sampled lines, but what is left is still "the line contains `parseInt`", with no measurement on the other 12 findings and no true positive anywhere in the corpus |
| `concurrency.shared_state` | 6 | `global\s+\w+` matches English. It fired on the comment `// If agent.http2 is unset, use the global agent for connection pooling.` and on the changelog line `Fix a global leak when multiple subnets are trusted`. Comment stripping removes the first shape; the prose-file shape needs the rule to know what a declaration is |
| `path.traversal.user_path` | 86 over the vulnerable corpus | Measured separately, on the September 2026 vulnerable corpus rather than the replay: 7 adjudicated, 3 true and 4 false, precision 0.43. Every false positive arrived through the `\{` alternative, which was meant to catch an f-string or a template interpolation and instead matches the brace of an options object. Removing that alternative also removes the rule's own true positive, so the pattern cannot be narrowed without a data-flow answer about where the path came from |
| `rate_limit.missing` | 2 | Reduced to "the line contains `/login`, `/auth`, ...". Its entire output over 165 pull requests was a redirect target in a test fixture, a JSDoc usage example, and the package name `@octokit/auth-token` in a vendored licence file |

**Why deferred.** Each of these needs a rule design, not a regex repair: a null check needs to know what can be null, an authorization rule needs to know what a route handler is, and a shared-state rule needs to know what a declaration is. The quarantine stops the harm now and keeps the measurement running. Re-enabling one is a change of its own, with its cases added to `benchmarks/tier1-precision/cases.json` and the gate green.

**Related gap, now closed.** Tier 1 used to read prose files (changelogs, READMEs, licence text) as code, and `auth.bypass.missing_check` fired on the express changelog line `app.get('/user/:id').remove();`. Prose-path scoping landed with the real-repository replay work, and the rule was separately re-anchored, so the case in `benchmarks/tier1-precision/cases.json` is now a suppressed false positive (`suppressed_by: prose_path_scope`) rather than a recorded gap.

## Detection gaps measured on 2026-10-25

The current vulnerable-corpus run
([full score](../validation/vulnerable-corpus-2026-10-25.md)) put the same 171 labelled
vulnerabilities in 23 pinned repositories through both tiers. It found 105 on the labelled
line (0.61 recall), including 90 by rules that post. Another 12 had the expected class elsewhere
in the file and 7 had a different class on the labelled line. The report records the command,
commit, class tables, missed labels, and the manual XSS/command-injection adjudication.

**Cross-site scripting: 26 of 32 on the labelled line (0.81).** Template scanning and the
string-interpolation coverage are now live. Current hits come from
`opengrep.cwe-79.js-angular-bypass-security-trust`,
`opengrep.cwe-79.tpl-ejs-unescaped-output`,
`opengrep.cwe-79.tpl-unescaping-filter`,
`opengrep.cwe-79.js-html-string-interpolated`,
`opengrep.cwe-79.tpl-inline-script-inner-html`,
`opengrep.cwe-79.py-html-percent-format`,
`opengrep.cwe-79.js-template-autoescape-disabled`, and `xss.unsafe_html_render`. The surviving
gaps are context-dependent template sinks under a separately disabled global autoescape setting,
a multiline `setup_jinja(autoescape=False)` call, HTML/script content built with concatenation
rather than interpolation, and nested percent formatting. One of those files reports XSS away
from the labelled line; broadening every interpolation/format operation would repeat the old
precision failure.

**Command injection: 6 of 11 on the labelled line (0.55), with one more in-file.** Current hits
come from `opengrep.cwe-78.child-process-exec`, `cmd.injection.shell_true`,
`opengrep.cwe-78.py-subprocess-shell-interpolated`, and
`opengrep.cwe-78.js-exec-interpolated`. The three electerm misses build a command and hand the
variable to `run`/`runWinCmd` in the next statement; the pygoat miss passes a previously built
variable to multiline `Popen(..., shell=True)`. Reaching those without matching every
`exec($VAR)` still needs bounded one-hop data flow.

**The remaining labelled gaps are distributed, not dominated by template coverage.** Path
traversal is now 13/14 with the last label found elsewhere in its file. The largest open groups
are hardcoded secrets (7/18 line hits, 4 more in-file), error-detail exposure (0/6), weak password
hashing (3/11), cookie flags (2/7), open redirect (3/6), and XML external entities (1/4). Smaller
zero-hit families are permissive CORS, prototype pollution, disabled security headers, and JWT
verification/algorithm configuration. Several secret and weak-hash misses are also consequences
of the one-finding-per-rule-per-file ceiling below; the others need new source/sink or framework
configuration rules, each with corpus precision evidence before posting.

**A tier 1 rule reports one finding per file.** `pattern_findings` in
`services/analysis-service/src/main.py` emits at most one finding per rule per file, at the
first match. `enrocrypt/hashing.py` offers eight digests including MD5; `crypto.weak.hash`
reports the first one and the CVE is at the eighth. Nine of the 18 labels that were found in
the file but not on the line are this. It keeps a file with fifty weak hashes from producing
fifty comments, which is why it is there, and it caps recall on any file with more than one
instance of the same defect.

## Repair-proof gaps measured in September 2026

The entries below come from the separate repair-pair runs linked in each entry. They describe
proof generation and sandbox reach, not scanner recall, and were not remeasured by the 2026-10-25
scanner replay above.

**Repair templates still need a sink they can name.** The route requirement and the enclosing
function requirement this entry used to describe are both gone: `sites.js_site_for_line` falls
back from the enclosing route to the enclosing function, method or `exports.name` binding, and
then to module scope, where the proof drives the sink by setting what the module reads and
importing it. `enclosing_route_not_found` and `enclosing_function_not_found` are both 0 on the
corpus. TypeScript loads too, through Node's type stripper. Three more per-shape refusals have
since gone the same way: `path_module_not_required` and `function_parameters_not_plain_names`
are both 0, and `path_join_not_found_in_scope` is down by a third, because the path binding is
read in every style a file can write it, a path built by concatenation or interpolation is a
repair site, and a parameter list is modelled rather than required to be a row of plain names.

What is left is narrower again and is mostly correct refusal rather than gap.
`module_scope_source_not_controllable` (59), `path_argument_is_constant`,
`path_argument_not_composed_in_scope` and `path_identifier_shadowed` all name code a generated
test could not fail on before a repair. The remaining gaps are `command_name_not_literal`,
`eval_argument_not_an_identifier`, `string_literal_assignment_not_found`, `sink_not_recognized`
and `method_receiver_not_supported`, the last of which grew because a site the scan can now
reach turns out to hang off a receiver the proof cannot construct.
`docs/validation/vulnerable-corpus-2026-09.md` has the full before and after.

**A dependency-free sandbox can only load a dependency-free module.** The reach work is done and
what it ran into is named. `docs/validation/pairs-2026-09.md` ran each complete pair's proof
against the original tree and the patched tree separately, and seventeen of the eighteen that did
not verify never reached the proof's first assertion. Ten were in a file policy will not let the
service change; seven could not load the module the proof names, because its import closure
reaches a package the sandbox has no copy of. All of those are now refused with a reason before
the work is done, and the pair count fell from 26 to 8, of which all 8 verify.

What is left is one number: **84 findings get no proof because
`dependency_not_available_in_sandbox`.** Every pair that does verify is a module with no imports
beyond the standard library, five Node configuration objects and three Django settings files, and
that is the only shape a sandbox with no `node_modules` and no site-packages can load. Faking the
packages does not scale, and the pairs page shows the arithmetic: one entry module reaches
fourteen packages, another twenty-five, juice-shop's between eleven and fifty-six, and the
overlap between any two is four pieces of Express middleware sitting in front of two different
ORMs.

Closing it is a decision about the sandbox rather than another refusal to remove: install the
repository's dependencies into the verification workspace, or carry `node_modules` and the
snapshot's site-packages into it, with the checks still on a network they cannot reach. Both are
larger than anything in that round, both carry a real supply-chain question, and neither should
start before someone measures what share of the 84 a dependency install would actually reach.

**Measured, and decided against.** The "With dependencies installed" section of
`docs/validation/pairs-2026-09.md` installed them and re-ran the pairs. On a fresh set of scans
the same refusal stood at 81. The install reached 17 of the 23 repositories and 1.7 GB of disk,
**80 of the 81 modules became loadable**, 7 of them produced a complete pair, and **0 verified**:
the count of verified pairs stayed at 8. The bar set before the measurement was 20. What the
install converts is the refusal reason and not the outcome, so the 81 become 73 findings that
name a site a proof cannot drive, 7 pairs that still fail at load for other reasons, and 1 with
no template. A production install would be the one step of a verification run that reaches a
package registry, over a tree chosen by whoever opened the pull request; that is not worth buying
for nothing, so it was not built. `policy.install_dependencies` exists, defaults false, and is
implemented for the development-only local driver that the measurement runs on;
`services/remediation-service/contracts/repair-v1.md` says so under "Installed dependencies".

**The constraint this leaves is the proof, not the sandbox.** With loadability removed, the
largest single reason a finding gets no proof is `module_scope_source_not_controllable` at 40 of
the 81, 29 of them in dicebear alone: a secret at module scope in a file the proof cannot make
the module read differently. Three smaller things the same measurement named, each with a row in
that page's table of the seven pairs: the harness's own `global.Function` recorder breaks a real
package that builds a wrapper with `new Function` at import (`depd`, under `express` and
`body-parser`); the harness's `registerHooks` resolver redirects a relative specifier to its
TypeScript source but does not answer for the entry module, so a `.ts` subject loaded through the
ES module loader raises `ERR_MODULE_NOT_FOUND` on itself; and an installed `@angular` puts files
in the closure that Node's strip-only mode cannot parse.

## Precision-admission gaps measured on 2026-10-25

**Three rules the corpus still cannot decide.** `xss.unsafe_html_render` (16 findings, 2
adjudicated, 0.50), `auth.bypass.missing_check` (8 findings, 1 adjudicated, 0.00) and
`opengrep.cwe-798.hardcoded-secret-js` (6 findings, 2 adjudicated, 0.50) are all below the
three adjudicated findings the posting policy requires before it will act. Reading one more
representative finding from each rule is the cheapest way to close this.

**`opengrep.cwe-489.py-debug-constant-true` remains short of re-enabling.** It has two current
findings; one overlaps a labelled `DEBUG = True` vulnerability and one remains unread. The shape
looks like the real Django settings case its quarantine reason doubted, but the rule still cannot
come back because the policy asks for three adjudicated findings.

**Pre-existing tier 2 rules pass their check id as `internal_type`.** The rules in
`javascript.yml` and `python.yml` declare no `internal_type`, so `opengrep_runner` sets it to
the check id and `taxonomy.canonicalize_internal_type` returns it unchanged: a finding
arrives as `internal_type: "cwe-502.pickle-loads"`, a category of one that nothing else can
group with. `tests/test_tier2_rule_metadata.py` forbids this for the coverage rules and the
older files are out of its scope. `scripts/replay/score.py` works around it by deriving the
class from the CWE.

## Provenance

This list was reconstructed from the code, from PR 421, from the residual-risk notes in `HARDENING-TRACKER.md` and `HARDENING-HANDOFF.md`, and from the linked validation runs. Completed tracked work is removed as it lands. Every remaining location above was confirmed in the source at the time of writing.

## From the database audit of 2026-09-22

- Budget reservations are a flat 0.05 USD for the snapshotting stage only; settled jobs have cost up to 0.28 USD, so the budget gate cannot refuse an over-budget job. Reserve per stage from the policy estimate (`services/api-service/src/db/remediation.js`, `reserveUsage`; `remediationPolicy.js`, `stageEstimate`).
- One candidate row from 2026-09-20 has the legacy bare-array `file_manifest` shape; its job is still `ready`. Make the reader tolerant or supersede the job.
- `evidence_details` is empty on findings persisted before migration 0007; expected, but reports that read it should treat empty as unknown.
- Autovacuum has not run on the small remediation tables; harmless at the current size, revisit when `remediation_jobs` grows.
- Live runtime-role cutover still requires an operator: the API now refuses elevated database roles at production startup, and the deployment provisions/verifies a separate non-owning `NOBYPASSRLS` login. The old migration credential is no longer mounted into the API or GitHub gRPC service. Create the runtime credential secret and validate the deployed role before onboarding a second tenant; see [Runtime Database Role](../runbooks/runtime-database-role.md). This is locally tested enforcement, not evidence that the live cutover has happened.
