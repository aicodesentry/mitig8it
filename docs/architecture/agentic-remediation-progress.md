# Agentic remediation implementation ledger

Branch: `feat/agentic-remediation`
Base commit: `6b02c870a3b1196103233876c94b09cf4ee77246`
Started: 2026-09-15. Last updated: 2026-09-22.

This document records observed evidence, not intended completion. The verification section dated 2026-09-18 was produced on a developer workstation with mocked providers, a local subprocess sandbox, or a disposable PostgreSQL 14 database. The live evidence sections that follow it were produced by the deployed single-instance development stack against repositories the operator owns. No result anywhere in this document is a real GKE Sandbox, a staging GitHub with branch protection, or a production observation, and every verification recorded here is `development_unverified`.

## Baseline and ownership

Existing unstaged hardening changes and untracked documents were preserved and are committed on this branch alongside the remediation work. Implementation was delegated by component (API control plane, Python repair service, GitHub adapter, frontend, infrastructure and docs, merge controller) with an orchestrator owning interface review, seam alignment, verification, and this ledger.

## Verification on 2026-09-18

All commands run from the named service directory unless stated. Disposable databases were dropped and recreated before each integration run.

| Check | Command | Result |
| --- | --- | --- |
| API unit | `npm test -- --runInBand` | 27 suites, 316 passed |
| API lint | `npm run lint` | clean |
| API access integration | `npm run test:integration:access` | 6 passed |
| API lifecycle integration | `npm run test:integration:lifecycle` | 8 passed |
| API remediation integration | `npm run test:integration:remediation` | 16 passed |
| API migrations | `npm run db:migrate` then `db:verify` then `db:migrate` on a fresh database | 0001 to 0016 applied once, verify clean, reapply applied nothing |
| GitHub adapter unit | `npm test -- --runInBand` | 6 suites, 104 passed |
| GitHub adapter remediation subset | `npm run test:remediation` | 54 passed |
| GitHub adapter lint | `npm run lint` | clean |
| Frontend unit | `npm test` | 15 files, 73 passed |
| Frontend lint and build | `npm run lint`, `npm run build` | clean, built |
| Frontend browser | `npm run test:remediation-browser` | 3 scenarios passed against the real Vite app with fixture API responses (system Chrome via `PLAYWRIGHT_CHROME_PATH`) |
| Repair service | `pytest tests -q` (Python 3.11) | 90 passed |
| Benchmark harness | `python -m unittest benchmarks.remediation.tests.test_evaluate` | 19 passed |
| Seed suite, reference oracle | `evaluate.py --suite seed` | exit 0 |
| Seed suite, real engine, local mode | `evaluate.py --suite seed --adapter engine-local` | exit 0; 7 cases, 4 verified repairs, 3 abstentions; `results_kind=pipeline_integrity`, `provider_kind=scripted-provider`, level `development_unverified` |
| Release gate | `evaluate.py --suite release` | exit 2 as expected: corpus is 7 of 120 fixtures, no review signatures, no signature trust root |
| Compose | `docker compose config`; `docker compose build` of repair service, worker, broker | valid; images built; repair service container answered `/health` 200 |
| Kubernetes | `render_kubernetes.py` with non-production values, then `kubectl kustomize` | 26 documents rendered |
| Terraform | `fmt -check`; `init -backend=false` and `validate` under Terraform 1.11.3 | clean; valid |
| Analysis service Python tests | `python -m pytest src/tests -q` (Python 3.11, native Semgrep on PATH) | 274 passed, zero skipped |

## Work package status

| ID | Status | Evidence and limits |
| --- | --- | --- |
| W00 | done | Baseline preserved, reviewed, rerun above |
| W01 | partial | Fixture schema, 11 fixtures (4 JavaScript supported including one two-file batch, 3 Python supported, 4 negative or adversarial), four adapters (`reference`, `engine-local`, `engine-live`, `engine`), release gate that refuses to pass without 120 reviewed fixtures and signatures. 11 of 120 is the whole corpus; there are no external review signatures and no trust root, and no quality metric is collected from live runs |
| W02 | done | Migrations 0013 to 0016, all ten planned tables plus writer leases, forced RLS, composite tenant keys, tested by upgrade and reapply |
| W03 | done for in-process dispatch | Outbox handler registry with delivery recorded only after handler success, backoff, dead letter after 5 attempts; reconciler for leases, stuck outbox rows, ambiguous writes, quarantine, intent expiry. `REMEDIATION_DISPATCH_MODE=cloud_tasks` throws not-implemented; Terraform gates the queue behind `enable_cloud_tasks_dispatch=false` |
| W04 | instrumented, not connected | Node OpenTelemetry with allowlisted attributes and log injection stripping; Python tracer with allowlist, redaction guard, and span links, tested with a secret canary. Dashboards and alert rules are files under `infrastructure/remediation/grafana/`; nothing provisions them. No deploy workflow sets `OTEL_EXPORTER_OTLP_ENDPOINT`, and no Prometheus scrape target points at a deployed service, so tracing is inert in the deployment and the metric-backed rules have no series. The rules file header now requires import with no data handled as NoData or OK (PR 422) |
| W05 | code complete, unproven | Real Kubernetes Job driver with gVisor, no token mount, dropped capabilities, and HMAC-attested broker evidence; local subprocess driver for development only. No isolation has been demonstrated on a real cluster; both attestation gates stay false |
| W06 | partial | Exact-commit snapshot from the GitHub adapter with blob SHA verification and tree identity re-bound in the repair service. The snapshot is bounded and ranked: finding files and manifests always ship, siblings are capped at 30 and unrelated files at 10, under a 60-file and 500 KB ceiling, with blobs fetched 8 at a time and Python sources and manifests included (PRs 405, 406, 408, 409). Retrieval inside the service is still literal search plus filename heuristics; no symbol parsing, ranking, or repair memory reads |
| W07 | done, template-first | Nine schema-validated tools, budgets, checkpoint resume, one agent per connected finding group. Since PR 417 the service writes the regression test (`src/proofs.py`) and attempts the patch (`src/templates.py`) itself from the derived site (`src/sites.py`) before any model call, charging zero tokens, and calls the model only for findings the templates did not prove. The provider adapter has been exercised live against gpt-4o on the deployed stack (PRs 124 to 132); PRs 133 and 134 needed no provider call at all |
| W08 | partial | Baseline and candidate runs, exploit-must-fail-on-baseline, patch policy with syntax, runtime load, and static undefined-name checks, honest limitations, verification levels. Since PR 410 a group proposal is split per finding by `src/splitting.py` and each candidate is verified on its own, so a candidate never carries a hunk its evidence does not cover. Advisory security review (plan section 8 step 7) is not implemented, and every verification to date is `development_unverified` |
| W09 | done | Combined tree from the union of candidate patches, overlap rejection, combined verification, immutable manifest |
| W10 | done | All public routes plus feedback; live actor authorization, branch policy, budget, writer lease, idempotency, revalidation with machine-readable rejections, checking and completed states, development verification refused unless `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true`; nine GitHub adapter operations with HTTP and gRPC parity |
| W11 | done | Per-finding and PR-level panel, unified diffs, coverage sentence, stale head, blocked reasons, capability-driven buttons, feedback control. Apply is per finding, per file, or the whole verified batch, and any other combination is refused as `subset_not_verified`; the panel offers no merge button. Verified fixes are also published on GitHub under each finding, and one residual report comment follows each apply |
| W12 | parked | Merge controller with ordered live re-checks, CAS transitions, bounded attempts, reconciling settlement, app verification check publication, GitHub-side cancel. Exercised live exactly once, on test-only PR 126, merged by `mitig8it[bot]` at 2026-09-20T18:54:30Z under the guarded flow. `REMEDIATION_MERGE_ENABLED` was turned off afterwards and the work is parked pending a two-step consent design; the product path requests no merge, and the apply route rejects `merge_when_ready: true` with 400 while the flag is off. Never exercised against a repository with branch protection |
| W13 | partial | Feedback persists observation rows in `repair_memory`; nothing promotes or reads them. Retention and deletion jobs do not exist, and neither retention nor restore has been exercised |
| W14 | not done | No load, chaos, or security acceptance suites |
| W15 | partial | CI runs every suite above; compose runs the whole stack locally; the runbook covers all listed incidents; `GET /api/remediations/:id/evidence` returns durable per-attempt evidence for a job in any state, which is the first diagnostic that needs no database access. The single-instance development deployment exercises a real GitHub pull request lifecycle on owned repositories. No production-shaped staging deployment, and no restore drill |

## Live evidence on the deployed app, 2026-09-19 to 2026-09-20

Staging repository: nebullii/test-only. Deployment: Cloud Run, single instance per service, scale to zero; repair service with the local execution backend, in-process worker and sandbox, gpt-4o; every result labelled `development_unverified`. An earlier revision of this line said "CPU always allocated". No deploy workflow passes `--no-cpu-throttling`, so that claim is withdrawn.

| Observation | Evidence |
| --- | --- |
| Analysis on a multi-file PR | PR 124: check run failure "5 critical/high findings"; 19 inline comments (3 blocking, 16 informational in test code); summary reports 3 test files scanned and 33 informational findings; one scanner batch, no memory events |
| Generation | PR 124 job 8b27a35b: ready in about one minute, 6,318 input and 471 output tokens, one candidate proven by a generated regression test that fails on baseline and passes on the candidate |
| Honest partial coverage | Two findings skipped as unsupported families, three as not repaired (no reproducing test); none claimed |
| Apply | Action c002de2b completed; commit e6593394 by the app on the PR branch changing one line (parameterized SQL query); exact head and manifest bound |
| Post-apply | Fresh analysis on the applied head shows the SQL finding gone (5 open, was 6); the app's remediation verification check reports failure because blocking findings remain |
| Defects fixed on the way | Cloud Run billing and CPU throttling, metadata token retry, protobuf map serialization, GitHub identity token on HTTP and gRPC transport for remediation calls, repair service secret precedence, request contract (attempt, platform, tree entries), partial coverage, budget estimation and overage settlement, checkpoint resume, lease heartbeat, reservation leak, sandbox workspace root, per-finding proof, full-file manifests, sandbox test harness |

Not yet exercised live: merge-when-ready (flag off; the installation lacks push and pull request review event subscriptions), and coverage of more than one finding per run.

## Live evidence 2026-09-21 to 2026-09-22

Same deployment. Repositories: nebullii/test-only and nebullii/Indoor-Plants, both owned by the operator. Every candidate below is `development_unverified`. Counts are taken from the review comments and report comments the app published, which are still on those pull requests.

### Merge under the guarded flow, then turned off

test-only PR 126 "Add customers lookup". One fix applied by explicit request in commit `6ae359ce157c` (SQL injection, `services/customers.js:9`); the residual report recorded zero remaining open findings in the changed files. The pull request was then merged at 2026-09-20T18:54:30Z by `mitig8it[bot]`, merge commit `6fc614c9758e`. This is the only app merge that has happened, and it happened while `REMEDIATION_MERGE_ENABLED` was on. The flag was turned off afterwards and the product path no longer offers merge: the apply route now rejects `merge_when_ready: true` with 400 `merge_not_available` while the flag is off, and the panel has no merge button.

### Per-finding apply

test-only PR 127 "Per-finding apply test", two applies on 2026-09-20 between 20:54 and 21:04.

| Apply | Commit | Report |
| --- | --- | --- |
| 1 | `e3bfba70c8b6` | One fix (SQL injection, `services/customers.js:9`); 6 remaining open findings listed by file and severity |
| 2 | `3a0eb23986cd` | Two fixes committed together as the verified batch (`services/orders.js:35`, the file-system-access and path-traversal pair); four findings listed as not repaired automatically, two outside the enabled families and two with no reproducing regression test |

Each apply was a separate human request and a separate commit against the exact verified tree. This is the run that demonstrated per-finding apply and the residual report comment.

One discrepancy is recorded and not resolved: the second report states "Remaining open findings in the pull request's changed files: 0" while listing four findings as not repaired automatically, and six inline finding comments were live on that head, five of them last updated one minute before the report was published. The report's applied list and not-repaired list are consistent with the inline comments; only the remaining count is not. Nothing has been changed on the basis of this observation.

### Automatic generation and publication

Four runs on test-only, each one an automatic job queued after the head's analysis was published. No developer pressed a generate button in any of them.

| PR | Run | Findings commented | Verified fixes published | Abstentions published |
| --- | --- | --- | --- | --- |
| 131 "Fresh remediation test" | 2026-09-21 17:36 | 5 | 0 | 4, with reasons: `code_injection_eval` not repaired for JavaScript, one regression test still failing on the patched code, two findings with no reproducing test |
| 132 "Final remediation check" | 2026-09-21 18:35 | 5 | 1 (`services/orders.js:13`, SQL) | 3 |
| 133 "Complete remediation check" | 2026-09-21 20:51 | 8 | 6 | 1 |
| 134 "Post-fix smoke" | 2026-09-22 19:43 | 5 | 4 | 0 |

The publication layout changed between 132 and 133. PR 132 carries the earlier layout, with a "Recommended fix (verified in a development sandbox)" heading and model-written prose for the stated intent. PRs 133 and 134 carry the layout merged in PR 417: the suggestion block first, then one `Verified: regression test failed on the original code and passed with this change (development sandbox).` line, then a collapsed `Details` block holding the intent, the proof, the evidence, the coverage limitations, and the human-in-the-loop sentence.

Every fix published on 133 and 134 came from the template path at zero model cost. The evidence is that each of them carries the stated intent "Legitimate input behaves as before; only the injected value is kept out of the sink.", which is a fixed string emitted only by `_template_pass` in `services/remediation-service/src/engine.py`, and every `_Pass` that function returns records `{"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []}`. The model is called only for findings the template pass did not prove, so a group the templates prove entirely never reaches a provider.

PR 133 in detail: six findings received a verified fix, three in `services/orders.js` (SQL at line 13, command execution at line 26, path containment at line 35, the last of which covers two co-located findings) and two in `text.py` (lines 10 and 15). Three further inline comments carry additional regions of those candidates (`services/orders.js:34` twice, `text.py:2`), which is the second-region publication path. One comment is a coverage revision: the medium null-pointer finding at `services/orders.js:27` is marked as fixed together with the command-execution finding on the same lines rather than claimed separately. The single abstention is `text.py:6`, where the Python static gate declined because the query reaches no known driver `execute()` and a parameterized rewrite cannot be chosen safely. That is a deliberate gate, not a failure, so every finding the service considers repairable on that head received a verified fix.

PR 134 is the post-fix smoke run after PR 421 merged: five findings in one file, four verified fixes, no abstentions. The fifth is a coverage revision of the same shape as PR 133's, a medium null-pointer finding on the same lines as the command-execution fix, marked as resolved by that fix rather than claimed separately. Three further comments carry additional regions of those candidates, which is why the pull request shows seven review comments for five findings.

### Python results

nebullii/Indoor-Plants PR 52 "Test webhooks", `text.py`, comments last updated 2026-09-21T13:56Z. Two findings, both published automatically:

- The hardcoded credential at `text.py:10` received a verified fix moving the literal to `os.environ["API_KEY"]` with the `import os` it needs. It was published as a unified diff rather than a suggestion, with the reason stated in the comment: the change spans lines 10 to 15 and the inline comment can only carry a suggestion for line 10. This is the non-suggestion fallback working as designed.
- The `eval` finding at `text.py:15` received `No automatic fix: The regression test for this finding still fails on the patched code.`

This run is the live evidence that the Python families, the Python harness, and the Python proof generator produce publishable results outside a fixture.

### Hot path correctness

mitig8it PR 421 "Fix hot-path correctness: event loops, GitHub write safety, timeouts, scanner rules", merged 2026-09-22T19:32:23Z. Eight commits, one fix each:

1. `72dfa836` analysis handlers run off the event loop; the blocking routes are synchronous handlers in the threadpool and tiers 1 and 2 run concurrently with a fixed merge order, so `/health` no longer waits behind a scan.
2. `a42aef79` the repair lease stays alive while candidates combine (`combine_patch_bundles` and `bundles_conflict` moved to `asyncio.to_thread`).
3. `5047b804` GitHub writes are sent once and only reads retry; `GitHubReader` retries GET and HEAD with jittered backoff honouring `Retry-After`, `GitHubWriter` returns an ambiguous outcome instead of resending.
4. `00c3be7d` `request_timeout_seconds` is the one verification deadline; the API default is 900 seconds, matching the 15-minute job ceiling.
5. `b3dc3a88` the auth-bypass rule's negative lookahead is anchored at line start so guarded routes stop being reported.
6. `d8e52e86` OpenGrep scan paths are resolved and required to stay under the scan root, failing the tier closed on escape.
7. `b1647ddc` the analysis internal secret is compared with `hmac.compare_digest`.
8. `0042937f` `/webhooks/unregister` requires the internal secret through the shared `ensureInternalAuth` middleware.

Suite counts reported on that pull request, each run locally: analysis-service 379 passed (329 on main), remediation-service 294 passed (290 on main), api-service 514 passed, github-service 167 passed, benchmarks 21 passed with `evaluate.py --suite seed` exiting 0. Each new regression test was run against the pre-fix code and failed there. No Cloud Run configuration or IAM change accompanied it.

A follow-up, PR 422 (`b9d2e796`), quieted the lease reclaim alert after a day of deliberate failure testing: the rule now needs more than three reclaims in thirty minutes, and the rules file header states that the rules must be imported with no data handled as NoData or OK, because the pending group queries metrics no service emits.


Deployment note: codesentry-api and codesentry-remediation run with CPU always allocated (Cloud Run `--no-cpu-throttling`). Their background workers (analysis queue, remediation dispatch, reconciler, in-process repair worker) starve when CPU is only allocated during requests; that starvation caused the stalled runs of 2026-09-19. The setting was first applied by hand and is now declared in the deploy workflows. Instances still scale to zero when idle.

Resolved observation: the second residual report on test-only PR 127 said "Remaining open findings: 0" while listing four unrepaired findings. Cause: the app's verification analysis run was re-pointed by the duplicate webhook run for the same commit, so the count came from the wrong run. Fixed in PR 402 by scoping the count to the immutable analysis snapshot; reports published after that PR are correct.

## Not done, as of 2026-09-22

| Item | Where it stands |
| --- | --- |
| Production-grade verification | Every candidate ever produced, in fixtures and on live pull requests, is `development_unverified`. The Kubernetes and gVisor driver exists and is rendered by `render_kubernetes.py`, but nothing has been applied to a cluster and both attestation gates are false. No result in this document satisfies an isolation gate |
| Analyzer misses | The repair service can only repair what the analyzer reports. Coverage of the detection tiers themselves is unmeasured: there is no false-negative corpus, so a finding the scanner does not raise is invisible to the whole pipeline. PR 421 fixed one such miss (the auth-bypass rule's exclusion was anchored so guarded routes stop being reported), which is evidence that rule defects exist and are found by inspection rather than by measurement |
| Analyzer precision | Now measured on one side and acted on. The September 2026 replay read 30 tier 1 findings by hand and found 29 false, so five rules (`null.pointer.deref`, `integer.overflow`, `rate_limit.missing`, `authz.missing_function_level`, `concurrency.shared_state`) are quarantined: they run and are counted, but nothing they produce is posted or sent to remediation. See the rule posting policy in [analysis-service.md](../services/analysis-service.md) and the gate in `benchmarks/tier1-precision/`. This removes noise; it does not add coverage, and it makes the remediation path's live input smaller rather than better |
| Five families | `sql_parameterization`, `command_arguments`, `path_containment` on JavaScript and Python; `hardcoded_credential` and `code_injection_eval` on Python only. Everything else is reported per finding as `unsupported_rule_family`. The JavaScript gap is the Node harness, which records no environment reads and stubs no `eval` |
| Merge | Parked. Exercised once on test-only PR 126, then `REMEDIATION_MERGE_ENABLED` was turned off. Resuming it needs a two-step consent design, because the single apply consent that exists today is not consent to merge. Never exercised against branch protection |
| Observability | Instrumented but not connected. Spans, attribute allowlists, redaction guards, dashboards, and alert rules all exist; no deploy workflow sets an OTLP endpoint and no scrape target points at a deployed service, so nothing is collected. The rules in `mitig8it-remediation-pending` query metric names no service emits |
| Evaluation corpus | 11 of the 120 fixtures the release manifest requires, all authored in this repository, with no external review signatures and no trust root. `evaluate.py --suite release` exits 2 by design. No online quality metric is collected from live runs, so live precision and abstention rates are unknown |
| Retention and restore | Repair memory rows are written and never read or promoted; retention and deletion jobs do not exist. The restore reconciliation procedure in the runbook has never been exercised, so its fencing and outbox assumptions are untested |
| Gemini key rotation | `codesentry-gemini-api-key` in Secret Manager backs tier 3 triage. Rotation is pending and has not been performed |
| Load, chaos, and security acceptance | Not started (W14) |

Everything the feature flags guard is false by default in the repository. The deployed single-instance stack has generation, publication, and apply on, and merge off.

## External acceptance prerequisites

A disposable staging GitHub repository with branch protection and the app's verification check required, a GCP project and region with GKE Sandbox, a repair model account with pricing configuration, and a budget for real-model and sandbox evaluation. Until those exist, this branch is a complete local implementation, not a release.

Full specification: [implementation plan](agentic-remediation-implementation-plan.md).
