# Remediation benchmark seed

This is an offline seed harness for repository-level repairs. It is deliberately not a quality claim: it contains eleven authored fixtures, while the release manifest requires 120 externally reviewed cases before a release gate can pass.

Four JavaScript fixtures validate SQL parameterization, command argument construction, path containment, and a multi-file batch; three Python fixtures validate sqlite3 parameterization, moving a hardcoded credential into the environment, and replacing `eval` with `ast.literal_eval`. Their checked-in original and reference-repaired sources are run by fixed, audited Node or Python assertions (`trusted_fixture_test.runtime` is `node` or `python3`). Negative and adversarial fixtures must abstain: `python-ambiguous-sql` mirrors a query handed to an unknown `execute_query` helper, which the engine skips as `ambiguous_query_api` before any agent runs.

`multi-file-batch` carries two findings in two files of one SQL injection chain. The engine groups them into two connected components, runs one bounded agent loop per group, and combines the two candidates into one batch that is verified again on the union. Either repair alone closes the chain, so each candidate tree and their union all satisfy the fixture's exploit check. A fixture declares extra affected files with `additional_units`, each carrying its own `source`, `reference_repair`, and `finding`.

Every fixture declares a `verification_checks` array: fixed argv the sandbox runs on the baseline and the candidate tree, with the outcome the fixture expects from each. A supported fixture's `exploit` check must exit non-zero on the vulnerable tree and zero on the repaired tree, and its `behavior` check must exit zero on both. `tests/verify.js` (or `tests/verify.py`) implements both the sandbox modes (`--exploit`, `--behavior`) and the original two-path comparison the reference adapter uses.

Run the deterministic seed suite:

```bash
python benchmarks/remediation/evaluate.py --suite seed
python -m unittest benchmarks.remediation.tests.test_evaluate
```

Generate a release report (expected to exit `2` until the release manifest's case/review requirements are genuinely met):

```bash
python benchmarks/remediation/evaluate.py --suite release --output /tmp/remediation-release.json
```

## Adapters

The harness supports four adapters. Only a run with a real evaluated model produces evidence about repair quality, and no such run happens in CI.

The `reference` adapter replays the checked-in reference repairs through the fixed Node assertions: it proves the fixtures, assertions, and grading are internally consistent, and it measures the authored answer rather than a model, so a 100% pass rate says nothing about the repair agent. The `engine-local` adapter proves the agent loop, tool schemas, grouping, budgets, patch validation, and fail-closed decisions behave as specified for canned responses, which are also authored. Reference and scripted-provider results are not comparable to real-model results and must never be reported as one number. A release report has to state which adapter produced it, along with sample counts and intervals.

| Adapter | What runs | Verification level | What the numbers mean |
| --- | --- | --- | --- |
| `reference` | The checked-in reference repair, no engine | none | Fixture integrity only |
| `engine-local` | The real engine in-process, local execution backend, local subprocess sandbox, scripted provider double | `development_unverified` | Pipeline integrity, not repair quality |
| `engine-live` | The same local pipeline with the real provider from `REPAIR_LLM_*` | `development_unverified` | A development repair attempt with no production isolation claim |
| `engine` | The same complete request posted to a deployed service over HTTP, polled to a terminal state | whatever that service reports | Graded like the local adapters at the level the service reported; see below |

Run the whole pipeline locally, with no cloud services and no provider spend:

```bash
python benchmarks/remediation/evaluate.py --suite seed --adapter engine-local
```

The scripted provider replays each fixture's reviewed reference repair, so precision and coverage from `engine-local` measure whether the service pipeline carries a finding to a verified candidate. They are not a measurement of a model's repair quality, and the report labels this with `provider_kind`, `verification_levels`, `results_kind`, and an explicit note.

`--adapter engine-live` uses the real provider and fails immediately with the missing variable names when `REPAIR_LLM_BASE_URL`, `REPAIR_LLM_API_KEY`, or `REPAIR_LLM_MODEL` is unset. Its candidates still run in the development sandbox, so they remain `development_unverified`.

`--adapter engine` drives a deployed service. It builds the same complete RepairRequest the in-process adapters build, posts it to `/v1/repair`, polls `GET /v1/repair/{execution_id}` until the execution is terminal under `--engine-poll-timeout-seconds`, and grades the returned candidates against the fixture's reviewed repair. Nothing the service returns is executed on this host. It requires an explicit opt-in network flag and errors with the missing variable's name when `REMEDIATION_SERVICE_URL` or `REMEDIATION_SERVICE_INTERNAL_SECRET` is unset:

```bash
REMEDIATION_SERVICE_URL=https://internal-remediation.example \
REMEDIATION_SERVICE_INTERNAL_SECRET=... python benchmarks/remediation/evaluate.py \
  --adapter engine --allow-network
```

Add `--engine-allow-development-verification` when pointing at the compose stack, whose sandbox driver is local, and `--engine-sandbox-image-digest` when pointing at a deployment that verifies with a digest-pinned runner image.

The report's `results_kind` follows the verification level the service reported. `development_unverified` is labelled `pipeline_integrity`. The production level is labelled `repair_quality` only when the operator also passes `--remote-provider live-provider`, because this harness cannot observe which provider a remote service used; without that declaration the production level is labelled `unverified_contract_smoke`. A declaration is not evidence, and no `engine` result can pass the release gate on its own.

Known gaps: this seed has no independent external-review signatures, no production sandbox/broker run, and no cryptographic signature verifier. The local driver used by `engine-local` and `engine-live` has no network, kernel, or filesystem isolation, so no result here satisfies an isolation gate. The seed must remain non-promotable until those controls and the configured minimum corpus are supplied.

When the corpus is expanded, `release/review-signatures.json` must contain a `reviews` array with one record per fixture: `{ "fixture_id", "reviewer_id", "algorithm": "ed25519", "key_id", "signature" }`. Schema validation alone is deliberately insufficient: wire an approved trust root and cryptographic verifier before allowing any release result to become promotable.
