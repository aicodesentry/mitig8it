# Repair HTTP contract v1

`POST /v1/repair` is the canonical authenticated durable intake operation. `POST /v1/repair-stages` is a compatibility alias with the identical request and response. It returns HTTP 202 with `{schema_version, execution_id, state}` after the request artifact and execution row are durable. `GET /v1/repair/{execution_id}` returns `running` or the terminal `ready | unsupported | inconclusive` result. Send `Authorization: Bearer <REMEDIATION_SERVICE_INTERNAL_SECRET>`; `x-internal-secret` is accepted only as a migration fallback.

The JSON request is validated by `src.models.RepairRequest` with unknown fields rejected. Required security bindings are:

- `schema_version: "v1"`, `job_id`, `tenant_id`, `repository_id`;
- exact `head_sha` and `base_sha`;
- `head_tree_oid`, `tree_truncated: false`, and the complete recursive-head leaf metadata in `tree_entries: [{path, mode, type, sha}]`;
- immutable finding snapshots and bounded `files: [{path, content, sha?}]` from the trusted control plane;
- `profile`, `policy`, and a non-empty `versions` manifest.

`sha` on a file accepts a 40-hex Git blob SHA-1 or a SHA-256 (64 hex or `sha256:` form). File content is always verified against its matching Git tree blob before generation. A complete tree is required because the applicable response includes an independently attested real Git `verified_tree_oid`; a SHA-256 manifest is never mislabeled as a Git tree OID.

The policy's `verification_checks` are fixed argv arrays selected by the trusted control plane, never model-selected shell strings. The list may be empty when `require_generated_regression_test` is true, which is the default; with it false, the policy must supply at least one `exploit` and one `behavior` check. A `ready` result always requires a digest-pinned sandbox runner image. Check kinds are `existing_test`, `typecheck`, `build`, `scanner`, `exploit`, and `behavior`.

## Generated regression tests

## Agent context and patch shape

`read_file` returns `lines`, a list of `[line_number, text]` pairs carrying the 1-based line number and the exact text of each line, plus `truncated`. A truncated read drops whole trailing lines and lowers `line_end` to match, so a numbered line is always the line the file holds. `original_lines` in a patch hunk are these `text` values copied back unchanged.

`read_file` takes an optional `line_start`/`line_end`. With them null it returns a window of `DEFAULT_READ_CONTEXT_LINES` (30) lines either side of the finding's reported range, clamped to the file. Every tool result is capped at `policy.max_tool_result_chars` characters, and a read never spans more than 400 lines. The snapshot is never injected into the prompt: the agent reaches source only through tools.

Once the message history is estimated above `policy.max_working_set_tokens`, consumed `read_file`, `search_code`, `find_references`, `read_dependency`, and `read_tests` results are replaced with a provenance stub carrying `{path, line_start, line_end, content_digest}` and a note that the content was read. The system prompt, the task message, the result the agent is currently reasoning about, the accepted proposal, and the latest verification result are never evicted.

`propose_patch.changes` are line-range hunks, not whole files. Each is `{path, start_line, original_lines, replacement_lines}`, where `original_lines` are the lines the hunk replaces copied back verbatim from `read_file` and neither list carries newline characters. The quoted lines are the anchor, not the numbers: the service finds them in the exact snapshot, derives the real line range from that match, and computes the replaced digest itself, so no caller is asked to count a range or compute a hash it cannot compute. `start_line` is a hint. It is used only to disambiguate a block that occurs more than once, so a hunk whose quoted lines are unique is applied where they really are even when the hint is wrong. A block that occurs several times and whose hint names none of them is rejected as `original_lines_ambiguous:<path>`, naming the candidate line numbers rather than guessing. Quoted lines that are nowhere in the file are rejected as `original_lines_not_found:<path>`, and the rejection quotes the first line that differs together with what the snapshot holds there. `end_line` and `replaced_sha256` remain accepted for callers that already send them, the digest in prefixed or bare hexadecimal form; each is checked against the located range and disagreement is rejected as `hunk_line_range_inconsistent` or `stale_hunk_digest`. Hunks are applied bottom-up so earlier line numbers stay valid, overlapping hunks on one file are rejected as `overlapping_hunks`, and the file and changed-line caps apply to the applied result. The response still carries each candidate's full `replacement_content`, because that is what the sandbox materializes and what the apply path writes. The regression test remains a complete small file under `.mitig8it/regression/`.

Plan section 8 step 4 requires a reproducer that distinguishes a real repair from disabling the feature. With `require_generated_regression_test: true` the agent's `propose_patch` must supply `regression_test: {path, content}`:

- `path` must be `.mitig8it/regression/<name>.test.{js,cjs,mjs}` and must not name a file the snapshot already carries. Any other path, including a nested subdirectory or an application file, is rejected by patch policy.
- `content` must parse under `node --check` and may import only Node built-ins, the repository's declared dependencies, and relative repository paths. It is at most 64,000 bytes. The task message carries `sandbox.dependencies_installed`; when it is false the sandbox has no `node_modules` and no network, so a reproducer that requires a declared package, or the changed module through one, cannot run at all. The tool contract therefore directs the agent to assert on the changed file's source text read with `node:fs` in that case, and to require the changed module only when dependencies are installed.

The file is written into both the baseline and the candidate workspace and executed as an `exploit` check with argv `["node", "<path>"]` and a 60-second timeout: it must exit non-zero on the original tree and zero on the patched tree. It is never part of the candidate patch set, so it never reaches `verified_tree_oid` or the tree the batch applies.

The engine also derives, from the candidate alone and without any fixture:

| Derived check | Kind | argv | Expectation |
| --- | --- | --- | --- |
| `generated_regression_test` | `exploit` | `node <generated test path>` | baseline `failed`, candidate `passed` |
| `generated_node_syntax` | `typecheck` | `node --check <changed path>` | candidate `passed` |
| `generated_repository_test_script` | `existing_test` | `npm test --silent` | baseline and candidate equal |

A `generated_node_syntax` check is derived for every changed `.js`, `.cjs`, or `.mjs` file. `generated_repository_test_script` is derived only when `run_repository_tests` is true and the root `package.json` declares `scripts.test`; because the sandbox has no network, a snapshot without installed dependencies records a limitation instead. Policy-supplied checks always run as before, and the derived checks are additive.

A candidate that supplies no regression test, or whose test completes on the baseline tree without failing, is `inconclusive` with reason `regression_test_not_reproducing` and is never `ready`.

Each candidate carries `generated_tests: [{path, new_sha256, bytes, kind}]` alongside its `file_manifest`, whose entries carry `kind: "application"`. The batch manifest carries the union under `generated_tests`. Generated tests are reviewed with the batch and tracked separately from the application files, because they are verification evidence rather than the repair.

### Tool outcomes and repeated rejections

Every rejected tool call returns `{error, reason, guidance}`: `reason` is the stable code and `guidance` names the specific correction, for example which line differed and what the snapshot holds there, or the `node --check` diagnostic naming the line of the patched file that fails to parse. A diagnostic is stripped of the host temporary directory it was produced in and bounded before it is returned. Guidance may quote snapshot lines the agent is already authorized to read; it is returned to the model and never persisted.

`evidence.agent_trace` records one entry per tool call: `{sequence, tool, arguments_digest_only, outcome, reason, result_bytes}`. `outcome` is `ok`, `rejected`, `error`, or `abstained`. `reason` is the redacted stable code, restricted to code-shaped characters and 120 characters, and is null for an `ok` step. `result_bytes` is the size of the rendered tool result. File contents, patch text, and model prose never enter the trace.

Two consecutive rejections of the same tool for the same reason end the run as `unsupported` with reason `repeated_tool_rejection`. One rejection is a correction the agent can act on; a second identical one means the contract cannot be satisfied, and continuing would spend the whole budget on the same answer.

## Verification levels

Every candidate's evidence carries `evidence.verification_level`:

| Value | Meaning |
| --- | --- |
| `independent_sandbox` | The check pair ran in the isolated Kubernetes/gVisor sandbox with a digest-pinned runner image, denied network, and a read-only root filesystem. |
| `development_unverified` | The check pair ran through the development-only local subprocess driver with no network, kernel, or filesystem isolation. |

`development_unverified` evidence is accepted only when the request policy sets `allow_development_verification: true`. That field defaults to `false` and the API control plane keeps it `false` in production, so a development run can never be labelled with the production verification level. A response whose evidence carries an unrecognized level, or `development_unverified` without the policy flag, is never `ready`.

## Scanner findings contract

A `scanner` verification check compares baseline and candidate findings. The check must print exactly one JSON object line to standard output:

```json
{"mitig8it_scanner_findings": ["<fingerprint>", "..."]}
```

Each fingerprint is a non-empty string of at most 200 characters that stably identifies one finding (for example `<rule_id>:<path>:<normalized-snippet-digest>`), and at most 500 fingerprints are accepted. The last conforming line wins; any other repository output is ignored. The driver records the parsed list as `scanner_findings` on each baseline and candidate check result.

The verifier compares the sets. A candidate whose findings include any fingerprint absent from the baseline fails with `scanner_findings_regression`. A scanner check that produces no conforming report is `inconclusive` with `scanner_findings_report_missing`; an absent report is never read as "no findings".

## Coverage limitations

`evidence.limitations` is an honest list of required verification that did not run. It names, at minimum, an absent `existing_test` check, an absent `typecheck` and `build` pair, an absent `scanner` comparison, any check that did not complete on either tree, the development verification level when it applies, and why the repository test script was skipped. An empty list means every one of those checks ran. Limitations are computed over the effective check set, so a derived `typecheck` or `existing_test` counts exactly like a policy-supplied one.

The batch manifest binds `verified_tree_oid` to the tree the batch actually applies. A batch of two or more candidates is built from the union of their patches, is rejected as `overlapping_candidates` when two candidates change the same line range of one file, and is verified again on the combined tree; its `combined_verification_evidence_digest` refers to that combined run, not to any single candidate's evidence.

Each candidate's `preview.evidence` carries that candidate's own `verification_level` and `limitations`, alongside its `status`, `evidence_digest`, and `verified_tree_oid`. The response-level `evidence.verification_level` and `evidence.limitations` describe the combined verification run instead. A consumer that stores a per-candidate level must read it from the candidate, not from the response.

## Finding grouping

The request's findings are grouped into connected components before generation. Two findings are connected when they name any file in common, counting each finding's affected path and every repository path its `trace` entries name. One bounded agent loop runs per group, sequentially, and each group contributes at most one candidate whose `finding_ids` are exactly that group's findings.

The job's tool-call, token, and spend budgets are divided evenly across the groups with a per-group floor. The first group always runs. A later group whose share of the remaining budget falls below the floor is not launched, and its findings are reported as unsupported with reason `budget_exhausted`.

`evidence.groups` is an ordered array of `{group_index, finding_ids, state, reason, candidate_id}`, one entry per group. A response is `ready` when at least one group produced a verified candidate and the combined tree verified, even when other groups did not:

| Group reason code | Meaning |
| --- | --- |
| `budget_exhausted` | The remaining job budget was below the per-group floor, so no agent ran for these findings. |
| `overlapping_candidates` | This group's patch changes a line range an earlier accepted candidate already changes, so it was left out of the batch. |
| `verification_level_not_permitted` | The group's evidence carried a level this policy does not accept. |
| any agent reason code | The group's bounded loop abstained or could not reach verified evidence. |

Partial coverage is therefore explicit. A finding absent from every candidate's `finding_ids` was not repaired, and `evidence.groups` states why.

## Trace context

Intake accepts a W3C `traceparent` header and continues that trace. The trace context is persisted with the execution, and the worker links its span to it rather than reparenting, because the stage is resumed asynchronously. Tracing is exported only when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured. Exported span attributes are restricted to an allowlist (job id, stage, attempt, model/prompt/policy version, outcome, error category, token counts, cost estimate) and pass a redaction guard that rejects oversized and secret-like values. No source, prompt, completion, patch, or tool output is ever exported as telemetry.

Terminal GET success uses HTTP 200 and `state: ready | unsupported | inconclusive`. `ready` contains immutable `candidates`, ordered `manifest_digest`, source/patch/evidence digests, full `replacement_content` plus `contents_base64`, previews, and the verified Git tree OID. A result cannot be `ready` unless the configured external broker returned authenticated evidence that binds the request nonce, original and candidate snapshot digests, exact checks, image, head tree, and candidate tree. Missing dependencies/configuration return `unsupported`; transient provider/broker failures and incomplete or invalid evidence return `inconclusive`.

Authentication failure is 401, absent service auth configuration is 503, unsupported media type is 415 after routing, and schema failure is 422. The API control plane owns durable workflow fencing and response persistence. It must reject any response whose job, tenant, repository, revisions, request digest, manifest, or tree identity differs from persisted input.

FastAPI publishes the mechanically generated OpenAPI/JSON Schemas at `/openapi.json`; this document defines the cross-service semantics those schemas cannot express.
