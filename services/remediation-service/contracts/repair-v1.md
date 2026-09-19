# Repair HTTP contract v1

`POST /v1/repair` is the canonical authenticated durable intake operation. `POST /v1/repair-stages` is a compatibility alias with the identical request and response. It returns HTTP 202 with `{schema_version, execution_id, state}` after the request artifact and execution row are durable. `GET /v1/repair/{execution_id}` returns `running` or the terminal `ready | unsupported | inconclusive` result. Send `Authorization: Bearer <REMEDIATION_SERVICE_INTERNAL_SECRET>`; `x-internal-secret` is accepted only as a migration fallback.

The JSON request is validated by `src.models.RepairRequest` with unknown fields rejected. Required security bindings are:

- `schema_version: "v1"`, `job_id`, `tenant_id`, `repository_id`;
- exact `head_sha` and `base_sha`;
- `head_tree_oid`, `tree_truncated: false`, and the complete recursive-head leaf metadata in `tree_entries: [{path, mode, type, sha}]`;
- immutable finding snapshots and bounded `files: [{path, content, sha?}]` from the trusted control plane;
- `profile`, `policy`, and a non-empty `versions` manifest.

`sha` on a file accepts a 40-hex Git blob SHA-1 or a SHA-256 (64 hex or `sha256:` form). File content is always verified against its matching Git tree blob before generation. A complete tree is required because the applicable response includes an independently attested real Git `verified_tree_oid`; a SHA-256 manifest is never mislabeled as a Git tree OID.

The policy's `verification_checks` are fixed argv arrays selected by the trusted control plane, never model-selected shell strings. A `ready` result requires at least one `exploit` and one `behavior` check plus a digest-pinned sandbox runner image. Other check kinds are `existing_test`, `typecheck`, `build`, and `scanner`.

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

`evidence.limitations` is an honest list of required verification that did not run. It names, at minimum, an absent `existing_test` check, an absent `typecheck` and `build` pair, an absent `scanner` comparison, any check that did not complete on either tree, and the development verification level when it applies. An empty list means every one of those checks ran.

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
