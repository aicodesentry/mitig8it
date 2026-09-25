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

`propose_patch.changes` are line-range hunks, not whole files. Each is `{path, finding_id, start_line, original_lines, replacement_lines}`, where `finding_id` names the finding the hunk fixes (an import-only hunk names the finding whose fix needs it; an id outside the task's findings is rejected as `hunk_finding_unknown`) and `original_lines` are the lines the hunk replaces copied back verbatim from `read_file` and neither list carries newline characters. The quoted lines are the anchor, not the numbers: the service finds them in the exact snapshot, derives the real line range from that match, and computes the replaced digest itself, so no caller is asked to count a range or compute a hash it cannot compute. `start_line` is a hint. It is used only to disambiguate a block that occurs more than once, so a hunk whose quoted lines are unique is applied where they really are even when the hint is wrong. A block that occurs several times and whose hint names none of them is rejected as `original_lines_ambiguous:<path>`, naming the candidate line numbers rather than guessing. Quoted lines that are nowhere in the file are rejected as `original_lines_not_found:<path>`, and the rejection quotes the first line that differs together with what the snapshot holds there. `end_line` and `replaced_sha256` remain accepted for callers that already send them, the digest in prefixed or bare hexadecimal form; each is checked against the located range and disagreement is rejected as `hunk_line_range_inconsistent` or `stale_hunk_digest`. Hunks are applied bottom-up so earlier line numbers stay valid, overlapping hunks on one file are rejected as `overlapping_hunks`, and the file and changed-line caps apply to the applied result. The response still carries each candidate's full `replacement_content`, because that is what the sandbox materializes and what the apply path writes. The regression test remains a complete small file under `.mitig8it/regression/`.

Plan section 8 step 4 requires a reproducer that distinguishes a real repair from disabling the feature. With `require_generated_regression_test: true` the agent's `propose_patch` must supply `regression_tests: [{finding_id, path, content}]`, one entry per finding the patch repairs:

- `finding_id` must be one of the task's finding ids, and each finding may have at most one test. An unknown id is rejected as `regression_test_finding_unknown`, a second test for the same finding as `duplicate_regression_test_finding`, and the retired single `regression_test` field as `regression_tests_required`.
- `path` must be `.mitig8it/regression/<name>.test.{js,cjs,mjs}` for a JavaScript group or `.mitig8it/regression/<name>.test.py` for a Python group, and must not name a file the snapshot already carries. Any other path, including a nested subdirectory or an application file, is rejected by patch policy.
- `content` must parse under `node --check` and may import only Node built-ins, the repository's declared dependencies, and relative repository paths. It is at most 64,000 bytes. It must exercise behavior: require the changed module by relative path and invoke the affected function or route handler with fake `req` and `res` objects, through the service harness at `.mitig8it/harness.js` (`require('../harness')`, see [test-harness-v1.md](test-harness-v1.md)), which injects fake `express`, `pg`, `child_process`, and `fs` and records every call, so nothing needs to be installed. A test that requires any other package is rejected as `missing_dependency:<name>`, and a proposal or test that writes to `.mitig8it/harness.js` is rejected as `harness_path_protected`. A test that reads a file with `fs.readFileSync` or `fs.readFile` and never requires a repository module can only assert on wording, and is rejected as `regression_test_reads_source_as_text`.

A Python group is the same contract in its own language: `content` must parse under `python -m py_compile`, may import only the standard library, repository modules, and the service harness (`import harness as h`, see [test-harness-python-v1.md](test-harness-python-v1.md)), and a test that requires `pytest`, `flask`, `requests`, or a database driver is rejected as `missing_dependency:<name>`. A proposal that writes to `.mitig8it/harness.py` is rejected as `harness_path_protected`, exactly as for the Node harness. A finding group is one language, so a group uses one harness.

Each test is written into both the baseline and the candidate workspace and executed as its own `exploit` check with a 60-second timeout: argv `["node", "<path>"]` for a JavaScript test, and `["python3", ".mitig8it/harness.py", "<path>"]` for a Python one, because the Python harness is also the runner. A finding is proven when its test exits non-zero on the original tree and zero on the patched tree. The verifier decides per finding: a candidate's `finding_ids` are exactly the proven findings, and every other finding in the group is reported in the response's `skipped` list with `regression_test_not_reproducing` when its test also passed on the original code, or `not_repaired` when it had no test, still failed on the patched code, or did not complete. A candidate with zero proven findings is never `ready`: it is `inconclusive` with `regression_test_not_reproducing` when a test did not reproduce, and `failed` with `verification_failed` when every test still failed on the patched code. The tests are never part of the candidate patch set, so they never reach `verified_tree_oid` or the tree the batch applies.

### Runtime load check

A syntax check proves a changed file parses; it does not prove its top level runs. After the syntax check, patch policy materializes the candidate tree into a temporary directory and loads every changed `.js`, `.cjs`, and `.mjs` file with `node -e` (a `require` for CommonJS, a dynamic `import` for `.mjs`) and every changed `.py` file with `runpy.run_path` under a module name that is not `__main__`, in both cases under a 10-second timeout. A module that throws when loaded, such as a `ReferenceError` or a `NameError` for an identifier used without its import, is rejected as `candidate_load_failed:<path>` with the runtime's diagnostic, so the agent adds the missing `require` or `import` in another hunk of the same call. A module that cannot be loaded for a reason the candidate did not introduce is a recorded limitation rather than a failure: a dependency the snapshot declares but does not carry (`MODULE_NOT_FOUND`), an ES module Node cannot `require`, an environment variable a Python module reads at import time, a timeout, a host without the runtime, or an original module that already throws on load.

### Repair families and languages

A finding is classified into one of five families from its CWE and rule text. Language follows the affected file's extension: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` are JavaScript and `.py` is Python; a group that mixes both is split by language before any agent runs.

| Family | JavaScript | Python |
| --- | --- | --- |
| `sql_parameterization` | yes | yes |
| `command_arguments` | yes | yes |
| `path_containment` | yes | yes |
| `hardcoded_credential` | yes | yes |
| `code_injection_eval` | yes | yes |

Both toolchains carry every family. A family is listed for a language only once the harness can observe the repair: the Node harness records environment reads, and it records `eval`, `new Function`, the `vm` compile calls, and a string `setTimeout`/`setInterval` without running any of them. A finding whose family is not supported for its language is reported in `skipped` as `unsupported_rule_family`; what refuses a finding today is the shape, through the static gates below.

Before any agent runs, a finding may also be reported in `skipped` as `rule_family_disabled` (the family is not in `policy.allowed_rule_families`), `affected_source_missing` (the affected path is absent from the snapshot), `unsupported_language` (neither JavaScript nor Python), or one of three static gate codes: `pg_dependency_not_proven` (a JavaScript SQL repair whose snapshot declares no `pg` dependency), `shell_pipeline_unsupported` (the command string's own literal text carries a pipeline, a redirection, a separator, or a substitution, which no argument list expresses), `ambiguous_query_api` (a Python query that reaches no known driver `execute()`, so the placeholder style cannot be chosen safely), and `dynamic_code_unsupported` (a JavaScript `new Function`, `new vm.Script`, or `vm` compile call, which hands back something the module calls later, so no data parser stands in for it). These gates are abstentions by design; they cost no budget and no provider call.

### Service-generated proofs and template-first patches

For every supported finding the service attempts both halves of the repair before any model call. It derives the enclosing site (the request handler that encloses the finding, on either language, else the function or method that does), generates one harness regression test from that site, and attempts a deterministic template hunk for the family. Template hunks are combined per group, bundled with the service proofs, and verified exactly like a model proposal; a pass that ships from this path records `{"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []}` and never reaches a provider. The model is asked only for findings the template pass did not prove, and it receives the same service-written proof plus the failure tail of a template that failed. A finding still unproven after the group pass gets one focused single-finding run unless the model deliberately abstained. `evidence.groups[].reason_evidence` records which path produced what.

#### A finding at module scope

Code with no enclosing callable runs once, when the module is imported. The template rewrites the sink in place exactly as it would inside a function, and the proof drives it by setting what the module reads and then importing it, so what decides whether a proof exists is where the tainted value comes from:

| Source | How the proof drives it |
| --- | --- |
| `process.env.NAME`, `os.environ["NAME"]`, `os.getenv("NAME")` | `h.load(path, { env: { NAME: payload } })` / `h.load(path, env={"NAME": payload})`, then the family assertion on the load. |
| `process.argv[i]`, `sys.argv[i]` | the same load with `argv`, the payload at the index the module reads. |
| a member of a module required at the top level, JavaScript only and a relative specifier only | the same load with `stubs`, standing the module in. A member that is called rather than read is not one of these: replacing the function with a payload would break the module instead of driving it. |
| a literal or a module-level constant | asserted on the load directly, which is the `hardcoded_credential` shape: the literal is the sink. |
| anything else | refused as `module_scope_source_not_controllable`. |

A `path_containment` repair at module scope throws or raises during the import, because there is no caller to answer, so its proof asserts that the import itself is refused for every traversal payload and still succeeds for a legitimate name.

#### How a generated proof lines a call up with a parameter list

A proof of a helper calls it, so it has to build an argument list the signature accepts. Each
JavaScript parameter is read as one of four forms, and the payload is placed accordingly:

| Form | Example | What the call passes |
| --- | --- | --- |
| a plain name | `name` | the payload, or an inert value |
| a name with a default | `options = {}` | the same, positionally |
| a rest element | `...rest` | nothing, because an extra argument changes the array the function sees, and it never carries the payload |
| a destructuring | `{ name }` | an object literal, with the payload under the member the body reads |

A destructured parameter binds its members rather than itself, so the member is what the taint
lookup and the template find; anything positional, such as the response a handler answers
through, is read from the parameter list's own order instead. `function_parameters_not_plain_names`
is now only a list a call cannot be built for without guessing: nested destructuring, an array
pattern, or a default inside a destructuring.

#### Why a service proof is refused

A proof the service cannot write is reported in `reason_evidence.proofs` as `model:<reason>`, and the same code appears in `templates` as `not_attempted:<reason>` because a template without a proof is never attempted. The reasons that turn on the file rather than on the site:

| Reason | Meaning |
| --- | --- |
| `module_not_loadable_by_node` | The affected file's suffix is not one the sandbox's Node can run: `.js`, `.cjs`, `.mjs`, `.ts`, `.cts`, and `.mts` are, and `.jsx` and `.tsx` are not, because strip-only mode deletes type syntax and does not transform JSX. |
| `typescript_syntax_not_strippable:<construct>` | The TypeScript file carries an `enum`, a `namespace`, or a constructor parameter property. Each has to be compiled into code rather than deleted, so Node's strip-only mode refuses the whole file with `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`. |
| `module_scope_source_not_controllable` | The finding is at module scope and the value reaching its sink comes from a call that happens on import, so no test can make the reproducer fail before the repair and pass after it. |

TypeScript is loaded by Node's own type stripper rather than by a toolchain: the sandbox still installs nothing and compiles nothing. One shape is not detectable in advance and so is not refused: an interface imported as an ordinary value binding (`import { Settings, settings } from './config'` rather than `import type`) survives stripping and names an export the stripped module does not have. That module fails to load, so its proof fails; it is never a false pass.

#### Where a `path_containment` repair finds the path, and when it refuses

Three shapes are repair sites, on both halves, because all three are how real code builds a path:

| Shape | Example | What the repair contains against |
| --- | --- | --- |
| a join call | `path.join(BASE, name)`, `path.resolve(__dirname, 'static', name)` | every argument but the last |
| a concatenation | `'./data/static/' + key + '.yml'` | up to the last separator a literal carries |
| a template literal | `` `${base}/${name}` `` | the same |

A join is read by its brackets rather than by a pattern, so a call with more than two arguments
keeps its whole base. A composition is read only out of a filesystem sink's first argument, so a
message built on the same line is not mistaken for a path, and a `this.` receiver is excluded
because `this.dialog.open(...)` is a UI call rather than a sink.

The module that a repair writes `resolve` and `sep` against is the one the file already binds,
under whatever name and in whatever style it binds it: a require under the module's own name or
an alias, an ESM default or namespace import, and `node:path` or `path` alike. A file that binds
none gets the import as part of the same patch, in its own style, at the top of its import block.

| Reason | Meaning |
| --- | --- |
| `path_identifier_shadowed` | The file does not bind `node:path` and already declares `path` as something of its own, so the import a repair would add is shadowed at the line the repair rewrites. |
| `path_argument_is_constant` | The sink's path argument is a string literal. There is no untrusted component, so there is nothing to contain and no test that could fail before a repair. |
| `path_argument_not_composed_in_scope` | The path reaches the sink as a single value built somewhere the enclosing scope does not show. |
| `path_join_not_found_in_scope` | No filesystem sink is on any line of the enclosing scope. |

The last three are correct refusals rather than gaps, and they are named apart so a reader can
tell them from one.

The containment check is the same wherever the path is built: resolve the base, resolve the
candidate against it, and compare before anything touches the filesystem. How the repair refuses
an escaping path depends on what the site can promise its caller.

| Site | Refusal |
| --- | --- |
| Express route handler | `return res.status(400).end()` |
| A route handler the module exports but never registers with Express | `return res.status(400).end()`, the same: it owns a response either way, and its second parameter is it |
| Flask view | `abort(400)` |
| A JavaScript function that takes a callback | `return callback(new Error('path escapes base directory'))` |
| Any other JavaScript function, method, or module-scope code | `throw new Error('path escapes base directory')` |
| Any other Python function, method, or module-scope code | `raise ValueError('path escapes base directory')` |

A handler owns the response, so it answers, and a function that takes a continuation reports
through it, because that is how it already reports every other failure. A plain function has
neither a response to write nor a declared failure value, and a returned sentinel is the one outcome a caller can mistake for a
path: `null` reaching `fs.readFile` is a crash at a distance, and `''` resolves to the base
directory itself. Raising is the only refusal a caller cannot read as success. A caller that does
not catch turns a file disclosure into a 500, which is the trade this family is for; a caller that
wants a sentinel catches and returns one. The generated proof asserts both halves: the traversal
payload is refused and reads nothing, and a legitimate name still resolves, so a repair cannot
pass by refusing everything.

### Static undefined-name check

After the load check, patch policy parses every changed Python file with `ast` and rejects a name the change introduces that the file binds nowhere (builtins, parameters, imports, definitions, assignments, `global` declarations, and exception, loop, comprehension, and pattern targets all count, wherever they appear) as `undefined_name:<name>`, because such a name raises `NameError` only when its function runs, which neither `py_compile` nor the load check reaches. A name the original file already used unbound is not held against the candidate, and a star import or a call to `exec`, `globals`, `locals`, or `vars` makes the check abstain. Changed JavaScript and TypeScript files get a lexical equivalent for identifiers the change introduces in call or member-root position that no declaration, import, `require`, parameter, or `catch` binding in the file could bind, such as `execFile(...)` added without its `require`; the guidance tells the agent to add the import in another hunk of the same call.

The engine also derives, from the candidate alone and without any fixture:

| Derived check | Kind | argv | Expectation |
| --- | --- | --- | --- |
| `generated_regression_test` (one per finding, suffixed `_2`, `_3`, ...) | `exploit` | `node <generated test path>` | baseline `failed`, candidate `passed` proves that finding |
| `generated_node_syntax` | `typecheck` | `node --check <changed path>` | candidate `passed` |
| `generated_repository_test_script` | `existing_test` | `npm test --silent` | baseline and candidate equal |

A `generated_node_syntax` check is derived for every changed `.js`, `.cjs`, or `.mjs` file. `generated_repository_test_script` is derived only when `run_repository_tests` is true and the root `package.json` declares `scripts.test`; because the sandbox has no network, a snapshot without installed dependencies records a limitation instead. Policy-supplied checks always run as before, and the derived checks are additive.

A regression check whose finding is unproven is left out of the pass/fail outcome: its finding is dropped from the candidate instead of failing the verification of the findings that were proven. Policy-supplied checks and the derived syntax and repository-test checks still gate the whole candidate.

Each candidate carries `generated_tests: [{path, finding_id, new_sha256, bytes, kind}]` alongside its `file_manifest`. The batch manifest carries the union under `generated_tests`. Generated tests are reviewed with the batch and tracked separately from the application files, because they are verification evidence rather than the repair.

## Candidate file manifest

The control plane commits whole files, never hunks, and never reconstructs content from a diff. Each candidate's `file_manifest` is therefore

```json
{"files": [{"path": "...", "base_sha256": "sha256:...", "new_sha256": "sha256:...", "contents_base64": "...", "blob_oid": "<40 hex>", "bytes": 123, "kind": "application"}], "verified_tree_oid": "<40 hex>"}
```

with one entry for every changed application file. `contents_base64` is the complete post-patch file exactly as the sandbox materialized it, `blob_oid` is the Git blob SHA-1 of those bytes, and `verified_tree_oid` is the tree obtained by replacing each changed path's blob in the head tree with that `blob_oid`; committing exactly these contents on the consented head reproduces `verified_tree_oid`, which the GitHub adapter checks after the commit. The API persists this object on `remediation_candidates.file_manifest`, and the apply worker reads `files[].contents_base64` from it; a candidate without full contents blocks the apply with `verified_full_file_manifest_unavailable`.

### Tool outcomes and repeated rejections

A check that exits non-zero records `output_tail`, the last 800 characters of its combined output, on that variant's result; a passing check records none. `inspect_failure` returns it with the check, so the agent sees why a generated test crashed rather than only its exit code.

Every rejected tool call returns `{error, reason, guidance}`: `reason` is the stable code and `guidance` names the specific correction, for example which line differed and what the snapshot holds there, or the `node --check` diagnostic naming the line of the patched file that fails to parse. A diagnostic is stripped of the host temporary directory it was produced in and bounded before it is returned. Guidance may quote snapshot lines the agent is already authorized to read; it is returned to the model and never persisted.

`evidence.agent_trace` records one entry per tool call: `{sequence, tool, arguments_digest_only, outcome, reason, result_bytes}`. `outcome` is `ok`, `rejected`, `error`, `abstained`, or `revision_requested` (a passed verification that proved only some of the group's findings and sent the agent back for the rest, reason `partial_coverage`). A group's trace begins with one `template_patch` step (sequence 0) when the service attempted deterministic hunks for it, with outcome `ok`, `rejected`, or `not_proven`; a focused per-finding retry appends its own steps after the group pass. `evidence.groups[].reason_evidence` carries `proofs` (per finding, `service` when the service generated its regression test, else `model:<reason>`), `templates` (`proven`, `not_proven`, `rejected:<code>`, or `not_attempted:<reason>`), `candidate_sources` (`template`, `model`, or `retry` per proven finding), and `retries` (the outcome of each focused retry); each candidate's `preview.evidence.candidate_source` names the path that wrote its hunks. A finding with a service-generated proof may carry one model-written test beside it (at most two tests per finding), and is proven only when every test of it fails on the original code and passes on the candidate. `reason` is the redacted stable code, restricted to code-shaped characters and 120 characters, and is null for an `ok` step. `result_bytes` is the size of the rendered tool result. File contents, patch text, and model prose never enter the trace.

### Coverage revisions

The task prompt lists every finding in the group with its id, repair family, path, and line range, and states that `propose_patch` carries one regression test per finding the agent intends to fix; the `propose_patch` result names the findings that still lack a test (`findings_with_test`, `findings_without_test`). When a verification passes but proves only a strict subset of the group, and `policy.max_revisions` (default 2), `policy.max_attempts`, and the tool budget allow, the verification result carries `coverage_revision`: each unproven finding with its lines, the verifier's reason, the family's harness assertion, its test path and the last 400 characters of that test's own failure output when a test existed, and the instruction to propose the complete proposal again with hunks and tests added for those findings only. The revised proposal must keep the test of every finding already proven (`coverage_revision_drops_proven_test`) and must precede the next `request_verification` (`coverage_revision_requires_new_proposal`); the re-verification spends one of `max_attempts` and every provider call is reserved and settled as usual. The run stops when every finding is proven, the revision, attempt, or tool budget is spent, or the agent abstains. Whatever stops it, the candidate that ships is the verified one that proved the most findings without losing any, claiming exactly its proven findings; `evidence.groups[].coverage` records `revisions_used`, `max_revisions`, `proven_finding_ids`, and `stopped` (`all_proven`, `revision_budget_spent`, `attempt_budget_spent`, `tool_budget_spent`, or the reason the run ended).

Two consecutive rejections of the same tool for the same reason end the run as `unsupported` with reason `repeated_tool_rejection`. One rejection is a correction the agent can act on; a second identical one means the contract cannot be satisfied, and continuing would spend the whole budget on the same answer.

## Verification levels

Every candidate's evidence carries `evidence.verification_level`:

| Value | Meaning |
| --- | --- |
| `independent_sandbox` | The check pair ran in the isolated Kubernetes/gVisor sandbox with a digest-pinned runner image, denied network, and a read-only root filesystem. |
| `isolated_job` | Each half of the check pair ran in its own Cloud Run job container, as an unprivileged user holding none of the job's credentials, on a network that the task's own probes measured as unreachable before the check started. The image digest matches `policy.sandbox_image_digest`. There is no read-only root filesystem and no gVisor runtime class. |
| `development_unverified` | The check pair ran through the development-only local subprocess driver with no network, kernel, or filesystem isolation. |

Levels are ordered `development_unverified` < `isolated_job` < `independent_sandbox`.

`isolated_job` evidence carries `runner.environment_kind: "cloud-run-job"`, `runner.job_executions` naming every Cloud Run execution that produced it, and, on every completed baseline and candidate result, `network_probes` with a `metadata`, `internet`, and `dns` entry and that result's own `job_execution`. Each probe must report `reached: false`; `reached: null` means the probe did not run and is refused exactly like a probe that connected. The driver itself refuses first: a reached or unmeasured probe returns `inconclusive` with `sandbox_network_not_denied`, and a task that reported an image digest other than the pinned one returns `inconclusive` with `sandbox_image_digest_mismatch`. Neither carries check results, so partial evidence can never be read as a pass. `isolated_job` evidence is accepted only when the request policy sets `allow_isolated_job_verification`, which defaults to `true`.

`development_unverified` evidence is accepted only when the request policy sets `allow_development_verification: true`. That field defaults to `false` and the API control plane keeps it `false` in production, so a development run can never be labelled with the production verification level. A response whose evidence carries an unrecognized level, `development_unverified` without the policy flag, or `isolated_job` with `allow_isolated_job_verification: false`, is never `ready`.

## Scanner findings contract

A `scanner` verification check compares baseline and candidate findings. The check must print exactly one JSON object line to standard output:

```json
{"mitig8it_scanner_findings": ["<fingerprint>", "..."]}
```

Each fingerprint is a non-empty string of at most 200 characters that stably identifies one finding (for example `<rule_id>:<path>:<normalized-snippet-digest>`), and at most 500 fingerprints are accepted. The last conforming line wins; any other repository output is ignored. The driver records the parsed list as `scanner_findings` on each baseline and candidate check result.

The verifier compares the sets. A candidate whose findings include any fingerprint absent from the baseline fails with `scanner_findings_regression`. A scanner check that produces no conforming report is `inconclusive` with `scanner_findings_report_missing`; an absent report is never read as "no findings".

## Coverage limitations

`evidence.limitations` is an honest list of required verification that did not run. It names, at minimum, an absent `existing_test` check, an absent `typecheck` and `build` pair, an absent `scanner` comparison, any check that did not complete on either tree, the development verification level when it applies, and why the repository test script was skipped. An empty list means every one of those checks ran. Limitations are computed over the effective check set, so a derived `typecheck` or `existing_test` counts exactly like a policy-supplied one.

The batch manifest binds `verified_tree_oid` to the tree the batch actually applies. A batch of two or more candidates is built from the union of their patches, applying the same change at the same place once (two per-finding candidates may share a prerequisite hunk such as an added import), is rejected as `overlapping_candidates` when two candidates change the same line range of one file differently, and is verified again on the combined tree unless that tree is one a run already verified with every claimed finding's test; its `combined_verification_evidence_digest` refers to that combined run, not to any single candidate's evidence.

Each candidate's `preview.evidence` carries that candidate's own `verification_level` and `limitations`, alongside its `status`, `evidence_digest`, `verified_tree_oid`, and `summary`: one sentence per piece of evidence (`Regression test <path> failed on the original code and passed on the fix.`, one line per other check with its outcome, and `Not run: ...` for every limitation that says a check did not run). `preview.hunks` lists the candidate's located hunks as `{path, start_line, end_line, finding_id}`. The response-level `evidence.verification_level` and `evidence.limitations` describe the combined verification run instead. A consumer that stores a per-candidate level must read it from the candidate, not from the response.

## Finding grouping

The request's findings are grouped into connected components before generation. Two findings are connected when they name any file in common, counting each finding's affected path and every repository path its `trace` entries name. One bounded agent loop runs per group, sequentially, and each group contributes one candidate per finding it proves. After the group verification the engine attributes each hunk to a finding (its `finding_id`, or the nearest finding on its path when untagged; an import-only hunk is shared by every finding whose hunks use a name it binds), drops every hunk owned by an unproven finding, rebuilds one candidate per proven finding from its own hunks plus the prerequisites they use, and verifies each candidate on its own tree unless that tree is the one the group run verified. A finding whose test does not pass on its own candidate is reported `dependent_hunk_unproven` and ships nothing. Each candidate's `finding_ids` is therefore the one finding its evidence covers, and its patch carries no hunk owned by an unproven finding.

The job's tool-call, token, and spend budgets are divided evenly across the groups with a per-group floor. The first group always runs. A later group whose share of the remaining budget falls below the floor is not launched, and its findings are reported as unsupported with reason `budget_exhausted`.

### Leases and resumption

The worker holds a lease on an execution and renews it every `REMEDIATION_WORKER_HEARTBEAT_SECONDS` (default 15). `REMEDIATION_WORKER_LEASE_SECONDS` (default 90) is the lease length and is clamped to at least three heartbeat intervals, so a lease survives missed renewals instead of expiring on the first one. The heartbeat shares the event loop with the repair, so blocking work inside the repair is run in a worker thread: `build_patch_bundle` shells out to `node --check`, and the sandbox driver's subprocesses already run through `asyncio.to_thread`.

An execution is reclaimable only once `lease_expires_at` has passed. Reclaiming bumps `attempt`, and `complete` requires the caller to still hold the lease, so a superseded attempt that finishes late cannot publish over the worker that took the work.

A checkpoint carrying a `pending_action` was written by `save_provider_action`, which settles the reservation in the same statement. That call is therefore already paid for: a resumed pending action neither reserves again nor settles again. With no pending action the next call is an ordinary one that reserves and then settles.

### Reservations, settlement and the hard caps

Before each provider call the service reserves an estimated token and dollar amount against the execution row. The estimate uses a bytes-per-token proxy with headroom, so it is approximate by construction. When the provider's reported usage comes in above the reservation, the call is settled at its **actual** cost rather than refused: the execution is charged what it really used, and the difference is recorded as an overage.

`evidence.budget_reservation` carries `{settled_calls, overage_calls, overage_tokens, overage_usd, settlements}`, where each settlement is `{call_index, reserved_tokens, reserved_usd, actual_tokens, actual_usd, overage_tokens, overage_usd}`. Every result carries it, not only a refused one, so an overage is visible on a job that otherwise succeeded. The list is bounded at 50 entries.

Only `policy.max_total_tokens` and `policy.max_spend_usd` refuse work. A call whose settlement takes cumulative actual spend past either cap ends the run as `inconclusive` with reason `budget_cap_exceeded`, after the spend has been recorded, so the cost of the crossing call is never lost.

Settling against an **absent** reservation still raises: a call that was never announced is a protocol violation, not an estimate that came in high, and it ends the run as `checkpoint_unavailable`.

`evidence.groups` is an ordered array of `{group_index, finding_ids, state, reason, candidate_id, candidate_ids}`, one entry per group (`candidate_id` is the first of `candidate_ids`); a group with candidates adds `repaired_finding_ids`, and a group whose candidate proved only some of its findings adds `unproven_findings: [{finding_id, code, message}]`. A response is `ready` when at least one group produced a verified candidate and the combined tree verified, even when other groups did not:

| Group reason code | Meaning |
| --- | --- |
| `budget_exhausted` | The remaining job budget was below the per-group floor, so no agent ran for these findings. |
| `budget_cap_exceeded` | Cumulative actual provider spend passed `max_total_tokens` or `max_spend_usd`. The call that crossed the cap is settled and recorded first. |
| `overlapping_candidates` | This group's patch changes a line range an earlier accepted candidate already changes, so it was left out of the batch. |
| `regression_test_not_reproducing` | No finding in the group was shown repaired by its own regression test. |
| `dependent_hunk_unproven` | Every proven finding in the group was proven only together with hunks owned by an unproven finding, which are never shipped; the same code names each such finding in `skipped`. |
| `verification_level_not_permitted` | The group's evidence carried a level this policy does not accept. |
| `sandbox_network_not_denied` | A Cloud Run job sandbox probe reached its target, or could not be run, so the network was not shown denied and no check result is reported. |
| `sandbox_image_digest_mismatch` | A Cloud Run job task reported running an image other than the pinned `policy.sandbox_image_digest`, or could not report one at all. |
| any agent reason code | The group's bounded loop abstained or could not reach verified evidence. |

Partial coverage is therefore explicit. A finding absent from every candidate's `finding_ids` was not repaired, and `evidence.groups` states why. The response-level `skipped: [{finding_id, code, message}]` lists every such finding the request carried, including findings outside the enabled families and findings a candidate's group could not prove (`not_repaired`, `regression_test_not_reproducing`, `dependent_hunk_unproven`). A batch of two or more candidates must also prove every claimed finding again on the combined tree; otherwise the response is `inconclusive` with `combined_verification_failed`.

## Trace context

Intake accepts a W3C `traceparent` header and continues that trace. The trace context is persisted with the execution, and the worker links its span to it rather than reparenting, because the stage is resumed asynchronously. Tracing is exported only when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured. Exported span attributes are restricted to an allowlist (job id, stage, attempt, model/prompt/policy version, outcome, error category, token counts, cost estimate) and pass a redaction guard that rejects oversized and secret-like values. No source, prompt, completion, patch, or tool output is ever exported as telemetry.

Terminal GET success uses HTTP 200 and `state: ready | unsupported | inconclusive`. `ready` contains immutable `candidates`, ordered `manifest_digest`, source/patch/evidence digests, full `replacement_content` plus `contents_base64`, previews, and the verified Git tree OID. A result cannot be `ready` unless the configured external broker returned authenticated evidence that binds the request nonce, original and candidate snapshot digests, exact checks, image, head tree, and candidate tree. Missing dependencies/configuration return `unsupported`; transient provider/broker failures and incomplete or invalid evidence return `inconclusive`.

Authentication failure is 401, absent service auth configuration is 503, unsupported media type is 415 after routing, and schema failure is 422. The API control plane owns durable workflow fencing and response persistence. It must reject any response whose job, tenant, repository, revisions, request digest, manifest, or tree identity differs from persisted input.

FastAPI publishes the mechanically generated OpenAPI/JSON Schemas at `/openapi.json`; this document defines the cross-service semantics those schemas cannot express.
