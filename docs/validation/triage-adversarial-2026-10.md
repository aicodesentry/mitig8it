# Adversarial per-finding triage, October 2026

Branch `feat/triage-adversarial-per-finding`. Written 17 October 2026.

**Nothing here has been measured against a model.** No provider key that the triage client
supports was available when this was written. Every result below comes from a fake `call_llm`
or from the evaluation harness's stub model, so it shows what the service does with an answer,
not what a model answers. The command that produces the live numbers is in
[Measuring it](#measuring-it).

## What changed

Before this branch, tier 3 was one call over the whole batch of findings at temperature 0, with
a prompt that asked for a verdict per finding. Two failures follow from that, and both appear in
[action-trial-2026-09.md](action-trial-2026-09.md):

* A critical finding could be confirmed with nothing showing how input reaches the sink. The
  trial's examples are `vm.runInContext` over a constant script in juice-shop's
  `routes/fileUpload.ts`, and express's own definition of `res.redirect`.
* A `fixed_code` from the model, or the deterministic patch, was attached when the verdict was
  `true_positive`. Nothing checked whether the patch removes the exposure.

The changes, all in `services/analysis-service/src/llm_triage.py` unless named:

1. **Isolation.** Findings at or above `LLM_TRIAGE_ISOLATE_SEVERITY` (default `high`) get one
   call each. The rest share one batched call. Isolated calls use `LLM_TRIAGE_MODEL_HIGH` when it
   is set and the batch model otherwise (`llm_client.call_llm` gained a per-call `model`).
2. **Budget.** Each run has a call cap (`LLM_TRIAGE_MAX_CALLS`, default 24) and a token cap
   (`LLM_TRIAGE_MAX_TOKENS`, default 300,000), checked before every call. A refused triage call
   leaves its findings untriaged. A refused critic call withholds the fix. The run logs
   `budget N/M calls, T/U tokens, R calls refused covering F findings`.
3. **Exploit payload.** The prompt now asks for reachability first, then
   `exploit_payload: {entrypoint, input, expected_effect}`, then the verdict. A high or critical
   `true_positive` (by the scanner's severity or the model's adjusted one) whose payload is
   missing, a placeholder, has an entrypoint that names only other files, or names neither the
   finding's file nor an identifier from the flagged line, becomes `uncertain` with reason
   `no_concrete_payload`. The reason is stored in `llm_triage.downgrade` and in
   `evidence_details.extra.triage_downgrade_reason`, which crosses gRPC and is stored with the
   finding.
4. **Patch critic.** Before a fix is attached, a second call receives the finding, the original
   lines, the proposed replacement, the surrounding diff and the payload, and must answer `NONE`
   or a counterexample input that still reaches the sink, plus a one-sentence `behavior_risk`.
   A counterexample, an answer that does not parse, a failed call and an exhausted budget all
   withhold the fix. The outcome is in `evidence_details.extra.fix_critic_*`. When a fix is
   rejected with a counterexample, the same patch is also removed from any other finding in
   that file, because tier 1 and tier 2 give findings on one line the same deterministic patch
   and the cross-tier fold may keep the sibling that was never checked.
5. **Fail closed.** A triage answer that is not JSON, or is JSON but not a verdict list (or a
   single verdict object, or a list wrapped under `verdicts`, `findings` or `results`), now
   returns `uncertain` for every finding in that call, with reason `parse_error`, no confidence
   change and no fix. Before, the findings passed through untouched with their deterministic
   patch. A provider error still passes the findings through untriaged, as before.
6. **API side.** `services/api-service` reads `evidence_details.extra.fix_critic_accepted`.
   When it is `false`, `normalizeFinding` stores no `remediation_patch`,
   `validateSuggestedFix` refuses with `patch critic found an input that still reaches the
   sink`, and the review comment shows the patch neither as a suggestion nor as a plain code
   block. The analysis service already drops the patch; this stops a rejected patch reaching a
   comment by any other route.

`LLM_TRIAGE_REQUIRE_PAYLOAD=false` turns off item 3. `LLM_TRIAGE_CRITIC_ENABLED=false` turns
off item 4. With both off and `LLM_TRIAGE_ISOLATE_SEVERITY=none`, the calls and the handling
match the previous behaviour, except for item 5, which is not behind a flag.

## What was checked without a model

| Command | Result |
| --- | --- |
| `cd services/analysis-service/src && python -m pytest -q tests/test_llm_triage.py tests/test_llm_triage_adversarial.py tests/test_llm_client.py tests/test_triage_adversarial_cases.py` | 157 passed |
| `cd services/analysis-service/src && python -m pytest -q tests/test_analysis_scope.py tests/test_cross_tier_duplicates.py tests/test_route_concurrency.py tests/test_test_code_scope.py tests/test_grpc_contracts.py` | 32 passed |
| `cd services/api-service && npx jest tests/orchestrator.test.js src/__tests__/findingUtils.test.js` | 76 passed |

Python 3.11.6 and Node 24 on macOS. The full analysis suite was not run locally.

`test_llm_triage_adversarial.py` covers: the isolation split and which model each call names;
payload rejection for missing, placeholder, unanchored and off-file payloads; the downgrade and
where it is recorded; a counterexample withholding the fix while keeping the finding; the critic
running on the deterministic fallback patch too; the sibling patch being withheld; every flag
off giving one batched call that confirms and attaches unchecked; parse errors and non-list
answers failing closed; and both budget caps. The tests in `test_llm_triage.py` that predate
this branch run with both flags off.

## The evaluation cases

`benchmarks/model-selection/triage/adversarial/cases.json` is a manifest in the format of the
triage evaluation on `feat/eval-triage` (`benchmarks/model-selection/triage/dataset.json`), so
that branch's `run_eval.py` reads it with `--manifest`. Twelve findings, one per request.

**Six authored, labelled not real.** Each is a file in `adversarial/sources/` on which a rule in
this repository fires but no caller input reaches the sink. They were written for this and are
not taken from any project.

| Case | Rule | Severity | Why it is not real |
| --- | --- | --- | --- |
| `constant-vm` | `code.injection.eval` | critical | `vm.runInContext` over a module constant |
| `constant-vm-new-context` | `code.injection.eval` | critical | `vm.runInNewContext` over a constant rule; the caller's value enters the sandbox as a checked number |
| `framework-redirect` | `redirect.open` | medium | a framework's own definition of `res.redirect`; no request value is read |
| `constant-redirect` | `redirect.open` | medium | `res.redirect` to a literal relative path |
| `resolved-path-read` | `opengrep.cwe-22.path-traversal-fs` | high | `path.basename` before the join keeps the read in the base directory |
| `allowlisted-path-read` | `opengrep.cwe-22.py-open-request-path` | critical | the name is checked against a fixed set before `open` |

**Six from the corpus, labelled real.** Findings that a reviewer read and marked true in
`benchmarks/vulnerable-corpus/adjudications.json`, and that are in the main triage manifest:
whoogle-search `pickle.load` on a request-named file, DSVW `urlopen` on a caller URL, DSVW a
request template rendered unescaped, juice-shop `js-yaml` `load` on request data, juice-shop
`bypassSecurityTrustScript` on a query parameter, and pygoat `@csrf_exempt` (high). The last is
there because a CSRF payload is a cross-site form rather than a literal value at a sink, so it is
the real finding most likely to be lowered wrongly.

`adversarial/build_inputs.py` runs the real tier 1 and tier 2 code over the authored sources,
takes the six corpus findings from the main build's materialised inputs, checks each prompt
context hash against the main manifest, and writes
`benchmarks/results/triage-adversarial-inputs.json`. `test_triage_adversarial_cases.py` checks
that the tiers still produce exactly the frozen authored findings, that the corpus findings are
still adjudicated true, and that the manifest hash is consistent.

### Stub run

`run_eval.py` from `feat/eval-triage` at `2f7af3af`, with `--stub --models stub-keep --runs 1`,
over these cases on this branch. `stub-keep` confirms every finding and writes no payload, which
is the failure the cases describe.

| Findings | Verdict after this branch |
| --- | --- |
| 4 authored, high or critical | `uncertain` (no_concrete_payload) |
| 2 authored, medium (both redirects) | `true_positive` |
| 6 corpus, all high or critical | `uncertain` (no_concrete_payload) |

This shows the rule fires; it says nothing about recall, because a stub writes no payload for the
real findings either. Whether a model writes a concrete payload for the six real findings, and
withholds one from the six authored ones, is the live measurement.

## What is not measured

* **Recall loss from the payload rule.** If a model confirms a real high or critical finding but
  writes a payload the lexical check rejects, the finding is shown as `uncertain` instead of
  confirmed. It is not removed. How often this happens is unknown.
* **Whether the authored cases are confirmed at all.** The trial suggests they are, but no model
  has been run on them.
* **The critic.** How often it rejects a correct fix, how often it accepts a wrong one, and what
  that does to apply rate. The critic uses the same model tier as the isolated triage call.
* **Cost and latency of isolation.** One call per high or critical finding instead of one per
  pull request. The default caps bound it; the effect on the 295-request triage dataset is not
  measured.
* **Dismiss rate.** This branch is meant to lower it. Only an action trial on real repositories
  measures it.

## Known gaps

* **Medium findings are below the payload rule.** Both redirect cases are medium, so a model that
  confirms them on the function name still confirms them. Lowering the threshold to medium is a
  one-line change once the live run says whether it costs recall.
* **The payload check is lexical.** It asks that the payload name the finding's file or an
  identifier from the flagged line, and that the entrypoint name no other file only. A model can
  satisfy it and still be wrong.
* **Untriaged findings keep their deterministic patch.** A finding the budget refused, or whose
  call failed, passes through untriaged with any tier 1 or tier 2 patch, unchecked by the critic.
  That was the behaviour before this branch for every finding, and is unchanged.

## Measuring it

On a branch where `feat/eval-triage` is merged, with an OpenAI or Gemini key exported:

```sh
make eval-triage-dataset
python benchmarks/model-selection/triage/adversarial/build_inputs.py

# this branch's defaults
python benchmarks/model-selection/triage/run_eval.py \
    --manifest benchmarks/model-selection/triage/adversarial/cases.json \
    --inputs benchmarks/results/triage-adversarial-inputs.json \
    --out benchmarks/results/triage-adversarial-on.jsonl \
    --models gpt-4o-mini,gemini-2.5-flash-lite --runs 3 --max-spend 2 --fresh

# the previous behaviour, for the paired comparison
LLM_TRIAGE_REQUIRE_PAYLOAD=false LLM_TRIAGE_CRITIC_ENABLED=false LLM_TRIAGE_ISOLATE_SEVERITY=none \
python benchmarks/model-selection/triage/run_eval.py \
    --manifest benchmarks/model-selection/triage/adversarial/cases.json \
    --inputs benchmarks/results/triage-adversarial-inputs.json \
    --out benchmarks/results/triage-adversarial-off.jsonl \
    --models gpt-4o-mini,gemini-2.5-flash-lite --runs 3 --max-spend 2 --fresh

# true_positive count per model and label, from each results file
python -c 'import json,sys,collections; c=collections.Counter(); lab={r["id"]:r["label"] for r in json.load(open("benchmarks/model-selection/triage/adversarial/cases.json"))["findings"]}; [c.update([(r["model"],lab[f["id"]],f["verdict"])]) for r in map(json.loads,open(sys.argv[1])) if "findings" in r for f in r["findings"]]; [print(*k,v) for k,v in sorted(c.items(),key=str)]' benchmarks/results/triage-adversarial-on.jsonl
```

What a good result looks like: with the flags on, no `true_positive` among the six not-real
findings that are high or critical, and six `true_positive` among the real ones in a majority of
runs. With the flags off, the not-real ones confirmed, which is what makes the comparison worth
reading. Twelve isolated calls plus a few critic calls per run is under 40,000 input tokens, a
few cents per model per run at the prices in the triage evaluation's README.

The same two commands without `--manifest` and `--inputs` run the full 408-finding triage
dataset, which is where recall loss and cost of isolation are measured.
