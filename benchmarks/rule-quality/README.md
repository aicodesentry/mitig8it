# Rule publication criterion

Install `python -m pip install pyyaml -r benchmarks/requirements-quality.txt`, then
run `python -m benchmarks.rule_quality_gate` from the repository root (Python 3.11),
or `make bench-rule-quality`. The command exits 2 on failure. CI,
`make bench`, and the image release workflow enforce this check. The optional
`--output /tmp/rule-quality.json` writes the full machine-readable report.

Existing postable rules are recorded, by definition SHA-256, in
`legacy-posting.json`. This is a compatibility exception, explicitly reported as
`legacy_unvalidated`; it is not a precision claim. Do not extend that inventory to
approve a new or changed rule. Quarantined rules do not need promotion evidence
to continue running and being counted without publication.
Remove a legacy entry when its rule changes, is quarantined, or is removed; stale
entries fail the check. A later rollback or re-enabling must supply evidence too.

A new postable rule, changed legacy rule, or previously quarantined rule may
publish only when its exact definition digest has evidence in `evidence.json`
that meets every requirement below:

- A named frozen holdout corpus and a written sampling plan; training and
  validation observations cannot count toward promotion.
- At least 100 adjudicated predictions for that individual rule, with no
  unresolved judgments. Safe cases the rule does not flag do not enter a
  precision denominator.
- The lower endpoint of the two-sided 95% Wilson score interval for
  `true / (true + false)` is at least 0.95, using z = 1.959963984540054.
  The decision uses the unrounded bound. 100/100 passes (lower bound about
  0.9630); 99/100 fails (about 0.9455). A point precision of 0.95 alone cannot pass.
- Every observation identifies its source, reviewer, finding ID, and independent
  sampling unit. Finding IDs and sampling units must be unique within a rule's
  evaluation. Use one finding per independently sampled PR (or repository where
  PRs are correlated), not many copies of the same fixture or many findings from
  one PR. False and uncertain judgments must remain in the evidence.
- `collection_provenance.review_identity_authenticated` and
  `collection_provenance.population_sampling_verified` must both be JSON `true`.
  Both claims must be authenticated by an unexpired, purpose-separated Ed25519
  receipt binding the entire evidence candidate, rule ID and exact definition
  digest. True flags without valid trusted signatures fail.
- Every named observation reviewer must sign with an enrolled
  `analysis-observation-review` key. A trusted `analysis-sampling-audit` signer
  must audit the declared population/frame, unit independence, holdout separation
  and adherence to the frozen sampling plan, plus the actual registrant identity
  and reviewers' independence from that person. The signer identities must differ
  from the study registrant. The local trust store controls reviewer thresholds,
  allowed roles, revocation and a maximum receipt lifetime of 30 days.

Evidence shape (the example alone intentionally cannot pass):

```json
{
  "schema_version": "v1",
  "rules": {
    "example.rule": {
      "rule_id": "example.rule",
      "rule_digest": "<digest from load_rules() for the evaluated definition>",
      "corpus": "pinned-corpus-and-revision",
      "split": "holdout",
      "sampling_plan": "Audited frozen sampling frame, one finding per independent unit",
      "observations": [
        {
          "id": "stable-finding-fingerprint",
          "sampling_unit": "owner/repository/pull/123",
          "source": "pinned-source-or-review-record-reference",
          "reviewer": "independent-reviewer-id",
          "verdict": "true"
        }
      ]
    }
  }
}
```

Verdicts are `true`, `false`, or `uncertain`. Rule definitions include tier 1
matching options and exclusions, dependency patterns, tier 2 YAML definitions,
and the secret detector implementation. Formatting and posting/evidence prose
are excluded where possible; changing the shared secret implementation requires
revalidating both signals. Runtime matching code outside those definitions still
needs the existing detector, precision-regression, and integration tests.

The interval assumes representative independent observations and applies per
rule, not simultaneously across all rules. The checker authenticates the trusted
reviewers' signed judgments and sampling-audit assertions, and rejects duplicate
unit identifiers. Cryptography cannot prove judgment correctness, population
representativeness, human independence, the absence of invented units, or holdout
separation. Authorized reviewers must audit the full plan and pinned sources,
document the audit, and keep holdout observations out of tuning. Key enrollment
must establish which independent human owns each reviewer identity; aliases must
not be enrolled as separate humans to satisfy a reviewer threshold.
This gate does not claim that the legacy inventory or authored regression
fixtures meet a production precision target.

The remediation release evaluator uses the same minimum of 100 holdout published
predictions and Wilson lower precision bound. An unsafe ready patch on a negative
or adversarial case counts as a false positive. All fixture results must be
present exactly once, and the manifest's holdout coverage floor also applies.
Existing corpus, external review signature, and production isolation requirements
still apply; the authored remediation seed remains non-promotable.

## Readiness, runtime admission, and audited shipping paths

`python -m benchmarks.production_readiness --output /tmp/readiness.json` emits a
machine-readable decision and exits 2 until the selected production component is
ready. `--component analysis` requires the promotion gate to pass, at least one
validated posting rule, and zero unvalidated legacy posting rules. Quarantined
rules are disabled and need not be promoted. The default `all` also requires
independent remediation release evidence. `--report-only` is for inspection;
`--compatibility` is restricted to staging and reports `production_ready: false`
even when compatibility admission passes.

The checked-in `services/analysis-service/src/publication-policy.json` is a
compiled allowlist, checked against the canonical evidence on every gate run.
After adding qualifying evidence or retiring legacy exceptions, regenerate it
with `python -m benchmarks.rule_quality_gate --refresh-runtime-policy`. Refresh
refuses if promotion evidence fails. Runtime code re-hashes each actual rule;
unknown IDs, changed definitions, invalid states, and missing IDs are withheld
even if somebody bypasses a normal workflow. A missing/stale allowlist that
approves no definitions prevents service startup. Tier 3 applies the same
admission before and after model triage, including caller-supplied findings.

Repair proposals remain available for development evaluation. Analysis responses
always withhold detector/Tier 3 candidate patches; only the separate verified
remediation path may publish repairs when release evidence qualifies. The API capability
policy disables fix publication and automatic generation for publication; feature
flags and development/static verification flags cannot override missing release
evidence. The GitHub service independently refuses fix-section publication and
suggestion blocks in generic review/comment transports. The Action skips repair
generation intended for publication and explains the withheld suggestions in its
review. Ordinary detection findings and remediation residual reports without
repair artifacts remain reportable.

| Path | Enforced decision |
| --- | --- |
| CI and `make bench-rule-quality` | Promotion evidence and exact packaged runtime allowlist; CI separately reports production readiness without claiming it passed. |
| Version/image release | Strict combined readiness before image push, tag changes, or GitHub release creation. |
| Analysis Cloud Run deployment | Strict analysis readiness for production; compatibility admission for staging. |
| Remediation Cloud Run deployment, including sandbox job image | Strict remediation readiness for production; compatibility admission for staging. |
| API, GitHub service, and Firebase deployments | Strict combined readiness for production; compatibility admission for staging. |
| Manual dispatch and reusable deployment workflows | Each leaf workflow invokes the local quality-readiness composite before cloud authentication and shipping. |
| Action source builds, local compose, and direct analysis calls | Packaged exact-definition runtime admission and independent publisher refusal still apply; a development build is not evidence of readiness. |
| LangSmith security-curation publisher | Publishes evaluation dataset examples only; it cannot approve a rule, enable repairs, publish product comments, or deploy a service. |

The Node services carry identical `quality-release.json` artifacts recording
`remediation_release_verified: false`. The authenticated external-review verifier
is implemented in `benchmarks/remediation/release_evidence.py`; the missing work
is evidence and trust enrollment, not implementing that verifier. No trusted
reviewer keys or signed release bundle are configured; current evaluation identity,
qualifying reviewed holdout corpus, and production isolation evidence are also
missing. The gate remains fail-closed until those inputs are supplied and
verified against the current engine/model/configuration and source revision.
Release artifacts must be regenerated through that verified process. A manual
JSON flag, reference fixture result, or provider self-assessment cannot substitute
for authenticated review and the separate statistical/isolation gates.

Remaining evidence work: independently adjudicate representative frozen holdout
samples for each posting rule (or quarantine/remove that rule), audit sampling
independence and provenance, supply the remediation manifest's full reviewed
corpus, enroll approved reviewer keys and obtain signed review receipts/current
evaluation identity, and record production isolation and live-provider evaluation evidence. No external deployment
or evidence collection is performed by these offline checks.

## Preregistered workflow-rule evidence collection

`python -m benchmarks.analysis_evidence` supplies the missing collection/review
workflow without creating labels or changing the promotion criterion. The initial
supported scope is one rule from `opengrep_rules/workflow_coverage.yml`, measured
as a deterministic Tier 2 detector with no Tier 3 or repair calls. A useful
documented candidate is `opengrep.cwe-1357.gha-third-party-action-unpinned`.
Naming that candidate is not a precision or exploitability claim.

### 1. Define and commit the study before collection

Use an activated analysis environment (`source .venv/analysis/bin/activate`): the
scanner executable and Python must share the same environment prefix. First commit
the measurement code/configuration. The tool refuses dirty or untracked matching
code, so later edits cannot quietly change what a preregistered study measures.

Prepare a specification with exactly these fields (the empty example intentionally
cannot pass validation and contains no invented observations):

```json
{
  "rule_id": "opengrep.cwe-1357.gha-third-party-action-unpinned",
  "corpus": "your-versioned-holdout-name",
  "population": "the actual intended deployment population and its exclusions",
  "sampling_plan": "the actual frame construction, exclusions, independence rationale and fixed stopping plan",
  "registered_by": "actual-study-registrant",
  "selection_seed": "choose-and-freeze-before-running-the-detector",
  "sample_size": 120,
  "frame": []
}
```

Fill `frame` with the exact intended units: each has canonical lowercase `repo`,
positive integer `pr`, full 40-character `head_sha` and `base_sha`, and an
`independence_group` identifying shared repository/fork lineage. There must be at
least `sample_size` frame units. Repeated repositories, PR/repository units, or
independence groups are rejected. This implementation conservatively permits one
PR per repository, not many nominally independent PRs from one project.

```sh
python -m benchmarks.analysis_evidence preregister \
  --specification /private/path/workflow-study-spec.json \
  --output benchmarks/rule-quality/frames/workflow-study.json
```

Review and commit that exact plan **before** collecting. The collector requires
the plan to match its committed Git content, and binds the registration commit.
Review the frame's actual population selection, prior exposure, excluded tuning
corpora, forks and correlated units. Existing authored fixtures, known vulnerable
labels, and repeated synthetic variants cannot be relabeled as fresh holdout.

### 2. Collect every fixed-frame unit and select predictions deterministically

```sh
python -m benchmarks.analysis_evidence collect \
  --plan benchmarks/rule-quality/frames/workflow-study.json \
  --output /private/path/workflow-collection.json
```

Only this phase makes GitHub reads. It uses the existing cached `gh api GET`
reader, retry ceiling and rate-limit backoff; `--cache` and `--refresh` are
available. Each exact PR is retrieved directly. Head/base refs must match the
frame; all changed-file records must be present exactly once. Production file
caps apply. Every in-scope workflow blob is read at its pinned ref, checked against
its Git blob digest and PR file SHA, and its diff is checked against both exact
source versions and declared additions/deletions. Missing/truncated source,
malformed diffs, failed scans and **any** scanner limitation abort collection.
Downloaded workflow code is only parsed/scanned, never executed.

The artifact retains every frame unit, including complete scans with zero target
predictions. From units with predictions it deterministically selects at most one
alert per repository, then the fixed number of units, using SHA-256 ranks of the
preregistered seed and bound identities. It does not select according to judgments.
Duplicate finding identities fail. Too few predicted units yield an explicit
incomplete selection and exit 2; no complete review queue or import is allowed.
Do not adapt the frame or stopping rule after seeing judgments until a bound passes.

Provenance includes the Git checkout, matching-source/rule hashes, Python and
scanner executable identities/version, installed dependency versions and wheel
RECORD digests, effective batch/measurement configuration, scanner environment
hashes, exact PR metadata, source bytes/blob hashes, diffs, and observation hashes.
No local provider credentials are included in provenance. Collection artifacts and review queues may
contain sensitive source text; files are created owner-only and are never uploaded
automatically. The existing GitHub cache also retains source: place `--cache` in a
private owner-only directory. Output paths must be new, preventing accidental plan/report overwrite.

### 3. Review the complete, bound queue

```sh
python -m benchmarks.analysis_evidence queue \
  --plan benchmarks/rule-quality/frames/workflow-study.json \
  --collection /private/path/workflow-collection.json \
  --output /private/path/workflow-reviews.json
```

Every row starts with null judgments. A reviewer fills only `verdict`, `reviewer`,
`reviewed_at` (timezone-aware), and `review_note`; the other fields bind its exact
finding, source, system, study and sampling unit. Use `true`, `false`, or leave it
unresolved (`null`/`uncertain`). Unresolved rows are retained but cannot import.
The reviewer identifier must differ from the registrant identifier, and a note
is required. The queue contains source links and local source context, not model
assessments or fabricated reviewer claims.

### 4. Verify and produce an unsigned evidence candidate

```sh
python -m benchmarks.analysis_evidence import \
  --plan benchmarks/rule-quality/frames/workflow-study.json \
  --collection /private/path/workflow-collection.json \
  --reviews /private/path/workflow-reviews.json \
  --evidence benchmarks/rule-quality/evidence.json \
  --output /private/path/evidence-candidate.json
```

Import reconstructs source/diff provenance and **re-runs the current detector** on
every stored unit, requiring the same observations and system/configuration as
the preregistration. Missing, duplicate, modified, stale, unresolved, self-reviewed
identifier or incorrectly timed rows fail closed. It checks the unchanged numeric
criterion: at least 100 reviewed units and Wilson lower precision bound >=0.95.
For example, 99/100 fails; a preregistered 120-unit study with 119 true and one false
passes numerically. These examples are thresholds, not a sequential stopping rule.

The output deterministically merges statistically qualifying, **unauthenticated** rule evidence with the supplied
canonical document, preserving unrelated entries and refusing to replace different
existing evidence for that rule. Review-row order does not change the candidate.
It binds the canonical review-document digest. It does **not** overwrite
`evidence.json`, retire legacy exceptions, re-enable rules, refresh the runtime
allowlist or claim production readiness. An unsigned import reports
`publication_evidence_validated: false` and cannot mark a rule `validated`, even
if manually copied into `evidence.json`. A successful command means the candidate
was generated; it does not mean the publication gate passed.

Before signing, reviewer strings are **not authenticated identities**;
a different string does not prove an independent human. Frame representativeness
and repository/fork independence are also unauthenticated claims. Seeded ranking
is deterministic only within the supplied frame, not proof of random sampling
from production. Git commits and digests bind local integrity but are not
signatures, trusted timestamps or authenticated execution attestations. Outputs
explicitly set `review_identity_authenticated: false` and
`population_sampling_verified: false`. The publication checker rejects either
missing/false flag and also rejects forged true flags without a valid receipt.
This is per-rule precision evidence, not end-to-end production accuracy or recall.

### 5. Authenticate observation reviews and the sampling audit

The real verifier is `benchmarks/analysis_attestation.py`. Its purpose-specific
trust store is `benchmarks/rule-quality/trusted-reviewers.json`, initially empty.
No current evidence can authenticate against that empty store. There are no
test keys or private keys in it. Enroll approved independent humans' Ed25519
public keys in a reviewed PR, using this key schema:

```json
{
  "key_id": "organization/reviewer/key-version",
  "reviewer_id": "actual-reviewer-identity",
  "algorithm": "ed25519",
  "status": "active",
  "public_key_base64": "<canonical base64 encoding of the raw 32-byte public key>",
  "roles": ["analysis-observation-review", "analysis-sampling-audit"]
}
```

Assign only approved roles. The auditor may also be an observation reviewer,
provided that person is independent of the registrant. Every named observation
reviewer must sign; changing to a single reviewer string cannot authenticate
other people's judgments. The auditor signs accountable assertions about the
complete collection's frame and population; `population_sampling_verified: true`
means **trusted human audit**, not a mechanically proved random population sample.
The audit reference must identify a durable review of frame construction,
exclusions, repository/fork lineage, prior tuning exposure, fixed stopping plan,
actual registrant identity and reviewer independence, and exact
source/system/collection/review bindings. Comparing identifier strings alone is
not an independence audit; the auditor must sign an explicit assertion that the
registrant identity and reviewer independence were checked.

Prepare the unsigned payload after that audit, choosing current UTC times with
a lifetime no longer than 30 days:

```sh
python -m benchmarks.analysis_attestation \
  --evidence /private/path/evidence-candidate.json \
  --rule-id opengrep.cwe-1357.gha-third-party-action-unpinned \
  --issued-at '<current UTC YYYY-MM-DDTHH:MM:SSZ>' \
  --expires-at '<UTC expiry no more than 30 days later>' \
  --auditor-id '<enrolled sampling auditor identity>' \
  --audit-reference '<durable independent sampling audit reference>' \
  --output /private/path/signing-payload.json
```

This command does not sign or authenticate anything. Each required reviewer and
auditor must inspect the complete candidate, original collection and review queue
before signing. The exact Ed25519 message is
`b"mitig8it/analysis-rule-publication/v1\x00" + canonical_json(payload)`, where
`\x00` denotes one NUL byte, not four literal characters. Use
`benchmarks.analysis_attestation.signing_bytes(payload)` to avoid encoding errors.
Canonical JSON sorts string keys, preserves array order, uses ASCII escaping and
compact separators, and rejects nonfinite/non-JSON values. Signatures from the
remediation protocol cannot be replayed here. Keep private keys in the reviewers'
approved signing systems; this tool never creates or receives private keys.

Assemble the external receipt as:

```json
{
  "schema_version": "v1",
  "payload": "<the complete prepared payload object, not a JSON string>",
  "signatures": [
    {
      "algorithm": "ed25519",
      "key_id": "<enrolled key ID>",
      "reviewer_id": "<matching enrolled human identity>",
      "signature": "<canonical base64 encoding of the raw 64-byte signature>"
    }
  ]
}
```

The illustrative payload placeholder above is intentionally invalid; replace it
with the actual object. Supply one signature per required distinct human. Keys
embedded in receipts or supplied through environment variables are never trusted.
Revoked/unknown keys, missing roles/signers, altered evidence, cross-rule reuse,
future/expired receipts and unsigned/missing/false audit assertions all fail.

Re-run the original import with `--attestation /private/path/signed-receipt.json`
and a new `--output /private/path/authenticated-evidence-candidate.json`. The
importer reconstructs and re-scans all sources again, verifies the exact receipt
against the checked-in trust store, and rechecks the statistical floor. It sets
both provenance flags true **only in a successfully verified output** and reports
`publication_evidence_validated: true`; production readiness still remains false
until the explicit promotion PR retires legacy exceptions, updates canonical
evidence and the runtime allowlist, and all other readiness requirements pass.
The ordinary publication gate independently re-verifies the signatures and expiry
on each run. A signature authenticates accountable assertions, not proof of an
honest signer, authenticated scanner execution or a trustworthy Git timestamp.

Offline regression tests (all synthetic fixtures, never release observations):

```sh
python -m pytest benchmarks/test_analysis_evidence.py benchmarks/test_analysis_attestation.py \
  benchmarks/test_quality_gate.py -q
```
