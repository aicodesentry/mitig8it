# External remediation release review

The standalone verifier authenticates external review evidence, **not production
readiness by itself**. Release admission now also recomputes statistical gates and
checks current source/provider/model/configuration/sandbox identity before it can
generate packaged `quality-release.json` artifacts. Deployment revalidates the
same receipt and exact artifact. Current gates remain closed: no reviewer keys,
evaluation identity, or qualifying signed release bundle has been supplied.

## Owner/reviewer inputs

1. Appoint independent reviewers and approve their stable reviewer IDs and Ed25519
   public keys through a separately reviewed change to
   `benchmarks/remediation/release/trusted-keys.json`. Register `key_id`,
   `reviewer_id`, `algorithm: "ed25519"`, `status: "active"`, and the canonical base64
   encoding of the 32-byte raw public key as `public_key_base64`. Never put private
   keys in this repository, GitHub variables, receipts, or the evaluated service.
   The store is deliberately empty today. Revocation sets `status: "revoked"`;
   receipts signed by revoked keys fail, even before their expiry. Key rotations
   need a distinct key ID. Do not reuse one key under multiple reviewer IDs.
2. Independently review a frozen, representative corpus and its complete model
   evaluation. Statistical corpus/precision/coverage requirements remain in
   `benchmarks/remediation/release-manifest.json`; signatures cannot waive them.
   Audit sampling independence, held-out provenance, source/reference/check files,
   full result evidence, and actual live-provider/production-sandbox identities.
   A provider's declaration alone does not prove the model it used.
3. Configure `benchmarks/remediation/release/evaluation-identity.json` with exactly
   `provider_id`, `model_id`, nonempty `configuration`, `sandbox_image_digest`, and
   `service_image_digest` (the exact evaluated remediation-service binary).
   It is deliberately `{}` until approved inputs exist. Pin the evaluated Git
   source SHA, provider/model version, non-secret effective
   configuration (including prompts, budgets, tools and policy), and the exact
   `registry/image@sha256:...` production sandbox image. Record secrets only by
   managed version identifier when needed, never by value. The current protocol
   requires `independent_sandbox`; `isolated_job`, development subprocess and static
   assertion results do not authenticate a production release.
4. Sign the complete receipt payload out of band with approved reviewer keys.
   The deployment job needs only public keys and signed evidence, **no signing
   secret**. Verify possession/ownership and independence of reviewers separately;
   cryptography authenticates an approved key, not a person's independence.

## Required committed corpus intake

Production admission also requires the complete
[committed preregistration chain](remediation-corpus-intake.md), not merely signed
fixture metadata. Every counted fixture must pass full fixture validation and map
to a preregistration committed before evaluation; every registered case must be
included, with no legacy exception or omitted unfavorable batch. The verifier
reconstructs historical baselines and introduction commits itself and verifies
current source/test/reference provenance against pinned local upstream Git blobs.
Configure the fixed, owner-reviewed `release/intake-origins.json` policy and local
checkouts; no origin policy or registration selection is trusted from the receipt.

The production payload additionally signs the recomputed `intake` binding
(ledger/population/origin-policy digests, count, and evaluation start/end times).
An authentication-only signature without that binding cannot promote a release.
A case or oracle author cannot approve that same fixture, even with an otherwise
trusted signing key. The current authored seed has no preregistration and remains
nonpromotable; do not retrospectively manufacture registrations or approvals.

## Receipt protocol v1

Install the pinned quality-only dependency:

```sh
python -m pip install -r benchmarks/requirements-quality.txt
```

The JSON envelope has exactly `schema_version: "v1"`, `payload`, and `signatures`.
The payload contains exactly:

- `schema_version: "v1"`, `purpose: "mitig8it/remediation-release-evidence"`;
- all fields returned by `expected_bindings(...)`: current `source_revision`,
  `manifest_digest`, `fixtures_digest`, `results_digest`, `provider`, and `sandbox`;
- `issued_at` and `expires_at` as UTC `YYYY-MM-DDTHH:MM:SSZ`; the trust store caps
  both the validity interval and receipt age (currently seven days, never over 30);
- `reviews`: exactly one record for every current fixture, with `fixture_id`,
  authenticated `reviewer_id`, `verdict: "approved"`, `fixture_digest`, and
  `result_digest`. Compute individual digests with the module's `digest` function.

`fixture_inventory` hashes every fixture's metadata, source, reference repair,
and check file. The full result array is signed by digest, not a summary/count.
Changes to either inventory or any evidence/result field invalidate the receipt.
Reviewers sign the same complete payload; each signer must own at least one
fixture review. The configured minimum counts distinct authenticated reviewers.

Sign the exact bytes returned by `signing_bytes(payload)`: the UTF-8/ASCII domain
`mitig8it/remediation-release-evidence/v1` followed by one NUL byte, followed by
sorted-key, compact JSON with ASCII escapes and no NaN/infinity. Arrays retain
their order. This is the protocol's encoding, not a claim of RFC 8785 compliance.
Each signature record has exactly `algorithm: "ed25519"`, `key_id`, `reviewer_id`,
and `signature` (canonical base64 of the raw 64-byte Ed25519 signature). Embedded
public keys, unknown/revoked keys, duplicate key/signature/review IDs, malformed
JSON/base64, incomplete reviews and stale evidence are refused.

With a complete evaluation report and the independently recorded current identity:

```sh
python -m benchmarks.remediation.release_evidence \
  --receipt /path/to/external-review-receipt.json \
  --evaluation /path/to/full-evaluation.json \
  --identity /path/to/non-secret-evaluation-identity.json
```

The identity document contains exactly `provider_id`, `model_id`, `configuration`
(nonempty JSON object), `sandbox_image_digest`, and `service_image_digest`. The CLI obtains the current
source SHA, manifest, corpus and checked-in trust policy itself. It refuses dirty
tracked engine/verifier/trust-policy files and untracked engine files; commit the evaluated implementation
before running an external review. Supply receipts out of band for that exact SHA;
do not create an extra evidence commit and pretend its SHA was evaluated. The
verifier never executes candidate code or calls a provider/cloud API.

Success returns an `external_review_authentication_only` receipt digest and
reviewer IDs. Failure exits 2. It does not return `passed`/`production_ready`, write
artifacts, deploy, or open any runtime publication gate.

## Complete release admission and packaged artifacts

Commit the evaluated implementation, trust policy and expected identity **first**.
The release request must set `REPAIR_LLM_MODEL` equal to the configured `model_id`;
the evaluator sends that exact `versions.repair_model`, which the remote provider
already checks against its configured model. The sandbox argument must equal the
configured digest. A reference/scripted/local run cannot become a release:

```sh
python benchmarks/remediation/evaluate.py --suite release --adapter engine \
  --allow-network --remote-provider live-provider \
  --engine-sandbox-image-digest registry/image@sha256:EXACT_DIGEST \
  --engine-service-image-digest registry/remediation@sha256:EXACT_SERVICE_DIGEST \
  --output /path/to/full-evaluation.json
```

This records the full result array, including candidate replacement bytes,
verification evidence and requested model/sandbox identity. Without external
signatures it deliberately exits 2 while writing the evaluation. Independently
review and sign those exact inputs; do not edit or rerun results after signing.

Deliver an out-of-band bundle with exactly `schema_version: "v1"`, `evaluation`
(the complete report above), and `receipt` (the signed envelope). The current
checkout SHA must equal its evaluated SHA. Do not commit the finished bundle in
a follow-up commit and pretend the new SHA was evaluated. Verify and generate:

```sh
python benchmarks/remediation/evaluate.py --suite release \
  --release-evidence /path/to/signed-release-bundle.json
python -m benchmarks.production_readiness --component remediation \
  --release-evidence /path/to/signed-release-bundle.json --refresh-release-artifacts
python -m benchmarks.production_readiness --component remediation \
  --release-evidence /path/to/signed-release-bundle.json
```

Every generation/revalidation authenticates signatures, expiry and revocation,
matches current source/manifest/corpus/results/expected identity, requires a live
provider and independent sandbox, then recomputes all release statistics. The
manifest cannot lower hard-coded policy floors. Holdout itself needs 20 supported
cases per family, 30 negatives and 30 adversarial cases; training/validation cases
cannot fill these strata. Its seven families require at
least 140 supported cases, plus 30 negatives and 30 adversarial cases, so meeting
all current minima needs at least 200 cases despite the global 120-case floor.
Only holdout published predictions enter precision; at least 100 are required,
with Wilson lower bound >= .95. No unresolved/failed results may disappear.
Five static regression demonstrations have exact-digest `release_abstentions`
entries: release requests disable static assertions and must return unsupported
without replacement code. They remain supported cases in the coverage denominator,
so abstention lowers coverage. Seed-mode static regression tests are unchanged.
Changed fixture bytes invalidate the policy until independently reviewed.

Generation writes the identical authenticated artifact into the API and GitHub
services. Its source SHA, evidence digests, provider/model/configuration digest,
sandbox/service image digests and expiry must match the current verified bundle. Hand-edited
booleans or metadata never qualify; expired/revoked evidence invalidates admission
even if an old packaged artifact still says `true`. Invalid evidence writes no
artifacts. Staging compatibility and report-only modes cannot generate them.

The ordered release first runs a read-only, no-OIDC topology/identity preflight
before API deployment or migration. Current local/Cloud Run Job topologies fail
there because neither supplies independent_sandbox, preventing partial rollout.
Production workflows use the same composite before registry pushes, migrations,
job mutations or deployment. Supply the bundle at the checked-out default
`benchmarks/remediation/release/evidence.json` (for example by authenticated
artifact acquisition before admission), or set the non-secret
`REMEDIATION_RELEASE_EVIDENCE_URL` GitHub variable to a public HTTPS bundle for
this exact SHA. URL acquisition has a 20 MiB/30-second limit, at most three
HTTPS-only redirects, and refuses user-info/query/fragment credentials. No token
or signing secret is sent. Signatures and source/identity/expiry remain mandatory
regardless of transport. Missing or tampered downloads fail closed.
The remediation service promotes the exact authenticated service image rather
than rebuilding it. The API sends its expected binary digest; both HTTP intake
and resumed repair execution compare it with `REMEDIATION_SERVICE_IMAGE_DIGEST`
before any enqueue/model/sandbox work. Required, unfiltered CI installs pinned
quality requirements and runs verifier, intake and real-Git provenance tests.

The remediation workflow's explicit release check consumes that same bundle;
its default seed check still expects refusal. The production sandbox-job path
checks both the reviewed digest **and execution level before any registry push**.
It explicitly refuses an `independent_sandbox` receipt under `cloud_run_job`,
which provides only `isolated_job`: digest equality cannot upgrade isolation.
If a future, separately reviewed policy supports that environment, it must promote
the already evaluated digest, not rebuild another runner, and revalidate again
immediately before changing the job. Today's required floor keeps this path closed.

## Remaining deployment checklist

- Collect a representative independently reviewed corpus meeting every manifest
  floor, approve external reviewer public keys and expected identity, and supply
  fresh signatures. The authored seed remains non-promotable.
- Provision and independently verify production sandbox isolation. The existing
  Cloud Run Job driver reports `isolated_job`, **not** `independent_sandbox`; a
  signed label cannot upgrade its implementation. The ordered production workflow
  currently selects that driver, so an independent broker/driver rollout remains
  required before its real results can satisfy this release policy.
- Require production Environment approvals and protected release branches. The
  read-only GitHub audit on 2026-10-23 found `production` with no protection rules
  or branch policy and no environment-scoped variables/secrets; `staging` was
  absent. Approval settings are owner actions, not receipt signatures.
- Provision sandbox resources, dedicated identities/IAM, separate runtime DB
  credentials, and Secret Manager application-auth secrets using their existing
  runbooks. None is a substitute for cryptographic review or quality evidence.

No production keys, signatures, evidence approvals, or cloud changes are supplied
by this implementation. Tests generate private keys only in memory.
