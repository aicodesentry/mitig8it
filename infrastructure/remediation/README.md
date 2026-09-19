# Remediation infrastructure staging definitions

Nothing in this directory has been applied. The module creates only resources
whose values are explicit inputs; it does not create a GCP project, cluster,
KMS key, TLS certificate, secret, image, or control-plane endpoint.

`terraform/` provisions a bounded Cloud Tasks queue, Scheduler identity/job,
and the durable remediation-artifact bucket. The bucket is versioned, prevents
public access, uses the supplied existing CMEK key, deletes request artifacts
under `remediation-inputs/` after seven days and results under
`remediation-results/` after 30 days. It grants the GCS service agent CMEK use
and binds only the remediation API and worker Workload Identities to create and
read bucket objects.

The repair service now persists durable request/result artifacts through
`REMEDIATION_DATABASE_URL`, `REMEDIATION_ARTIFACT_BUCKET`, and
`REMEDIATION_ARTIFACT_KMS_KEY`; the worker runs `python -m src.worker` in its
own Deployment. This is distinct from sandbox input transfer: the current
broker still limits its one-use Kubernetes Secret payload to 700 KB. A larger
sandbox verification remains `unsupported`; never substitute GCS credentials,
a mount, or runner egress for that capability.

Cloud Tasks remains intentionally **unwired**: the present control plane polls
its PostgreSQL outbox and has no enqueue/dispatch endpoint. The queue’s future
per-task OIDC contract and Scheduler reconciler are defined so the handler can
be added safely, but creating these resources does not start work.

## Render and validate a deployment

The checked-in Kustomize base deliberately has required `__TOKEN__` fields.
Render it first; the renderer rejects mutable images, broad CIDRs, unknown
tokens, and output paths inside the source tree. Use output values from
Terraform for the two GCP service-account flags.

```sh
terraform -chdir=infrastructure/remediation/terraform init
terraform -chdir=infrastructure/remediation/terraform plan -var-file=staging.tfvars

python infrastructure/remediation/render_kubernetes.py \
  --output /secure-render/remediation \
  --remediation-service-image 'REGISTRY/remediation@sha256:...' \
  --remediation-worker-image 'REGISTRY/remediation@sha256:...' \
  --sandbox-broker-image 'REGISTRY/remediation@sha256:...' \
  --otel-collector-image 'REGISTRY/collector@sha256:...' \
  --remediation-api-gcp-service-account 'OUTPUT_FROM_TERRAFORM' \
  --remediation-worker-gcp-service-account 'OUTPUT_FROM_TERRAFORM' \
  --kubernetes-api-cidr 'CONTROL_PLANE_PRIVATE_CIDR' \
  --remediation-external-egress-cidr 'APPROVED_EGRESS_GATEWAY_CIDR' \
  --remediation-database-cidr 'POSTGRES_PRIVATE_CIDR'
kubectl kustomize /secure-render/remediation >/secure-render/remediation.yaml
kubectl apply --server-side --dry-run=server -f /secure-render/remediation.yaml
```

Only a change-managed deploy operation may replace the final dry-run; this
repository intentionally performs no deploy. The egress CIDR must identify a
reviewed egress gateway/proxy, not `0.0.0.0/0`. That gateway is responsible for
the separately reviewed provider, GCS, and telemetry upstream destinations.

## Production prerequisites

- An existing GKE cluster with NetworkPolicy enforcement and a `gvisor`
  RuntimeClass. Validate the runner has label `app=mitig8it-sandbox`; the
  namespace default-deny policy then blocks its network and metadata access.
- Immutable repair-service, worker, broker, collector, and runner images. The
  runner digest must also be in `SANDBOX_ALLOWED_IMAGE_DIGESTS`.
- Secret-manager supplied Kubernetes Secrets, never committed here:
  - `remediation-service-secrets`: internal API secret; provider settings;
    broker URL/token/attestation fields; `REMEDIATION_DATABASE_URL`,
    `REMEDIATION_ARTIFACT_BUCKET`, and `REMEDIATION_ARTIFACT_KMS_KEY`.
  - `sandbox-broker-secrets`: broker token, attestation secret/key ID/broker ID,
    and the runner image allowlist.
  - `sandbox-broker-tls`: `tls.crt` and `tls.key`, with a certificate SAN for
    the cluster DNS used by `SANDBOX_BROKER_URL`.
  - `remediation-observability-secrets`: upstream OTLP endpoint and auth.
- The broker Service terminates TLS itself on 8443 and is exposed as HTTPS on
  ClusterIP port 443. Set `SANDBOX_BROKER_URL` to its HTTPS DNS name; provide a
  CA trust chain in the repair image where a private CA is used.
- A cluster-specific private Kubernetes API CIDR. The rendered exception is
  only for the trusted broker; runner pods have neither token nor RBAC.
- The approved database and egress-gateway CIDRs used by the renderer.
- An existing regional KMS CryptoKey and a globally unique bucket name passed to
  Terraform. Bucket region and key location must be compatible.

## Safety gates and current limits

- `SANDBOX_NETWORK_POLICY_ATTESTED` and `SANDBOX_NODE_LIMITS_ATTESTED` remain
  hard-coded `false`. Change either only after staging evidence proves each
  check runs in its own gVisor Job, egress/metadata stay denied, bounded logs
  are captured, and node/container process, ephemeral-storage, and log-rotation
  controls work.
- The broker Role is deliberately limited to Jobs, Pods/Pod logs, and one-use
  Secrets. It has no ConfigMap, PVC, exec, cluster-wide, or runner authority.
- OTel collector tail sampling retains error traces and 10% of other traces;
  memory limits and batching bound it. Source, prompts, completions, and patches
  are stripped. The API metrics dashboard uses the four currently declared
  remediation series; lease reclaim remains uninstrumented until its counter is
  incremented.
- The six seed fixtures are CI smoke coverage, not release evidence. The normal
  workflow expects the release evaluator’s diagnostic exit 2. A manual
  `release_gate=true` run requires exit 0, which needs the reviewed 120-case
  corpus and signatures; it still does not deploy or enable remediation.
