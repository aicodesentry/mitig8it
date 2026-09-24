# Cloud Run Jobs sandbox runbook

The `isolated_job` verification level. It exists because the two levels either side of it are
not available to this deployment: `independent_sandbox` needs a GKE cluster with a gVisor node
pool that has never been applied, and `development_unverified` runs repository checks inside
the repair service's own container with no isolation of any kind. This level runs each half of
each check pair in its own Cloud Run job container, as an unprivileged user that holds none of
the job's credentials, on a network that the task's own probes measured as unreachable before
the check started.

Nothing here is applied automatically, and no step in this repository turns it on. The service
keeps running `SANDBOX_DRIVER=local` until an owner completes every step below in order.

Read [what this design cannot guarantee](#what-this-design-cannot-guarantee) before step 1. It
is the reason the level is called `isolated_job` and not `independent_sandbox`, and it is the
part an owner has to be able to repeat to whoever asks what the label means.

## The one thing step 4 might tell you

The control that denies the link-local metadata server at `169.254.169.254` is the private user
and network namespace the entrypoint creates. No VPC firewall rule reaches that address, and a
Cloud Run container holds neither `CAP_NET_ADMIN` nor `CAP_SYS_ADMIN`, so there is no second
mechanism behind it.

Whether an unprivileged user namespace can be created depends on the sandbox the platform runs
the container in, and that is not something this repository can assert from outside. It has been
observed unavailable under a restrictive seccomp profile: building the job image locally and
running one task body inside it reports `network_namespace: "unavailable"`, and the internet
probe then comes back `reached: true`, because only the cleared resolver is left. The driver
refuses that evidence, which is correct, but it means the feature is inert rather than unsafe.

So step 4 has two possible outcomes, and both are information:

* probes all `false` and `network_namespace: "applied"`: the level can be claimed, continue;
* any probe `true` or `null`: stop at step 4. Do not flip the driver. The service keeps
  producing honest `development_unverified` evidence, which is what it produced before.

Running step 4 before step 5 exists precisely so this is discovered against a throwaway
execution rather than against every verification.

## Ordered owner steps

Every command names the project and region explicitly. Substitute the installation's own
values for `PROJECT`, `REGION`, `GAR_REPOSITORY`, and `ENVIRONMENT`; they are the same values
the deploy workflows read from `vars.GCP_PROJECT_ID`, `vars.GCP_REGION`, `vars.GAR_REPOSITORY`.

### 1. Apply the Terraform

```sh
cd infrastructure/remediation/terraform
```

Set these in the tfvars file, on top of the existing variables:

```hcl
enable_cloud_run_job_sandbox      = true
sandbox_bucket_prefix             = "<globally unique prefix>"
sandbox_job_name                  = "codesentry-remediation-sandbox"
remediation_service_account_email = "<the identity codesentry-remediation runs as>"
```

`remediation_service_account_email` is required once the sandbox is enabled. Leaving it empty
fails the plan with that message rather than creating IAM members of the literal form
`serviceAccount:`.

```sh
terraform init
terraform plan  -out=sandbox.tfplan
terraform apply sandbox.tfplan
```

The module needs Terraform >= 1.6. This apply creates:

* `<prefix>-snapshots` and `<prefix>-results`: two buckets, uniform access, public access
  prevention enforced, one-day lifecycle deletion, versioning off;
* `remediation-sandbox-<environment>`: the identity every sandbox task runs as. Its whole
  authority is `objectViewer` on the snapshots bucket, `objectCreator` on the results bucket,
  and `run.viewer` on this one job;
* `remediation-sandbox-<environment>`: a VPC and subnet with Private Google Access on, no Cloud
  NAT, no peering, an egress allow rule for the two Private Google Access ranges on tcp/443 at
  priority 1000, and a deny-all egress rule at priority 65000;
* the Cloud Run v2 job: 1 vCPU, 1 GiB, task timeout 600 s, `max_retries = 0`, direct VPC egress
  with `ALL_TRAFFIC`, running as the sandbox identity;
* a custom role `remediation_sandbox_job_operator_<environment>` bound to the remediation
  service on this job: start, poll, and cancel executions, and nothing that can change the job's
  image or its service account.

The job is created pointing at a placeholder digest and cannot run yet. That is expected.

Record the outputs; steps 3 and 5 need them.

```sh
terraform output sandbox_snapshot_bucket sandbox_result_bucket sandbox_job_name
```

### 2. Build and push the first job image

The job image is built from the same `services/remediation-service/Dockerfile` as the service,
with `RUNTIME_UID=0`. The job entrypoint has to drop the repository's check to a *different*
unprivileged user (`sandboxcheck`, uid 65533, created in that Dockerfile), and only a process
that starts as root can change uid. Cloud Run offers no way to override a container's user, so
the difference lives in the image.

```sh
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

docker build \
  --build-arg RUNTIME_UID=0 \
  -f services/remediation-service/Dockerfile \
  -t "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)" \
  services/remediation-service

docker push "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)"
```

`.github/workflows/deploy-remediation-cloudrun.yml` does exactly this on every push to `main`,
so after the first manual build this step is automatic. Do it by hand once, here, because the
next two steps have to run against a known digest before the driver is ever selected.

### 3. Compute the digest and point the job at it

```sh
DIGEST=$(gcloud artifacts docker images describe \
  "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)" \
  --project "${PROJECT}" --format='value(image_summary.digest)')

IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job@${DIGEST}"
echo "${IMAGE}"

gcloud run jobs update codesentry-remediation-sandbox \
  --image "${IMAGE}" \
  --region "${REGION}" --project "${PROJECT}"
```

`${IMAGE}` in full, registry path and all, is what `SANDBOX_IMAGE_DIGEST` must be set to. It is
not the bare `sha256:...`. The driver compares it, character for character, against the image
each task reads back from the Cloud Run Admin API, and returns `inconclusive` with
`sandbox_image_digest_mismatch` on any disagreement, including a task that could not read one.

Terraform ignores changes to the job's image on purpose (`ignore_changes` on the container
image), so a later `terraform plan` does not try to roll this back to the placeholder.

### 4. Smoke test one execution and check the probes came back denied

This is the step that decides whether the level may be claimed. Run it before the driver is
selected, so a sandbox that does not deny the network is found here and not in a verification.

```sh
BUCKET=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_result_bucket)
NONCE=$(openssl rand -hex 32)
PREFIX="smoke/$(date +%s)"
```

The smoke test runs the job with overrides that point at a snapshot the operator uploads. Build
a one-file archive, upload it, and start one execution:

```sh
SNAPSHOTS=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_snapshot_bucket)
WORK=$(mktemp -d)
mkdir -p "${WORK}/repo" && printf 'print("smoke")\n' > "${WORK}/repo/smoke.py"
tar -C "${WORK}/repo" -czf "${WORK}/baseline.tar.gz" smoke.py
cp "${WORK}/baseline.tar.gz" "${WORK}/candidate.tar.gz"

for VARIANT in baseline candidate; do
  gcloud storage cp "${WORK}/${VARIANT}.tar.gz" "gs://${SNAPSHOTS}/${PREFIX}/${VARIANT}.tar.gz" --project "${PROJECT}"
done

MANIFEST=$(python3 - "${WORK}" "${PREFIX}" <<'PY'
import hashlib, json, pathlib, sys
work, prefix = pathlib.Path(sys.argv[1]), sys.argv[2]
print(json.dumps({
    variant: {
        "object": f"{prefix}/{variant}.tar.gz",
        "sha256": "sha256:" + hashlib.sha256((work / f"{variant}.tar.gz").read_bytes()).hexdigest(),
    }
    for variant in ("baseline", "candidate")
}, sort_keys=True))
PY
)

gcloud run jobs execute codesentry-remediation-sandbox \
  --region "${REGION}" --project "${PROJECT}" --wait --tasks 2 \
  --update-env-vars "^@^SANDBOX_JOB_SNAPSHOT_BUCKET=${SNAPSHOTS}@SANDBOX_JOB_SNAPSHOT_MANIFEST=${MANIFEST}@SANDBOX_JOB_RESULT_BUCKET=${BUCKET}@SANDBOX_JOB_RESULT_PREFIX=${PREFIX}@SANDBOX_JOB_CHECK={\"check_id\":\"smoke\",\"kind\":\"behavior\",\"argv\":[\"python3\",\"smoke.py\"],\"timeout_seconds\":30}@SANDBOX_JOB_NONCE=${NONCE}@SANDBOX_JOB_CHECK_USER=sandboxcheck@SANDBOX_JOB_PROJECT=${PROJECT}@SANDBOX_JOB_REGION=${REGION}@SANDBOX_JOB_NAME=codesentry-remediation-sandbox"
```

Then read both results and assert what they measured. This is the acceptance check; it fails
loudly rather than printing something an operator has to interpret:

```sh
for VARIANT in baseline candidate; do
  gcloud storage cat "gs://${BUCKET}/${PREFIX}/${VARIANT}.json" --project "${PROJECT}"
done | python3 - "${NONCE}" "${IMAGE}" <<'PY'
import hashlib, hmac, json, sys

nonce, expected_image = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
decoder, index, envelopes = json.JSONDecoder(), 0, []
while index < len(raw):
    while index < len(raw) and raw[index].isspace():
        index += 1
    if index >= len(raw):
        break
    document, index = decoder.raw_decode(raw, index)
    envelopes.append(document)

assert len(envelopes) == 2, f"expected two task results, got {len(envelopes)}"
for envelope in envelopes:
    signature = hmac.new(nonce.encode(), envelope["payload"].encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, envelope["signature"]), "result was not written by this execution"
    result = json.loads(envelope["payload"])
    runner = result["runner"]
    assert runner["environment_kind"] == "cloud-run-job", runner
    assert runner["image_digest"] == expected_image, (runner["image_digest"], expected_image)
    for target in ("metadata", "internet", "dns"):
        probe = result["probes"][target]
        assert probe["reached"] is False, f"{target} was {probe}; the sandbox did not deny the network"
    print(f"{result['variant']}: exit {result['exit_code']}, "
          f"namespace {runner['network_namespace']}, resolver {runner['dns_resolution']}, probes denied")
print("SMOKE TEST PASSED")
PY
```

A `reached: true` means the network was not denied. A `reached: null` means the probe could not
run, which proves nothing and is refused exactly the same way. Either one stops the rollout
here: do not continue to step 5. Check `network_namespace` in the printed line first, because
`unavailable` there means the kernel refused the unprivileged user namespace and only the
cleared resolver and the VPC rules are denying anything.

Clean up the smoke objects; the one-day lifecycle rule is a backstop, not the plan:

```sh
gcloud storage rm "gs://${SNAPSHOTS}/${PREFIX}/**" "gs://${BUCKET}/${PREFIX}/**" --project "${PROJECT}"
```

### 5. Flip the driver

Only after step 4 printed `SMOKE TEST PASSED`:

```sh
gcloud run services update codesentry-remediation \
  --region "${REGION}" --project "${PROJECT}" \
  --update-env-vars "\
SANDBOX_DRIVER=cloud_run_job,\
SANDBOX_JOB_NAME=codesentry-remediation-sandbox,\
SANDBOX_JOB_REGION=${REGION},\
SANDBOX_JOB_PROJECT=${PROJECT},\
SANDBOX_BUCKET=${SNAPSHOTS},\
SANDBOX_RESULTS_BUCKET=${BUCKET},\
SANDBOX_IMAGE_DIGEST=${IMAGE}"
```

Or, equivalently, run the deploy workflow with its `SANDBOX_DRIVER` input set to
`cloud_run_job`. The input defaults to `local`, so an ordinary push to `main` never flips the
driver by itself.

`SANDBOX_RESULTS_BUCKET` may be omitted when the two buckets are the Terraform pair: the driver
derives `<prefix>-results` from `<prefix>-snapshots`. Set it explicitly anyway; an env var that
says what it means is cheaper than remembering the derivation.

To go back, set `SANDBOX_DRIVER=local`. Nothing else has to change, and evidence produced
afterwards is labelled `development_unverified` again, honestly.

### 6. Confirm one real verification

Generate a fix on a test repository and read the evidence:

```
GET /api/remediations/:id/evidence
```

The `verification` record must carry `verification_level: "isolated_job"`, a `runner` with
`environment_kind: "cloud-run-job"`, `job_executions` naming each execution, and, on every
completed baseline and candidate result, `network_probes` with all three targets at
`reached: false`. The pull request comment reads "isolated sandbox (Cloud Run job, network
denied)". A run that instead comes back `inconclusive` with `sandbox_network_not_denied` or
`sandbox_image_digest_mismatch` is the driver refusing to claim the level, which is the
designed behaviour and not a bug to work around.

## Expected latency and cost

Order of magnitude only; measure the installation's own numbers before quoting any of this.

**Latency.** One check is one execution of two tasks running concurrently, so a check costs
container start plus the slower of its two variants. Cloud Run job task start is seconds, not
milliseconds: expect roughly 10-30 s before the check's first instruction, dominated by the
image pull on a cold start. Checks run one execution after another, so a verification with
three checks adds roughly 1-2 minutes of wall clock over the local driver, which has no start
cost at all. The driver allows a check its own timeout plus a 180 s start margin before it
calls the execution lost, and the job's own task timeout is 600 s.

**Cost.** A task is 1 vCPU and 1 GiB for its lifetime. At Cloud Run's per-second rates that is
on the order of $0.00003 per task-second, so a 60 s check pair is roughly half a US cent. A
verification of three checks is on the order of one to two cents; a month of a few hundred
verifications is single-digit dollars. The two buckets hold objects for at most a day and the
snapshot objects are deleted as each verification ends, so storage is rounding error. The
dominant cost of a repair remains the model call, not the sandbox.

No Cloud NAT is provisioned, which is both a control and the reason there is no per-GB egress
charge to account for.

## What this design cannot guarantee

Stated plainly, because the verification level's whole value is that it claims only what it
measured.

1. **The probes are one measurement at one moment, from one process.** They run from the
   check's own user, in the check's own isolation context, immediately before the check starts.
   They do not prove the network stayed unreachable for the check's whole lifetime, and they do
   not enumerate every address a check might try. A control that failed open after the probe
   ran would not be caught.
2. **There is no read-only root filesystem.** A Cloud Run container has a writable overlay. The
   check can write anywhere its user can write, including over the interpreters on `PATH`,
   inside its own task. This is one of the two reasons the level is not `independent_sandbox`,
   and `runner.read_only_root` is reported as `false` rather than omitted.
3. **There is no gVisor runtime class.** The isolation boundary is the ordinary container
   boundary Cloud Run provides, not a user-space kernel. A container escape is a container
   escape.
4. **The unprivileged user namespace may not be available, and it is the only thing denying the
   metadata server.** The entrypoint feature-detects it in a throwaway child and reports
   `network_namespace: "applied"` or `"unavailable"`. When it is unavailable, the only remaining
   denials are the cleared `/etc/resolv.conf` and the VPC's egress rules, and neither of those
   reaches `169.254.169.254`. The driver refuses the evidence when any probe came back reachable,
   so the failure is inert rather than unsafe, but an operator reading evidence should look at
   this field rather than assume the strongest control was in force. See
   [The one thing step 4 might tell you](#the-one-thing-step-4-might-tell-you).
5. **The entrypoint runs as root inside the job container.** It has to, in order to drop the
   check to a different user. It never executes repository content, and the check runs as
   `sandboxcheck`, which holds none of the task's credentials and cannot read the entrypoint's
   environment. But root in that container is real, and a defect in the entrypoint itself is not
   contained by any of the controls above.
6. **There is no broker trust boundary.** The deployed shape is `SANDBOX_BROKER_MODE=inprocess`:
   the evidence is assembled in the repair service's own process, and there is no attestation
   between that process and the control plane. This level improves where the *check* runs. It
   does not add the separate, attested broker the production design calls for.
7. **The image digest check trusts the Cloud Run Admin API, not the running kernel.** Each task
   reads the job's configured image with its own credentials and reports it; the driver compares
   that against the pinned digest. That establishes the job was configured to run that image. It
   is not an attestation of the bytes that were actually executed.
8. **The HMAC nonce proves origin, not correctness.** A result that verifies against the nonce
   came from a task this driver started with this nonce. It does not make the task's own
   measurements true, which is why the driver independently checks the check id, the variant,
   the image digest, and every probe before it accepts anything.
9. **None of this satisfies the production isolation gate.** `SANDBOX_NETWORK_POLICY_ATTESTED`
   and `SANDBOX_NODE_LIMITS_ATTESTED` are about the Kubernetes/gVisor broker and stay `false`.
   Nothing in this runbook is evidence for setting either of them.

## Failure modes and what they mean

| What you see | What it means | What to do |
| --- | --- | --- |
| `inconclusive` / `sandbox_network_not_denied` | A probe reached its target, or could not be run. The sandbox did not do what the level claims, so no check result is reported at all | Re-run step 4 by hand and read `network_namespace` and `dns_resolution`. `unavailable` there with the metadata probe reached means the platform refused the user namespace and the level cannot be claimed at all: set `SANDBOX_DRIVER=local` and stop. Otherwise check the VPC egress rules were not widened and that no Cloud NAT was added |
| `inconclusive` / `sandbox_image_digest_mismatch` | A task reported an image other than `SANDBOX_IMAGE_DIGEST`, or could not read one | A deploy updated the job without updating the service's env var, or the job identity lost `run.viewer` on the job. Re-run step 3 |
| `sandbox_result_unavailable` on every variant | No signed result object was readable | Check the job identity still holds `objectCreator` on the results bucket and the remediation identity still holds `objectViewer`. Read the execution's logs |
| `check_user_unavailable:KeyError` | The image has no `sandboxcheck` user | The job image was built from an older Dockerfile. Re-run steps 2 and 3 |
| `check_deadline_exceeded` | The execution did not finish inside the check's budget plus the 180 s start margin | Usually a cold start behind an image pull. If it repeats, the check's own `timeout_seconds` is too small for a container-start-bound sandbox |
| `sandbox_execution_failed` | The driver itself raised | Configuration: a missing `SANDBOX_JOB_*` variable, or the remediation identity lacking the custom operator role. The service logs name which |

## Related

* [Remediation operations runbook](remediation.md) for the rest of the deployment.
* `services/remediation-service/contracts/sandbox-broker-v1.md` for the driver's evidence shape.
* `services/remediation-service/contracts/repair-v1.md` for what each verification level means
  to a consumer of the repair API.
