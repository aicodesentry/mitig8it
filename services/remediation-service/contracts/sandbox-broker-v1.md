# Sandbox broker protocol v1

The repair service sends `POST /v1/verifications` over HTTPS with bearer authentication and `Idempotency-Key: <request_digest>`. The request contains:

- a unique 256-bit `request_nonce`, canonical `request_digest`, and deterministic `execution_id`;
- tenant/repository/revision identities, full exact snapshot, strict whole-file patches, source and candidate snapshot digests;
- actual Git `head_tree_oid` and computed candidate `verified_tree_oid`;
- digest-pinned runner image, `network: deny`, read-only-root requirement, fixed check argv, output cap, deadline, and version manifest.

The executable broker in `src.sandbox.broker_app` passes this request to `KubernetesJobDriver`. The driver creates one immutable request Secret, then a separate one-use GKE Sandbox pod for every baseline/candidate/check tuple. A trusted init container is the only container that mounts the request; it materializes an exact baseline or digest-bound candidate into that pod's private emptyDir. The untrusted workload container cannot mount the request capability and runs the fixed argv directly as its container command. Baseline and candidate never share a pod or writable volume. The broker trusts Kubernetes termination state, not repository-written output; logs are bounded and hashed only. Pods have no mounted service-account token, service links, host mounts/socket, privilege escalation, or Linux capabilities, and use non-root UID, RuntimeDefault seccomp, read-only root, bounded resources/deadline, and `runtimeClassName: gvisor`. The broker deletes every Job and the input Secret after collecting results.

The response is HMAC-SHA256 attested over canonical JSON and includes the request/execution/nonce bindings, both snapshot digests, both Git tree OIDs, runner identity/isolation fields, an explicit `verification_level`, and one baseline/candidate result per exact policy check. A `scanner` check result also carries the parsed `scanner_findings` fingerprints defined in `repair-v1.md`. The repair client verifies the MAC with a distinct attestation key, constant-time comparison, and validates every bound field and check before accepting `passed`.

`POST /v1/verifications` honours `Idempotency-Key`. A repeated key with an identical `request_digest` returns the previously attested evidence without executing a second time; the same key with a different payload digest is rejected with HTTP 409. The Kubernetes driver deletes only the input Secret its own execution created: a duplicate whose Secret already exists returns `inconclusive` with `duplicate_execution_in_flight` rather than removing an in-flight execution's input. The driver enforces the request's total `deadline_seconds` across every baseline and candidate check; checks that lose their budget are reported incomplete with `job_deadline_exceeded` and never as passed.

`SANDBOX_DRIVER=local` selects a development-only subprocess driver. Its evidence declares `verification_level: development_unverified`, `runtime_class: local-subprocess`, `network: unrestricted`, and `read_only_root: false`, and it satisfies no production isolation gate.

Inline Kubernetes Secret transfer is intentionally capped at 700 KB; larger snapshots return `unsupported` until the production one-use object-capability transport is provisioned. The driver also refuses execution unless the runner image digest is allowlisted and `SANDBOX_NETWORK_POLICY_ATTESTED=true` has been set after deployment isolation tests. This flag records an external gate; it does not itself create or prove a NetworkPolicy.

HMAC is suitable only while repair service and broker are within one controlled trust domain. Cross-domain deployments should replace it with asymmetric workload-identity signatures and key rotation while retaining the signed payload fields.
