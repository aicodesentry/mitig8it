from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .execution import aggregate_outcome, output_tail, parse_scanner_findings


class KubernetesExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class KubernetesDriverConfig:
    namespace: str
    service_account_name: str
    runtime_class_name: str = "gvisor"
    max_payload_bytes: int = 700_000
    poll_interval_seconds: float = 2.0


class KubernetesJobDriver:
    """Runs each baseline/candidate check in a separate pod and trusts only Kubernetes status."""

    verification_class = "independent_sandbox"
    verification_level = "independent_sandbox"

    def __init__(self, settings: KubernetesDriverConfig | None = None):
        self.settings = settings or KubernetesDriverConfig(
            namespace=os.environ["SANDBOX_K8S_NAMESPACE"],
            service_account_name=os.getenv("SANDBOX_K8S_SERVICE_ACCOUNT", "sandbox-no-access"),
            runtime_class_name=os.getenv("SANDBOX_K8S_RUNTIME_CLASS", "gvisor"),
        )
        try:
            config.load_incluster_config()
        except config.ConfigException:
            if os.getenv("SANDBOX_BROKER_ALLOW_KUBECONFIG", "").lower() != "true":
                raise KubernetesExecutionError("broker requires in-cluster Kubernetes identity")
            config.load_kube_config()
        self.batch = client.BatchV1Api()
        self.core = client.CoreV1Api()

    @staticmethod
    def _security() -> client.V1SecurityContext:
        return client.V1SecurityContext(
            allow_privilege_escalation=False,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            privileged=False,
            read_only_root_filesystem=True,
            run_as_non_root=True,
            run_as_user=65532,
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )

    def _job(self, name: str, secret_name: str, image: str, variant: str, check: dict[str, Any], budget_seconds: float | None = None) -> client.V1Job:
        labels = {"app": "mitig8it-sandbox", "execution": name.split("-")[1]}
        workspace = client.V1VolumeMount(name="workspace", mount_path="/workspace")
        materializer = client.V1Container(
            name="materializer",
            image=image,
            image_pull_policy="IfNotPresent",
            command=["python3", "/runner/runner.py", variant],
            env=[client.V1EnvVar(name="MITIG8IT_SANDBOX_RUNTIME", value="gvisor")],
            security_context=self._security(),
            resources=client.V1ResourceRequirements(requests={"cpu": "50m", "memory": "64Mi"}, limits={"cpu": "250m", "memory": "256Mi", "ephemeral-storage": "256Mi"}),
            volume_mounts=[client.V1VolumeMount(name="input", mount_path="/input", read_only=True), workspace],
        )
        workload = client.V1Container(
            name="workload",
            image=image,
            image_pull_policy="IfNotPresent",
            command=[check["argv"][0]],
            args=check["argv"][1:],
            working_dir="/workspace/repo",
            env=[client.V1EnvVar(name="HOME", value="/workspace/no-home"), client.V1EnvVar(name="CI", value="true"), client.V1EnvVar(name="NO_COLOR", value="1")],
            stdin=False,
            tty=False,
            security_context=self._security(),
            resources=client.V1ResourceRequirements(requests={"cpu": "250m", "memory": "256Mi", "ephemeral-storage": "256Mi"}, limits={"cpu": "2", "memory": "2Gi", "ephemeral-storage": "2Gi"}),
            volume_mounts=[workspace, client.V1VolumeMount(name="tmp", mount_path="/tmp")],
        )
        pod = client.V1PodSpec(
            automount_service_account_token=False,
            init_containers=[materializer],
            containers=[workload],
            restart_policy="Never",
            runtime_class_name=self.settings.runtime_class_name,
            service_account_name=self.settings.service_account_name,
            enable_service_links=False,
            security_context=client.V1PodSecurityContext(run_as_non_root=True, run_as_user=65532, fs_group=65532),
            volumes=[
                client.V1Volume(name="input", secret=client.V1SecretVolumeSource(secret_name=secret_name, default_mode=0o400)),
                client.V1Volume(name="workspace", empty_dir=client.V1EmptyDirVolumeSource(size_limit="2Gi")),
                client.V1Volume(name="tmp", empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi")),
            ],
        )
        return client.V1Job(
            metadata=client.V1ObjectMeta(name=name, labels=labels),
            spec=client.V1JobSpec(active_deadline_seconds=max(1, int(min(int(check["timeout_seconds"]), budget_seconds if budget_seconds is not None else 900, 900))), backoff_limit=0, ttl_seconds_after_finished=300, template=client.V1PodTemplateSpec(metadata=client.V1ObjectMeta(labels=labels), spec=pod)),
        )

    def runner_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "image_digest": payload["execution_policy"]["image_digest"],
            "network": "deny",
            "read_only_root": True,
            "runtime_class": self.settings.runtime_class_name,
        }

    def _execute_variant(self, name: str, secret_name: str, image: str, variant: str, check: dict[str, Any], budget_seconds: float) -> dict[str, Any]:
        started = time.monotonic()
        if budget_seconds <= 0:
            return {"completed": False, "status": "inconclusive", "exit_code": None, "stdout_digest": None, "output_truncated": False, "duration_ms": 0, "reason_code": "job_deadline_exceeded", "scanner_findings": None}
        self.batch.create_namespaced_job(self.settings.namespace, self._job(name, secret_name, image, variant, check, budget_seconds))
        try:
            cutoff = started + min(int(check["timeout_seconds"]) + 30, budget_seconds, 930)
            while time.monotonic() < cutoff:
                pods = self.core.list_namespaced_pod(self.settings.namespace, label_selector=f"job-name={name}").items
                if pods:
                    pod = pods[0]
                    init_statuses = pod.status.init_container_statuses or []
                    if init_statuses and init_statuses[0].state.terminated and init_statuses[0].state.terminated.exit_code != 0:
                        raise KubernetesExecutionError("trusted materializer failed")
                    statuses = pod.status.container_statuses or []
                    if statuses and statuses[0].state.terminated is not None:
                        terminated = statuses[0].state.terminated
                        text = self.core.read_namespaced_pod_log(pod.metadata.name, self.settings.namespace, container="workload", limit_bytes=2_000_000)
                        log = text.encode("utf-8", errors="replace")
                        completed_normally = terminated.exit_code is not None and not terminated.signal and terminated.reason != "OOMKilled"
                        return {
                            "completed": completed_normally,
                            "status": "passed" if completed_normally and terminated.exit_code == 0 else ("failed" if completed_normally else "inconclusive"),
                            "exit_code": terminated.exit_code,
                            "stdout_digest": f"sha256:{hashlib.sha256(log).hexdigest()}",
                            "output_truncated": len(log) >= 2_000_000,
                            "output_tail": output_tail(text, terminated.exit_code if completed_normally else None),
                            "duration_ms": round((time.monotonic() - started) * 1000),
                            "scanner_findings": parse_scanner_findings(text) if check["kind"] == "scanner" else None,
                        }
                time.sleep(self.settings.poll_interval_seconds)
            return {"completed": False, "status": "inconclusive", "exit_code": None, "stdout_digest": None, "output_truncated": False, "duration_ms": round((time.monotonic() - started) * 1000), "reason_code": "check_deadline_exceeded", "scanner_findings": None}
        finally:
            try:
                self.batch.delete_namespaced_job(name, self.settings.namespace, propagation_policy="Background")
            except ApiException:
                pass

    def execute(self, request: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > self.settings.max_payload_bytes:
            return {"outcome": "unsupported", "reason_code": "snapshot_exceeds_inline_transfer_limit", "checks": []}
        image = request["execution_policy"]["image_digest"]
        allowed = {item.strip() for item in os.getenv("SANDBOX_ALLOWED_IMAGE_DIGESTS", "").split(",") if item.strip()}
        if image not in allowed:
            return {"outcome": "unsupported", "reason_code": "runner_image_not_allowlisted", "checks": []}
        if os.getenv("SANDBOX_NETWORK_POLICY_ATTESTED", "").lower() != "true" or os.getenv("SANDBOX_NODE_LIMITS_ATTESTED", "").lower() != "true":
            return {"outcome": "inconclusive", "reason_code": "sandbox_isolation_not_attested", "checks": []}
        started = time.monotonic()
        suffix = request["request_digest"].removeprefix("sha256:")[:20]
        secret_name = f"repair-{suffix}-input"
        secret = client.V1Secret(metadata=client.V1ObjectMeta(name=secret_name, labels={"app": "mitig8it-sandbox", "execution": suffix}), immutable=True, string_data={"request.json": raw.decode("utf-8")}, type="Opaque")
        try:
            self.core.create_namespaced_secret(self.settings.namespace, secret)
        except ApiException as exc:
            if exc.status == 409:
                # Another execution with this exact request digest already owns the input
                # Secret. Never delete resources this execution did not create.
                return {"outcome": "inconclusive", "reason_code": "duplicate_execution_in_flight", "checks": []}
            raise KubernetesExecutionError("Kubernetes sandbox execution failed") from exc
        try:
            results = []
            for index, check in enumerate(request["execution_policy"]["commands"]):
                record = {"check_id": check["check_id"], "kind": check["kind"], "argv": check["argv"]}
                for variant in ("baseline", "candidate"):
                    remaining = deadline_seconds - (time.monotonic() - started)
                    record[variant] = self._execute_variant(f"repair-{suffix}-{index}-{variant[0]}", secret_name, image, variant, check, remaining)
                results.append(record)
            return {"outcome": aggregate_outcome(results), "checks": results}
        except (ApiException, ValueError, KeyError, TypeError) as exc:
            raise KubernetesExecutionError("Kubernetes sandbox execution failed") from exc
        finally:
            self._delete_owned_resources(suffix)

    def _delete_owned_resources(self, suffix: str) -> None:
        """Deletes only the input Secret this execution created, keyed by its execution suffix."""
        try:
            self.core.delete_namespaced_secret(f"repair-{suffix}-input", self.settings.namespace)
        except ApiException:
            pass

    def cancel(self, request_digest: str) -> None:
        suffix = request_digest.removeprefix("sha256:")[:20]
        try:
            jobs = self.batch.list_namespaced_job(self.settings.namespace, label_selector=f"execution={suffix}").items
            for job in jobs:
                self.batch.delete_namespaced_job(job.metadata.name, self.settings.namespace, propagation_policy="Background")
        finally:
            try:
                self.core.delete_namespaced_secret(f"repair-{suffix}-input", self.settings.namespace)
            except ApiException as exc:
                if exc.status != 404:
                    raise
