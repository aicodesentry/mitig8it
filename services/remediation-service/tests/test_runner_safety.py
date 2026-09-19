from pathlib import Path

import pytest

from src.sandbox.runner import _safe_path
from src.sandbox.kubernetes_driver import KubernetesDriverConfig, KubernetesJobDriver


def test_runner_path_resolution_rejects_escape(tmp_path: Path):
    with pytest.raises(ValueError):
        _safe_path(tmp_path, "../../etc/passwd")
    with pytest.raises(ValueError):
        _safe_path(tmp_path, "/etc/passwd")
    assert _safe_path(tmp_path, "src/app.ts") == tmp_path / "src" / "app.ts"


def test_kubernetes_workload_never_mounts_input_capability_and_runs_direct_argv():
    driver = object.__new__(KubernetesJobDriver)
    driver.settings = KubernetesDriverConfig(namespace="sandbox", service_account_name="sandbox-no-access")
    job = driver._job(
        "repair-abc-0-b",
        "repair-abc-input",
        "ghcr.io/mitig8it/runner@sha256:" + "c" * 64,
        "baseline",
        {"argv": ["npm", "test", "--", "security"], "timeout_seconds": 60},
    )
    spec = job.spec.template.spec
    assert spec.runtime_class_name == "gvisor"
    assert spec.automount_service_account_token is False
    assert spec.init_containers[0].volume_mounts[0].name == "input"
    assert "input" not in {mount.name for mount in spec.containers[0].volume_mounts}
    assert spec.containers[0].command == ["npm"]
    assert spec.containers[0].args == ["test", "--", "security"]
    assert spec.containers[0].security_context.capabilities.drop == ["ALL"]


class _FakeApiException(Exception):
    def __init__(self, status):
        super().__init__(f"status {status}")
        self.status = status


def _stub_driver(monkeypatch, *, create_status=None):
    import src.sandbox.kubernetes_driver as module

    driver = object.__new__(KubernetesJobDriver)
    driver.settings = KubernetesDriverConfig(namespace="sandbox", service_account_name="sandbox-no-access", poll_interval_seconds=0.01)
    deleted: list[str] = []

    class Core:
        def create_namespaced_secret(self, namespace, secret):
            if create_status is not None:
                raise module.ApiException(create_status)
            return secret

        def delete_namespaced_secret(self, name, namespace):
            deleted.append(name)

        def list_namespaced_pod(self, namespace, label_selector):
            class Items:
                items: list = []

            return Items()

    class Batch:
        def create_namespaced_job(self, namespace, job):
            return job

        def delete_namespaced_job(self, name, namespace, propagation_policy=None):
            return None

    monkeypatch.setattr(module, "ApiException", _FakeApiException)
    driver.core = Core()
    driver.batch = Batch()
    return driver, deleted


def _execute_request(deadline_seconds):
    return {
        "request_digest": "sha256:" + "a" * 64,
        "execution_policy": {
            "image_digest": "ghcr.io/mitig8it/runner@sha256:" + "c" * 64,
            "commands": [{"check_id": "exploit", "kind": "exploit", "argv": ["npm", "test"], "timeout_seconds": 600}],
            "deadline_seconds": deadline_seconds,
        },
    }


def test_job_deadline_is_bounded_by_the_remaining_job_budget():
    driver = object.__new__(KubernetesJobDriver)
    driver.settings = KubernetesDriverConfig(namespace="sandbox", service_account_name="sandbox-no-access")
    job = driver._job("repair-abc-0-b", "repair-abc-input", "ghcr.io/x@sha256:" + "c" * 64, "baseline", {"argv": ["npm", "test"], "timeout_seconds": 600}, 45)
    assert job.spec.active_deadline_seconds == 45


def test_expired_total_deadline_yields_incomplete_checks_not_success(monkeypatch):
    monkeypatch.setenv("SANDBOX_ALLOWED_IMAGE_DIGESTS", "ghcr.io/mitig8it/runner@sha256:" + "c" * 64)
    monkeypatch.setenv("SANDBOX_NETWORK_POLICY_ATTESTED", "true")
    monkeypatch.setenv("SANDBOX_NODE_LIMITS_ATTESTED", "true")
    driver, deleted = _stub_driver(monkeypatch)
    result = driver.execute(_execute_request(0), 0)
    assert result["outcome"] == "inconclusive"
    assert result["checks"][0]["baseline"]["reason_code"] == "job_deadline_exceeded"
    assert deleted == ["repair-" + "a" * 20 + "-input"]


def test_duplicate_execution_never_deletes_another_executions_secret(monkeypatch):
    monkeypatch.setenv("SANDBOX_ALLOWED_IMAGE_DIGESTS", "ghcr.io/mitig8it/runner@sha256:" + "c" * 64)
    monkeypatch.setenv("SANDBOX_NETWORK_POLICY_ATTESTED", "true")
    monkeypatch.setenv("SANDBOX_NODE_LIMITS_ATTESTED", "true")
    driver, deleted = _stub_driver(monkeypatch, create_status=409)
    result = driver.execute(_execute_request(60), 60)
    assert result == {"outcome": "inconclusive", "reason_code": "duplicate_execution_in_flight", "checks": []}
    assert deleted == []
