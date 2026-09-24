"""`SANDBOX_DRIVER` has to mean the same thing to the HTTP broker and the in-process broker.

Before `src/sandbox/drivers.py` existed it did not: `broker_app` read the variable while the
in-process broker, which is what the Cloud Run deployment actually runs, always built the local
subprocess driver, so setting `SANDBOX_DRIVER=cloud_run_job` on that deployment changed nothing
and its evidence stayed `development_unverified`.
"""
from __future__ import annotations

import pytest

from src.sandbox import (
    INPROCESS_BROKER_WARNING,
    INPROCESS_CLOUD_RUN_JOB_NOTICE,
    BrokerConfigurationError,
    InProcessSandboxBroker,
    LocalSubprocessDriver,
    create_sandbox_broker,
)
from src.sandbox.cloud_run_job_driver import CloudRunJobConfigurationError, CloudRunJobDriver
from src.sandbox.drivers import DRIVER_KINDS, DriverSelectionError, build_driver, selected_driver_kind

IMAGE_DIGEST = "us-central1-docker.pkg.dev/p/r/remediation-job@sha256:" + "a" * 64


@pytest.fixture
def job_environment(monkeypatch):
    monkeypatch.setenv("SANDBOX_JOB_NAME", "sandbox")
    monkeypatch.setenv("SANDBOX_JOB_REGION", "us-central1")
    monkeypatch.setenv("SANDBOX_JOB_PROJECT", "proj")
    monkeypatch.setenv("SANDBOX_BUCKET", "snap")
    monkeypatch.setenv("SANDBOX_IMAGE_DIGEST", IMAGE_DIGEST)


def test_the_three_drivers_are_the_whole_set():
    assert DRIVER_KINDS == ("kubernetes", "local", "cloud_run_job")


def test_the_strongest_isolation_is_the_default_where_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("SANDBOX_DRIVER", raising=False)
    assert selected_driver_kind() == "kubernetes"
    assert selected_driver_kind("local") == "local", "the in-process broker keeps its own weaker default"


def test_an_explicit_driver_beats_either_default(monkeypatch):
    monkeypatch.setenv("SANDBOX_DRIVER", "cloud_run_job")
    assert selected_driver_kind() == "cloud_run_job"
    assert selected_driver_kind("local") == "cloud_run_job"


def test_an_unknown_driver_is_refused_rather_than_guessed(monkeypatch):
    monkeypatch.setenv("SANDBOX_DRIVER", "docker")
    with pytest.raises(DriverSelectionError) as failure:
        selected_driver_kind()
    assert "cloud_run_job" in str(failure.value)


def test_the_cloud_run_job_driver_is_built_from_the_environment(monkeypatch, job_environment):
    monkeypatch.setenv("SANDBOX_DRIVER", "cloud_run_job")
    driver = build_driver()
    assert isinstance(driver, CloudRunJobDriver)
    assert driver.verification_level == "isolated_job"
    assert driver.settings.job_path == "projects/proj/locations/us-central1/jobs/sandbox"


def test_an_unconfigured_cloud_run_job_driver_fails_loudly_at_construction(monkeypatch):
    for name in ("SANDBOX_JOB_NAME", "SANDBOX_JOB_REGION", "SANDBOX_JOB_PROJECT", "SANDBOX_BUCKET", "SANDBOX_IMAGE_DIGEST"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(CloudRunJobConfigurationError):
        build_driver("cloud_run_job")


def test_the_inprocess_broker_honours_the_driver_variable(monkeypatch, job_environment, caplog):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "cloud_run_job")
    with caplog.at_level("WARNING"):
        broker = create_sandbox_broker()
    assert isinstance(broker, InProcessSandboxBroker)
    assert isinstance(broker.driver, CloudRunJobDriver)
    assert any(INPROCESS_CLOUD_RUN_JOB_NOTICE in record.message for record in caplog.records)


def test_the_inprocess_broker_still_defaults_to_the_development_driver(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.delenv("SANDBOX_DRIVER", raising=False)
    with caplog.at_level("WARNING"):
        broker = create_sandbox_broker()
    assert isinstance(broker.driver, LocalSubprocessDriver)
    assert any(INPROCESS_BROKER_WARNING in record.message for record in caplog.records)


def test_the_inprocess_broker_refuses_an_unknown_driver(monkeypatch):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "docker")
    with pytest.raises(BrokerConfigurationError):
        create_sandbox_broker()
