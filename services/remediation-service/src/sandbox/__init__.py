from __future__ import annotations

import logging
import os

from .broker import (
    BrokerConfigurationError,
    BrokerEvidenceError,
    BrokerTransportError,
    HttpSandboxBroker,
    SandboxBroker,
)
from .drivers import DRIVER_KINDS, LOCAL_DRIVER, DriverSelectionError, build_driver, selected_driver_kind
from .local_driver import InProcessSandboxBroker, LocalExecutionError, LocalSubprocessDriver

logger = logging.getLogger("mitig8it.remediation.sandbox")

INPROCESS_BROKER_WARNING = (
    "SANDBOX_BROKER_MODE=inprocess runs repository checks inside this service process through the "
    "local subprocess driver. There is no broker trust boundary, no attestation, and no isolation, "
    "and every result is labelled development_unverified. Never enable it for production traffic."
)

INPROCESS_CLOUD_RUN_JOB_NOTICE = (
    "SANDBOX_BROKER_MODE=inprocess with SANDBOX_DRIVER=cloud_run_job keeps the evidence assembly in "
    "this process, but every repository check runs in a separate Cloud Run job container with its own "
    "unprivileged user and a denied network. There is still no broker trust boundary and no "
    "attestation between this process and the control plane."
)


def selected_broker_mode() -> str:
    mode = os.getenv("SANDBOX_BROKER_MODE", "http").strip().lower() or "http"
    if mode not in {"http", "inprocess"}:
        raise BrokerConfigurationError("SANDBOX_BROKER_MODE must be 'http' or 'inprocess'")
    return mode


def create_sandbox_broker() -> SandboxBroker:
    """Production default is the attested HTTPS broker. `inprocess` is development only.

    The in-process broker honours `SANDBOX_DRIVER`, so a deployment that has no separate broker
    can still send its checks to the Cloud Run job sandbox. Whatever driver it builds, the
    broker returns that driver's own honest verification level, and a policy that does not
    allow that level still refuses the evidence.
    """
    if selected_broker_mode() == "inprocess":
        try:
            kind = selected_driver_kind(LOCAL_DRIVER)
        except DriverSelectionError as error:
            raise BrokerConfigurationError(str(error)) from error
        logger.warning(INPROCESS_CLOUD_RUN_JOB_NOTICE if kind == "cloud_run_job" else INPROCESS_BROKER_WARNING)
        return InProcessSandboxBroker(build_driver(kind))
    return HttpSandboxBroker.from_env()


__all__ = [
    "BrokerConfigurationError",
    "DRIVER_KINDS",
    "DriverSelectionError",
    "BrokerEvidenceError",
    "BrokerTransportError",
    "HttpSandboxBroker",
    "INPROCESS_BROKER_WARNING",
    "INPROCESS_CLOUD_RUN_JOB_NOTICE",
    "InProcessSandboxBroker",
    "LocalExecutionError",
    "LocalSubprocessDriver",
    "SandboxBroker",
    "build_driver",
    "create_sandbox_broker",
    "selected_broker_mode",
    "selected_driver_kind",
]
