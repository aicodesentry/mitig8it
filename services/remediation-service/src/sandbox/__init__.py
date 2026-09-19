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
from .local_driver import InProcessSandboxBroker, LocalExecutionError, LocalSubprocessDriver

logger = logging.getLogger("mitig8it.remediation.sandbox")

INPROCESS_BROKER_WARNING = (
    "SANDBOX_BROKER_MODE=inprocess runs repository checks inside this service process through the "
    "local subprocess driver. There is no broker trust boundary, no attestation, and no isolation, "
    "and every result is labelled development_unverified. Never enable it for production traffic."
)


def selected_broker_mode() -> str:
    mode = os.getenv("SANDBOX_BROKER_MODE", "http").strip().lower() or "http"
    if mode not in {"http", "inprocess"}:
        raise BrokerConfigurationError("SANDBOX_BROKER_MODE must be 'http' or 'inprocess'")
    return mode


def create_sandbox_broker() -> SandboxBroker:
    """Production default is the attested HTTPS broker. `inprocess` is development only.

    The in-process broker returns the local driver's honest `development_unverified` level, so
    a policy without `allow_development_verification` still refuses its evidence.
    """
    if selected_broker_mode() == "inprocess":
        logger.warning(INPROCESS_BROKER_WARNING)
        return InProcessSandboxBroker(LocalSubprocessDriver())
    return HttpSandboxBroker.from_env()


__all__ = [
    "BrokerConfigurationError",
    "BrokerEvidenceError",
    "BrokerTransportError",
    "HttpSandboxBroker",
    "INPROCESS_BROKER_WARNING",
    "InProcessSandboxBroker",
    "LocalExecutionError",
    "LocalSubprocessDriver",
    "SandboxBroker",
    "create_sandbox_broker",
    "selected_broker_mode",
]
