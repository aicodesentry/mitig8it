"""One place that turns `SANDBOX_DRIVER` into a driver.

The HTTP broker and the in-process broker both have to honour the same variable. They did
not: `broker_app` read it while the in-process broker, which is what the Cloud Run deployment
actually runs, always built the local subprocess driver. Setting `SANDBOX_DRIVER` on that
deployment therefore changed nothing. Both now come through here.

Every import is deferred. The local driver path must not need `kubernetes`, and neither the
local nor the Kubernetes path must need `google-cloud-run` or `google-cloud-storage`.
"""
from __future__ import annotations

import os
from typing import Any

KUBERNETES_DRIVER = "kubernetes"
LOCAL_DRIVER = "local"
CLOUD_RUN_JOB_DRIVER = "cloud_run_job"
DRIVER_KINDS = (KUBERNETES_DRIVER, LOCAL_DRIVER, CLOUD_RUN_JOB_DRIVER)


class DriverSelectionError(ValueError):
    pass


def selected_driver_kind(default: str = KUBERNETES_DRIVER) -> str:
    """The configured driver, or `default` when `SANDBOX_DRIVER` is unset.

    The broker's default stays `kubernetes`: where two drivers are equally configured, the
    strongest isolation wins. The in-process broker passes `local` instead, because that is
    what it has always built and a process with no broker trust boundary must not silently
    acquire a cluster one. Either way an explicit `SANDBOX_DRIVER` decides.
    """
    kind = os.getenv("SANDBOX_DRIVER", default).strip().lower() or default
    if kind not in DRIVER_KINDS:
        raise DriverSelectionError(f"SANDBOX_DRIVER must be one of {', '.join(DRIVER_KINDS)}")
    return kind


def build_driver(kind: str | None = None) -> Any:
    """Constructs the selected driver. `local` is development only and says so when it starts."""
    selected = kind or selected_driver_kind()
    if selected == LOCAL_DRIVER:
        from .local_driver import LocalSubprocessDriver

        return LocalSubprocessDriver()
    if selected == CLOUD_RUN_JOB_DRIVER:
        from .cloud_run_job_driver import CloudRunJobDriver

        return CloudRunJobDriver()
    from .kubernetes_driver import KubernetesJobDriver

    return KubernetesJobDriver()
