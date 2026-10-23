"""Compare request-bound service binary identity before any repair side effects."""
from __future__ import annotations

import os
import re

from .models import RepairRequest

IMAGE_DIGEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[a-f0-9]{64}\Z")


def service_image_matches(request: RepairRequest) -> bool:
    expected = request.versions.get("repair_service_image")
    mounted = os.environ.get("REMEDIATION_SERVICE_IMAGE_DIGEST")
    # Development-only requests remain supported without claiming a release
    # identity. Once either side declares an image, both must match exactly.
    if expected is None and mounted is None:
        return True
    return (isinstance(expected, str) and IMAGE_DIGEST.fullmatch(expected) is not None
            and isinstance(mounted, str) and IMAGE_DIGEST.fullmatch(mounted) is not None
            and expected == mounted)
