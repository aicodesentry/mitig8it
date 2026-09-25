"""The Node the action actually runs on must be able to verify a JavaScript repair.

This is the in-image half of the Node pin. tests/test_action_definition.py compares the two
Dockerfiles, which is a statement about the repository; this runs the interpreter that is on
PATH and asks it for the three things the repair engine's sandbox harness needs. Inside the
image that is the pinned runtime, and the test is therefore the proof that the image can verify
JavaScript at all.

The September 2026 trial is what this exists for. The image pinned Node 20, the harness needed
22.6 and 22.15 features, and the only symptom was one ERROR line in a log nobody had to read:
zero fixes were produced on four JavaScript repositories and the review looked otherwise normal.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

# What services/remediation-service/src/sandbox needs of the runtime it launches checks in.
# `module.stripTypeScriptTypes` arrived in Node 22.6 and `module.registerHooks` in 22.15.
PROBE = (
    "const m = require('node:module');"
    "m.stripTypeScriptTypes('const x: number = 1;');"
    "if (typeof m.registerHooks !== 'function') throw new Error('registerHooks is missing');"
    "process.stdout.write('ok');"
)


@pytest.fixture(autouse=True)
def node_present():
    if not shutil.which("node"):
        pytest.skip("node is not on PATH")


def test_node_can_strip_types_and_register_hooks():
    completed = subprocess.run(
        [
            "node",
            "--experimental-strip-types",
            "--disable-warning=ExperimentalWarning",
            "-e",
            PROBE,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    version = subprocess.run(
        ["node", "--version"], capture_output=True, text=True, timeout=60, check=False
    ).stdout.strip()
    assert completed.returncode == 0, (
        "the sandbox test harness needs Node features this runtime does not provide "
        f"(node here reports {version}); the supported runtime is the one "
        f"services/remediation-service/Dockerfile pins in ARG NODE_VERSION: {completed.stderr}"
    )
    assert completed.stdout == "ok"
