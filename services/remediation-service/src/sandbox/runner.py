"""Trusted snapshot materializer; invoked as a gVisor pod init container.

`materialize_tree` is the shared, trusted materialization and digest verification used
by both the Kubernetes init container and the development-only local subprocess driver,
so both enforce identical path safety and patch digest checks.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any

INPUT = Path("/input/request.json")
ROOT = Path("/workspace/repo")


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _safe_path(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe repository path")
    target = root.joinpath(*path.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("repository path escapes workspace")
    return target


def materialize_tree(root: Path, request: dict[str, Any], variant: str) -> None:
    """Writes the exact snapshot into `root` and, for `candidate`, applies digest-bound patches."""
    if variant not in {"baseline", "candidate"}:
        raise ValueError("sandbox variant is invalid")
    root.mkdir(parents=True, exist_ok=True)
    for item in request["snapshot"]:
        target = _safe_path(root, item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ValueError("duplicate or symlink snapshot path")
        target.write_text(item["content"], encoding="utf-8")
    if variant == "candidate":
        for patch in request["patches"]:
            target = _safe_path(root, patch["path"])
            if target.is_symlink() or not target.is_file():
                raise ValueError("patch target is not a regular file")
            if _digest(target.read_bytes()) != patch["base_sha256"]:
                raise ValueError("patch base digest mismatch")
            replacement = patch["replacement_content"].encode("utf-8")
            if _digest(replacement) != patch["new_sha256"]:
                raise ValueError("patch replacement digest mismatch")
            target.write_bytes(replacement)


def materialize(variant: str) -> None:
    if os.getenv("MITIG8IT_SANDBOX_RUNTIME") != "gvisor":
        raise ValueError("sandbox runtime is invalid")
    request = json.loads(INPUT.read_text(encoding="utf-8"))
    if ROOT.exists():
        raise ValueError("sandbox workspace is not empty")
    materialize_tree(ROOT, request, variant)


if __name__ == "__main__":
    try:
        materialize(sys.argv[1])
    except Exception as error:
        print(json.dumps({"materializer_error": type(error).__name__}))
        raise SystemExit(70)
