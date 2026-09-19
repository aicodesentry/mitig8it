from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .digests import git_blob_sha1
from .models import GitTreeEntry
from .retrieval.snapshot import validate_repo_path


class GitTreeError(ValueError):
    pass


@dataclass
class _Node:
    directories: dict[str, "_Node"] = field(default_factory=dict)
    leaves: dict[str, tuple[str, str, str]] = field(default_factory=dict)


def _hash_object(kind: str, body: bytes) -> str:
    header = f"{kind} {len(body)}\0".encode("ascii")
    return hashlib.sha1(header + body).hexdigest()  # noqa: S324 - required Git SHA-1 object identity.


def _tree_oid(node: _Node) -> str:
    records: list[tuple[bytes, bytes]] = []
    for name, child in node.directories.items():
        oid = _tree_oid(child)
        records.append((name.encode("utf-8") + b"/", b"40000 " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)))
    for name, (mode, _kind, oid) in node.leaves.items():
        normalized_mode = mode.lstrip("0")
        records.append((name.encode("utf-8"), normalized_mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)))
    records.sort(key=lambda item: item[0])
    return _hash_object("tree", b"".join(record for _, record in records))


def compute_tree_oid(entries: list[GitTreeEntry], replacements: dict[str, str] | None = None) -> str:
    replacements = replacements or {}
    root = _Node()
    paths: set[str] = set()
    leaf_entries = [entry for entry in entries if entry.type != "tree"]
    if not leaf_entries:
        raise GitTreeError("complete tree contains no leaves")
    metadata = {entry.path: entry for entry in leaf_entries}
    if not set(replacements).issubset(metadata):
        raise GitTreeError("replacement path is absent from complete Git tree")
    for entry in leaf_entries:
        path = validate_repo_path(entry.path)
        if path in paths:
            raise GitTreeError(f"duplicate Git tree path: {path}")
        paths.add(path)
        if entry.type == "blob" and entry.mode not in {"100644", "100755", "120000"}:
            raise GitTreeError("invalid blob mode")
        if entry.type == "commit" and entry.mode != "160000":
            raise GitTreeError("invalid submodule mode")
        if path in replacements and entry.mode in {"120000", "160000"}:
            raise GitTreeError("repairs cannot replace symlinks or submodules")
        oid = git_blob_sha1(replacements[path].encode("utf-8")) if path in replacements else entry.sha
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            if part in node.leaves:
                raise GitTreeError("Git tree contains a file/directory collision")
            node = node.directories.setdefault(part, _Node())
        name = parts[-1]
        if name in node.directories or name in node.leaves:
            raise GitTreeError("Git tree contains a duplicate or collision")
        node.leaves[name] = (entry.mode, entry.type, oid)
    return _tree_oid(root)


def validate_snapshot_tree(entries: list[GitTreeEntry], expected_oid: str, files: dict[str, str]) -> None:
    actual = compute_tree_oid(entries)
    if actual != expected_oid:
        raise GitTreeError("head_tree_oid does not match complete tree entries")
    metadata = {entry.path: entry for entry in entries if entry.type != "tree"}
    for path, content in files.items():
        entry = metadata.get(path)
        if entry is None or entry.type != "blob":
            raise GitTreeError(f"snapshot file is not bound to a Git blob: {path}")
        if git_blob_sha1(content.encode("utf-8")) != entry.sha:
            raise GitTreeError(f"snapshot content differs from head Git blob: {path}")
