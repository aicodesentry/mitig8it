from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from src.git_tree import GitTreeError, compute_tree_oid, validate_snapshot_tree
from src.models import GitTreeEntry, RepairRequest
from src.retrieval import Snapshot, SnapshotError


def test_snapshot_rejects_traversal(request_payload):
    request_payload["files"][0]["path"] = "src/../../secret"
    request_payload["files"][0].pop("sha")
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(SnapshotError, match="parent"):
        Snapshot(request)


def test_snapshot_verifies_optional_hash(request_payload):
    request_payload["files"][0]["sha"] = "0" * 40
    with pytest.raises(ValidationError, match="does not match sha"):
        RepairRequest.model_validate(request_payload)


def test_git_tree_oid_matches_independent_single_blob_construction():
    content = "hello\n"
    blob_body = content.encode()
    blob_oid = hashlib.sha1(f"blob {len(blob_body)}\0".encode() + blob_body).hexdigest()
    tree_body = b"100644 hello.txt\0" + bytes.fromhex(blob_oid)
    expected = hashlib.sha1(f"tree {len(tree_body)}\0".encode() + tree_body).hexdigest()
    entry = GitTreeEntry(path="hello.txt", mode="100644", type="blob", sha=blob_oid)
    assert compute_tree_oid([entry]) == expected


def test_validate_tree_binds_snapshot_bytes(request_payload):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(GitTreeError, match="differs"):
        validate_snapshot_tree(request.tree_entries, request.head_tree_oid, {"src/db.ts": "tampered"})
    validate_snapshot_tree(request.tree_entries, request.head_tree_oid, {path: snapshot.full_content(path) for path in snapshot.paths})


def test_candidate_tree_preserves_executable_mode():
    original = "console.log('old')\n"
    old_oid = hashlib.sha1(f"blob {len(original.encode())}\0".encode() + original.encode()).hexdigest()
    entry = GitTreeEntry(path="bin/tool.js", mode="100755", type="blob", sha=old_oid)
    replaced = compute_tree_oid([entry], {"bin/tool.js": "console.log('new')\n"})
    non_executable = compute_tree_oid([entry.model_copy(update={"mode": "100644"})], {"bin/tool.js": "console.log('new')\n"})
    assert replaced != non_executable
