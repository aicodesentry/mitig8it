from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..digests import content_sha256, digest_json
from ..models import RepairRequest


class SnapshotError(ValueError):
    pass


@dataclass(frozen=True)
class ContextHit:
    path: str
    line_start: int
    line_end: int
    content: str
    reason: str
    content_digest: str

    def provenance(self, request: RepairRequest) -> dict[str, object]:
        return {
            "tenant_id": request.tenant_id,
            "repository_id": request.repository_id,
            "commit_sha": request.head_sha,
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "reason": self.reason,
            "content_digest": self.content_digest,
        }


def validate_repo_path(value: str) -> str:
    if not value or len(value) > 512:
        raise SnapshotError("path is empty or too long")
    if value != unicodedata.normalize("NFC", value):
        raise SnapshotError("path must use NFC Unicode normalization")
    if "\\" in value or "\x00" in value or any(ord(ch) < 32 for ch in value):
        raise SnapshotError("path contains a backslash or control character")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/"):
        raise SnapshotError("absolute paths are forbidden")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotError("path contains an empty, dot, or parent component")
    if path.parts and path.parts[0].lower() == ".git":
        raise SnapshotError("Git metadata paths are forbidden")
    return path.as_posix()


class Snapshot:
    """Validated in-memory exact-commit snapshot; it never materializes host files."""

    def __init__(self, request: RepairRequest):
        policy = request.policy
        if len(request.files) > policy.max_snapshot_files:
            raise SnapshotError("snapshot_file_limit_exceeded")
        files: dict[str, str] = {}
        total_bytes = 0
        for item in request.files:
            path = validate_repo_path(item.path)
            if path in files:
                raise SnapshotError(f"duplicate snapshot path: {path}")
            size = len(item.content.encode("utf-8"))
            if size > policy.max_file_bytes:
                raise SnapshotError(f"snapshot file exceeds byte limit: {path}")
            total_bytes += size
            if total_bytes > policy.max_snapshot_bytes:
                raise SnapshotError("snapshot_byte_limit_exceeded")
            files[path] = item.content
        self._files = files
        self.request = request
        entries = [
            {"path": path, "content_digest": content_sha256(content), "bytes": len(content.encode("utf-8"))}
            for path, content in sorted(files.items())
        ]
        self.manifest = {
            "schema_version": "v1",
            "tenant_id": request.tenant_id,
            "repository_id": request.repository_id,
            "commit_sha": request.head_sha,
            "retriever_version": request.versions.get("retriever", "unspecified"),
            "policy_version": request.policy.policy_version,
            "files": entries,
        }
        self.manifest_digest = digest_json(self.manifest)
        self.tree_digest = digest_json({"files": entries})

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(sorted(self._files))

    def read(self, path: str, start: int = 1, end: int | None = None, max_chars: int = 20_000) -> ContextHit:
        normalized = validate_repo_path(path)
        if normalized not in self._files:
            raise SnapshotError("path_not_in_snapshot")
        lines = self._files[normalized].splitlines(keepends=True)
        if start < 1 or start > max(len(lines), 1):
            raise SnapshotError("line_start_out_of_range")
        stop = min(end or len(lines), len(lines))
        if stop < start:
            raise SnapshotError("line_end_out_of_range")
        content = "".join(lines[start - 1 : stop])
        if len(content) > max_chars:
            content = content[:max_chars]
        return ContextHit(normalized, start, stop, content, "scoped_read", content_sha256(content))

    def full_content(self, path: str) -> str:
        normalized = validate_repo_path(path)
        try:
            return self._files[normalized]
        except KeyError as exc:
            raise SnapshotError("path_not_in_snapshot") from exc

    def search(self, query: str, max_results: int = 20, max_chars: int = 24_000) -> list[ContextHit]:
        query = query.strip()
        if not query or len(query) > 200:
            raise SnapshotError("search query must contain 1-200 characters")
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        hits: list[ContextHit] = []
        used = 0
        for path in self.paths:
            lines = self._files[path].splitlines()
            for index, line in enumerate(lines, start=1):
                if not pattern.search(line):
                    continue
                start, end = max(1, index - 3), min(len(lines), index + 3)
                content = "\n".join(lines[start - 1 : end])
                if used + len(content) > max_chars:
                    return hits
                used += len(content)
                hits.append(ContextHit(path, start, end, content, "lexical_match", content_sha256(content)))
                if len(hits) >= max_results:
                    return hits
        return hits

    def nearest_tests(self, source_path: str, max_results: int = 20) -> list[ContextHit]:
        source_path = validate_repo_path(source_path)
        stem = PurePosixPath(source_path).stem.lower()
        candidates = [
            path
            for path in self.paths
            if ("test" in path.lower() or "spec" in path.lower()) and stem in PurePosixPath(path).stem.lower()
        ][:max_results]
        hits = []
        for path in candidates:
            hit = self.read(path, max_chars=12_000)
            hits.append(ContextHit(hit.path, hit.line_start, hit.line_end, hit.content, "nearest_test", hit.content_digest))
        return hits

    def symbol_references(self, symbol: str, max_results: int = 20) -> list[ContextHit]:
        if not re.fullmatch(r"[$A-Za-z_][$\w]{0,127}", symbol):
            raise SnapshotError("symbol must be a JavaScript/TypeScript identifier")
        return [
            ContextHit(hit.path, hit.line_start, hit.line_end, hit.content, "symbol_reference", hit.content_digest)
            for hit in self.search(symbol, max_results=max_results)
        ]
