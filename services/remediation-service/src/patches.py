from __future__ import annotations

import difflib
import base64
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .digests import content_sha256, digest_json
from .models import FilePatch, RepairRequest
from .retrieval import Snapshot, SnapshotError
from .retrieval.snapshot import validate_repo_path


class PatchPolicyError(ValueError):
    pass


NODE_BUILTIN_MODULES = frozenset(
    {
        "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
        "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http",
        "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process",
        "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
        "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
        "worker_threads", "zlib",
    }
)

SYNTAX_CHECKED_SUFFIXES = {".js", ".cjs", ".mjs"}

_REQUIRE_RE = re.compile(r"""\brequire\s*\(\s*['"]([^'"\n]{1,200})['"]\s*\)""")
_IMPORT_FROM_RE = re.compile(r"""\b(?:import|export)\b[^;\n]*?\bfrom\s*['"]([^'"\n]{1,200})['"]""")
_BARE_IMPORT_RE = re.compile(r"""\bimport\s*['"]([^'"\n]{1,200})['"]""")
_DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*['"]([^'"\n]{1,200})['"]\s*\)""")


@dataclass(frozen=True)
class PatchBundle:
    patches: tuple[FilePatch, ...]
    artifact_digest: str
    changed_lines: int
    limitations: tuple[str, ...] = ()

    @property
    def file_manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "path": patch.path,
                "base_sha256": patch.base_sha256,
                "new_sha256": patch.new_sha256,
            }
            for patch in self.patches
        ]


def module_specifiers(source: str) -> set[str]:
    """Extracts static module specifiers from JavaScript/TypeScript text.

    This is a bounded lexical scan, not a parser. It is used only to reject a candidate that
    introduces a dependency the snapshot does not prove, so over-matching is safe and
    under-matching is covered by the sandbox run.
    """
    found: set[str] = set()
    for pattern in (_REQUIRE_RE, _IMPORT_FROM_RE, _BARE_IMPORT_RE, _DYNAMIC_IMPORT_RE):
        found.update(match.group(1) for match in pattern.finditer(source))
    return found


def package_root(specifier: str) -> str | None:
    """Returns the installable package name, or None for a relative/absolute path import."""
    if not specifier or specifier.startswith((".", "/")):
        return None
    if specifier.startswith("node:"):
        return specifier
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else specifier
    return parts[0]


def _is_builtin(specifier: str) -> bool:
    name = specifier.removeprefix("node:")
    return name in NODE_BUILTIN_MODULES


def declared_dependencies(snapshot: Snapshot) -> set[str]:
    declared: set[str] = set()
    for path in snapshot.paths:
        if PurePosixPath(path).name != "package.json":
            continue
        try:
            manifest = json.loads(snapshot.full_content(path))
        except (TypeError, ValueError):
            continue
        if not isinstance(manifest, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            section = manifest.get(key)
            if isinstance(section, dict):
                declared.update(str(name) for name in section)
    return declared


def _reject_missing_dependencies(path: str, original: str, replacement: str, snapshot: Snapshot) -> None:
    introduced = {
        root
        for root in (package_root(item) for item in module_specifiers(replacement) - module_specifiers(original))
        if root
    }
    if not introduced:
        return
    allowed = declared_dependencies(snapshot)
    for name in sorted(introduced):
        if _is_builtin(name) or name.removeprefix("node:") in allowed or name in allowed:
            continue
        raise PatchPolicyError(f"missing_dependency:{name}")


def _syntax_check(path: str, replacement: str) -> str | None:
    """Runs `node --check` on a candidate JavaScript file. Returns a limitation, or None.

    A parse failure raises; an unavailable Node toolchain or an unsupported extension is
    recorded as an explicit limitation rather than treated as a passing check.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in SYNTAX_CHECKED_SUFFIXES:
        return f"syntax check skipped for {path}: only .js, .cjs, and .mjs are parsed by node --check"
    with tempfile.TemporaryDirectory(prefix="mitig8it-syntax-") as directory:
        target = Path(directory) / f"candidate{suffix}"
        target.write_text(replacement, encoding="utf-8")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, temporary file only.
                ["node", "--check", str(target)],
                cwd=directory,
                env={"PATH": __import__("os").environ.get("PATH", ""), "NO_COLOR": "1"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return f"syntax check unavailable for {path}: no usable node toolchain"
    if completed.returncode != 0:
        raise PatchPolicyError(f"candidate_syntax_invalid:{path}")
    return None


def _path_forbidden(path: str, request: RepairRequest) -> bool:
    lowered = path.lower()
    name = PurePosixPath(path).name.lower()
    if name in {item.lower() for item in request.policy.forbidden_filenames}:
        return True
    return any(lowered.startswith(prefix.lower().rstrip("/") + "/") for prefix in request.policy.forbidden_path_prefixes)


def build_patch_bundle(
    request: RepairRequest,
    snapshot: Snapshot,
    proposed_changes: list[dict[str, Any]],
) -> PatchBundle:
    if not proposed_changes:
        raise PatchPolicyError("proposal_contains_no_changes")
    if len(proposed_changes) > request.policy.max_files:
        raise PatchPolicyError("changed_file_limit_exceeded")

    seen: set[str] = set()
    patches: list[FilePatch] = []
    limitations: list[str] = []
    total_changed = 0
    for change in proposed_changes:
        if set(change) != {"path", "base_sha256", "replacement_content"}:
            raise PatchPolicyError("change_schema_invalid")
        try:
            path = validate_repo_path(str(change["path"]))
            original = snapshot.full_content(path)
        except SnapshotError as exc:
            raise PatchPolicyError(str(exc)) from exc
        if path in seen:
            raise PatchPolicyError("duplicate_patch_path")
        seen.add(path)
        if _path_forbidden(path, request):
            raise PatchPolicyError(f"protected_path:{path}")
        if PurePosixPath(path).suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            raise PatchPolicyError(f"unsupported_application_file:{path}")

        base_digest = content_sha256(original)
        if change["base_sha256"] != base_digest:
            raise PatchPolicyError(f"stale_file_digest:{path}")
        replacement = change["replacement_content"]
        if not isinstance(replacement, str):
            raise PatchPolicyError("replacement_content_must_be_string")
        if replacement == original:
            raise PatchPolicyError(f"unchanged_file:{path}")
        if len(replacement.encode("utf-8")) > request.policy.max_file_bytes:
            raise PatchPolicyError(f"replacement_file_too_large:{path}")

        diff_lines = list(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                replacement.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=3,
            )
        )
        changed = sum(
            1
            for line in diff_lines
            if (line.startswith("+") and not line.startswith("+++"))
            or (line.startswith("-") and not line.startswith("---"))
        )
        total_changed += changed
        if total_changed > request.policy.max_changed_lines:
            raise PatchPolicyError("changed_line_limit_exceeded")
        _reject_missing_dependencies(path, original, replacement, snapshot)
        limitation = _syntax_check(path, replacement)
        if limitation:
            limitations.append(limitation)
        patches.append(
            FilePatch(
                path=path,
                base_sha256=base_digest,
                replacement_content=replacement,
                contents_base64=base64.b64encode(replacement.encode("utf-8")).decode("ascii"),
                new_sha256=content_sha256(replacement),
                unified_diff="".join(diff_lines),
            )
        )

    patches.sort(key=lambda item: item.path)
    artifact = {
        "schema_version": "v1",
        "tenant_id": request.tenant_id,
        "repository_id": request.repository_id,
        "head_sha": request.head_sha,
        "base_sha": request.base_sha,
        "analysis_run_id": request.analysis_run_id,
        "context_manifest_digest": snapshot.manifest_digest,
        "versions": request.versions,
        "policy_version": request.policy.policy_version,
        "patches": [patch.model_dump(mode="json") for patch in patches],
    }
    return PatchBundle(tuple(patches), digest_json(artifact), total_changed, tuple(sorted(set(limitations))))


def candidate_tree_digest(snapshot: Snapshot, bundle: PatchBundle) -> str:
    replacements = {patch.path: patch.replacement_content for patch in bundle.patches}
    entries = [
        {
            "path": path,
            "content_digest": content_sha256(replacements.get(path, snapshot.full_content(path))),
            "bytes": len(replacements.get(path, snapshot.full_content(path)).encode("utf-8")),
        }
        for path in snapshot.paths
    ]
    return digest_json({"files": entries})


def _changed_ranges(original: list[str], replacement: list[str]) -> list[tuple[int, int, list[str]]]:
    matcher = difflib.SequenceMatcher(a=original, b=replacement, autojunk=False)
    return [
        (start_a, end_a, replacement[start_b:end_b])
        for tag, start_a, end_a, start_b, end_b in matcher.get_opcodes()
        if tag != "equal"
    ]


def _ranges_conflict(first: tuple[int, int, list[str]], second: tuple[int, int, list[str]]) -> bool:
    first_start, first_end, _ = first
    second_start, second_end, _ = second
    if first_start == first_end and second_start == second_end:
        return first_start == second_start
    return first_start < second_end and second_start < first_end


def combine_patch_bundles(request: RepairRequest, snapshot: Snapshot, bundles: list[PatchBundle]) -> PatchBundle:
    """Unions candidate patches into one tree, rejecting candidates that edit the same range.

    Whole-file replacements are reduced to their changed line ranges against the exact snapshot.
    Two candidates whose ranges intersect on one file cannot be combined mechanically, so the
    batch is rejected as `overlapping_candidates` instead of silently preferring one candidate.
    """
    if not bundles:
        raise PatchPolicyError("batch_contains_no_candidates")
    if len(bundles) == 1:
        return bundles[0]
    by_path: dict[str, list[FilePatch]] = {}
    for bundle in bundles:
        for patch in bundle.patches:
            by_path.setdefault(patch.path, []).append(patch)
    changes: list[dict[str, Any]] = []
    for path, patches in sorted(by_path.items()):
        original = snapshot.full_content(path)
        if len(patches) == 1:
            changes.append({"path": path, "base_sha256": patches[0].base_sha256, "replacement_content": patches[0].replacement_content})
            continue
        original_lines = original.splitlines(keepends=True)
        accepted: list[tuple[int, int, list[str]]] = []
        for patch in patches:
            for candidate_range in _changed_ranges(original_lines, patch.replacement_content.splitlines(keepends=True)):
                if any(_ranges_conflict(candidate_range, existing) for existing in accepted):
                    raise PatchPolicyError("overlapping_candidates")
                accepted.append(candidate_range)
        merged: list[str] = []
        cursor = 0
        for start, end, lines in sorted(accepted, key=lambda item: (item[0], item[1])):
            merged.extend(original_lines[cursor:start])
            merged.extend(lines)
            cursor = max(cursor, end)
        merged.extend(original_lines[cursor:])
        changes.append({"path": path, "base_sha256": content_sha256(original), "replacement_content": "".join(merged)})
    return build_patch_bundle(request, snapshot, changes)


def _bundle_ranges(snapshot: Snapshot, bundles: list[PatchBundle]) -> dict[str, list[tuple[int, int, list[str]]]]:
    ranges: dict[str, list[tuple[int, int, list[str]]]] = {}
    for bundle in bundles:
        for patch in bundle.patches:
            original_lines = snapshot.full_content(patch.path).splitlines(keepends=True)
            ranges.setdefault(patch.path, []).extend(
                _changed_ranges(original_lines, patch.replacement_content.splitlines(keepends=True))
            )
    return ranges


def bundles_conflict(snapshot: Snapshot, accepted: list[PatchBundle], candidate: PatchBundle) -> bool:
    """True when `candidate` changes a line range an already accepted bundle changes.

    This is the same range test `combine_patch_bundles` applies, used before the combination so
    the conflict can be attributed to the later finding group instead of failing the whole batch.
    """
    if not accepted:
        return False
    ranges = _bundle_ranges(snapshot, accepted)
    for patch in candidate.patches:
        existing = ranges.get(patch.path)
        if not existing:
            continue
        original_lines = snapshot.full_content(patch.path).splitlines(keepends=True)
        for candidate_range in _changed_ranges(original_lines, patch.replacement_content.splitlines(keepends=True)):
            if any(_ranges_conflict(candidate_range, other) for other in existing):
                return True
    return False
