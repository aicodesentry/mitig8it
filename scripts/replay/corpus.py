"""Pinned repository snapshots, cached on disk the way the GitHub responses are.

A pull request replay measures how the pipeline behaves on ordinary code. It cannot say
whether a rule finds a vulnerability, because merged pull requests of mature libraries
contain almost none. This module fetches whole repository trees at a pinned commit so the
same pipeline can be pointed at code that is known to be vulnerable.

Nothing here writes to GitHub, and no source tree is committed: the tarball for a
`(repo, ref)` pair is downloaded once into the cache and extracted there, and the cache is
ignored by git. Refetching is deleting the cache directory and running the harness again.
"""
from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any, Iterator

from prodfilters import CONTENT_BYTE_CAP, should_fetch_content

CODELOAD = "https://codeload.github.com/{repo}/tar.gz/{ref}"
DOWNLOAD_TIMEOUT_SECONDS = 600

# A snapshot is a whole repository, not a pull request, so the vendored and generated
# trees production never sees in a diff have to be excluded here instead. These are the
# directories a repository checks in but does not author.
VENDOR_DIRECTORY_NAMES = {
    ".git", "node_modules", "dist", "build", "vendor", "bower_components",
    "site-packages", "venv", ".venv", "__pycache__", ".tox", ".mypy_cache",
    "coverage", ".next", ".nuxt", "out", "target", "third_party", "thirdparty",
}


class SnapshotError(RuntimeError):
    pass


class SnapshotCache:
    """Repository trees at a pinned ref, extracted once under the cache directory."""

    def __init__(self, cache_dir: Path, refresh: bool = False):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.refresh = refresh
        self.downloads = 0
        self.cache_hits = 0

    def tree(self, repo: str, ref: str) -> Path:
        """The extracted root of `repo` at `ref`, downloading it if it is not cached."""
        if not _looks_like_ref(ref):
            raise SnapshotError(
                f"{repo}: {ref!r} is not a full 40-character commit sha; a snapshot must be "
                "pinned or the measurement cannot be repeated"
            )
        target = self.cache_dir / repo.replace("/", "__") / ref
        marker = target / ".snapshot-complete"
        if marker.exists() and not self.refresh:
            self.cache_hits += 1
            return _single_child(target)

        if target.exists():
            _remove_tree(target)
        target.mkdir(parents=True, exist_ok=True)
        self.downloads += 1
        blob = _download(CODELOAD.format(repo=repo, ref=ref))
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            _extract_safely(archive, target)
        marker.write_text(f"{repo}@{ref}\n", encoding="utf-8")
        return _single_child(target)


def _looks_like_ref(ref: str) -> bool:
    ref = str(ref or "")
    return len(ref) == 40 and all(char in "0123456789abcdef" for char in ref.lower())


def _download(url: str) -> bytes:
    result = subprocess.run(
        ["curl", "-sSL", "--fail", "--max-time", str(DOWNLOAD_TIMEOUT_SECONDS), url],
        capture_output=True,
        timeout=DOWNLOAD_TIMEOUT_SECONDS + 30,
    )
    if result.returncode != 0:
        raise SnapshotError(f"download failed for {url}: {result.stderr.decode('utf-8', 'replace')[:300]}")
    return result.stdout


def _extract_safely(archive: tarfile.TarFile, target: Path) -> None:
    """Extract, refusing any member that would land outside the target directory.

    A corpus is downloaded from the internet. An archive whose member path escapes the
    extraction root is the oldest trick there is, and this harness runs on a developer
    machine with the repository checked out next to it.
    """
    root = target.resolve()
    for member in archive.getmembers():
        if member.issym() or member.islnk():
            continue
        destination = (root / member.name).resolve()
        if destination != root and root not in destination.parents:
            raise SnapshotError(f"archive member escapes the extraction root: {member.name}")
        archive.extract(member, path=root)


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _single_child(target: Path) -> Path:
    children = [child for child in target.iterdir() if child.is_dir()]
    if len(children) != 1:
        raise SnapshotError(f"expected one extracted directory under {target}, found {len(children)}")
    return children[0]


def walk_analysable_files(root: Path) -> Iterator[Path]:
    """Every file in the tree the production content fetch would accept, vendored trees aside."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in VENDOR_DIRECTORY_NAMES and not name.startswith(".")
        )
        for name in sorted(filenames):
            candidate = Path(dirpath) / name
            relative = candidate.relative_to(root).as_posix()
            if should_fetch_content(relative):
                yield candidate


def read_snapshot_file(path: Path, relative: str) -> dict[str, Any]:
    """One file as the payload carries it, with the production 500 kB drop applied.

    The patch is the whole file as an addition, which is exactly what production sends
    tier 1 for a newly added file, and `reviewable_line_spans` covers every line, which is
    what it sends tier 2. A snapshot has no diff, so the only faithful reading of "what
    would be reviewed here" is the whole file.
    """
    raw = path.read_bytes()
    if len(raw) > CONTENT_BYTE_CAP:
        return {"skipped": "content_over_500kb"}
    try:
        content = raw.decode("utf-8")
        non_utf8 = False
    except UnicodeDecodeError:
        # Node's Buffer.toString('utf8') replaces invalid bytes rather than failing, so
        # production really does hand this text to the analysis service.
        content = raw.decode("utf-8", errors="replace")
        non_utf8 = True

    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    count = len(lines)
    if count == 0:
        return {"skipped": "empty_file"}
    patch = f"@@ -0,0 +1,{count} @@\n" + "".join(f"+{line}\n" for line in lines)
    return {
        "path": relative,
        "patch": patch,
        "content": content,
        "additions": count,
        "deletions": 0,
        "status": "added",
        "reviewable_line_spans": [{"start": 1, "end": count}],
        "non_utf8": non_utf8,
    }
