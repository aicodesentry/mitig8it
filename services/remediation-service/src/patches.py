from __future__ import annotations

import ast
import builtins
import difflib
import base64
import json
import re
import subprocess
import sys
import tempfile
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .digests import content_sha256, digest_json, git_blob_sha1
from .models import FilePatch, RepairRequest
from .retrieval import Snapshot, SnapshotError
from .retrieval.snapshot import validate_repo_path
from .families import PYTHON, language_of_path
from .sandbox.harness import HARNESS_PATH, PYTHON_HARNESS_MODULES, PYTHON_HARNESS_PATH, is_harness_path


class PatchPolicyError(ValueError):
    """A rejected proposal, carrying a stable code and optional actionable guidance.

    `code` is a short machine-readable identifier safe to record in the agent trace. `guidance`
    is the specific, human-readable correction returned to the model in the tool result: it may
    quote snapshot lines the agent is already authorized to read, so it is never traced.
    """

    def __init__(self, code: str, guidance: str | None = None):
        super().__init__(code)
        self.code = code
        self.guidance = guidance


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

NODE_SYNTAX_SUFFIXES = {".js", ".cjs", ".mjs"}
PYTHON_SYNTAX_SUFFIXES = {".py"}
SYNTAX_CHECKED_SUFFIXES = NODE_SYNTAX_SUFFIXES | PYTHON_SYNTAX_SUFFIXES
APPLICATION_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}

# Agent-generated regression tests live in a dedicated directory that no repository file may
# occupy, so a generated reproducer can never overwrite or shadow application or test code.
GENERATED_TEST_DIRECTORY = ".mitig8it/regression"
GENERATED_TEST_SUFFIXES = (".test.js", ".test.cjs", ".test.mjs", ".test.py")
PYTHON_GENERATED_TEST_SUFFIX = ".test.py"
MAX_GENERATED_TEST_BYTES = 64_000
MAX_GENERATED_TESTS = 20
# A finding runs its service-generated proof and, at most, one model-written test beside it.
MAX_TESTS_PER_FINDING = 2

_REQUIRE_RE = re.compile(r"""\brequire\s*\(\s*['"]([^'"\n]{1,200})['"]\s*\)""")
_IMPORT_FROM_RE = re.compile(r"""\b(?:import|export)\b[^;\n]*?\bfrom\s*['"]([^'"\n]{1,200})['"]""")
_BARE_IMPORT_RE = re.compile(r"""\bimport\s*['"]([^'"\n]{1,200})['"]""")
_DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*['"]([^'"\n]{1,200})['"]\s*\)""")
_PYTHON_IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import\b|import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*))", re.MULTILINE)
_PYTHON_RELATIVE_IMPORT_RE = re.compile(r"^[ \t]*from[ \t]+\.", re.MULTILINE)
# Introduced reads of the process environment, so a candidate that moves a secret out of the
# source names the variable a deployment has to provide.
_PYTHON_ENV_READ_RE = re.compile(r"""\bos\.(?:environ\s*\[\s*|environ\.get\s*\(\s*|getenv\s*\(\s*)['"]([A-Za-z_][A-Za-z0-9_]{0,120})['"]""")
PYTHON_STDLIB_MODULES = frozenset(getattr(sys, "stdlib_module_names", ()))


@dataclass(frozen=True)
class GeneratedTest:
    """One agent-authored regression test: repository-adjacent, never applied to the tree.

    Its content is untrusted model output treated exactly like repository text. It is
    materialized into the baseline and candidate workspaces and executed only by the sandbox
    driver, alongside every other verification check. Each test names the one finding it
    reproduces: a candidate claims exactly the findings whose test fails on the baseline tree
    and passes on the candidate tree.
    """

    path: str
    content: str
    new_sha256: str
    finding_id: str

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "finding_id": self.finding_id,
            "new_sha256": self.new_sha256,
            "bytes": len(self.content.encode("utf-8")),
            "kind": "generated_regression_test",
        }

    def spec(self) -> dict[str, str]:
        return {"finding_id": self.finding_id, "path": self.path, "content": self.content}


@dataclass(frozen=True)
class LocatedHunk:
    """One line-range replacement located in the exact snapshot.

    `finding_id` is the finding the proposer says the hunk fixes, or None when the caller did not
    tag it; the engine attributes an untagged hunk by proximity to the group's finding ranges.
    Lines are stored without line endings, so two hunks that make the same change at the same
    place compare equal whatever the caller's line-ending convention.
    """

    path: str
    start_line: int
    end_line: int
    original_lines: tuple[str, ...]
    replacement_lines: tuple[str, ...]
    finding_id: str | None = None

    @property
    def key(self) -> tuple[str, int, int, tuple[str, ...]]:
        """Content and location: two hunks with the same key are the same change."""
        return (self.path, self.start_line, self.end_line, self.replacement_lines)

    def overlaps(self, other: "LocatedHunk") -> bool:
        return self.path == other.path and self.start_line <= other.end_line and other.start_line <= self.end_line

    def spec(self) -> dict[str, Any]:
        """The hunk as a `propose_patch` change, so a subset of hunks can be rebuilt into a bundle."""
        change: dict[str, Any] = {
            "path": self.path,
            "start_line": self.start_line,
            "original_lines": list(self.original_lines),
            "replacement_lines": list(self.replacement_lines),
        }
        if self.finding_id is not None:
            change["finding_id"] = self.finding_id
        return change

    def manifest_entry(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line, "finding_id": self.finding_id}


@dataclass(frozen=True)
class PatchBundle:
    patches: tuple[FilePatch, ...]
    artifact_digest: str
    changed_lines: int
    limitations: tuple[str, ...] = ()
    generated_tests: tuple[GeneratedTest, ...] = ()
    # The located hunks the bundle was built from, in proposal order. A bundle built from whole
    # file contents (a combined batch of untracked bundles) carries none.
    hunks: tuple[LocatedHunk, ...] = ()

    @property
    def hunk_manifest(self) -> list[dict[str, Any]]:
        return [hunk.manifest_entry() for hunk in self.hunks]

    @property
    def file_manifest(self) -> list[dict[str, Any]]:
        """The final content of every changed application file, not just its digests.

        The control plane never reconstructs file content from hunks, so a candidate has to
        carry the whole post-patch file: `contents_base64` is what the GitHub adapter commits,
        `blob_oid` is the exact Git blob the verified tree was computed over, and `new_sha256`
        binds the two. Without these an applicable candidate is unusable and the apply blocks
        with `verified_full_file_manifest_unavailable`.
        """
        return [
            {
                "path": patch.path,
                "base_sha256": patch.base_sha256,
                "new_sha256": patch.new_sha256,
                "contents_base64": patch.contents_base64,
                "blob_oid": git_blob_sha1(patch.replacement_content.encode("utf-8")),
                "bytes": len(patch.replacement_content.encode("utf-8")),
                "kind": "application",
            }
            for patch in self.patches
        ]

    @property
    def generated_test_manifest(self) -> list[dict[str, Any]]:
        """Tracked separately from `file_manifest`: these files are evidence, not the repair."""
        return [test.manifest_entry() for test in self.generated_tests]


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


def python_module_specifiers(source: str) -> set[str]:
    """Extracts the dotted module names a Python file imports; relative imports are left out."""
    found: set[str] = set()
    for match in _PYTHON_IMPORT_RE.finditer(source):
        if match.group(1):
            found.add(match.group(1))
        else:
            found.update(part.strip() for part in match.group(2).split(",") if part.strip())
    return found


def python_top_level(specifier: str) -> str:
    return specifier.split(".", 1)[0]


def python_declared_dependencies(snapshot: Snapshot) -> set[str]:
    """Distribution names a requirements file or pyproject declares, lower-cased with `-` as `_`."""
    declared: set[str] = set()
    for path in snapshot.paths:
        name = PurePosixPath(path).name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            for line in snapshot.full_content(path).splitlines():
                line = line.split("#", 1)[0].strip()
                match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if match:
                    declared.add(match.group(1).lower().replace("-", "_"))
        elif name in {"pyproject.toml", "setup.cfg", "setup.py", "pipfile"}:
            for match in re.finditer(r"""['"]([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[ ]|['"])""", snapshot.full_content(path)):
                declared.add(match.group(1).lower().replace("-", "_"))
    return declared


def python_local_modules(snapshot: Snapshot) -> set[str]:
    """Top-level names the snapshot itself provides: a sibling `x.py` or package directory `x/`."""
    names: set[str] = set()
    for path in snapshot.paths:
        parts = PurePosixPath(path).parts
        if parts[-1].endswith(".py"):
            names.add(parts[-1][:-3])
            names.update(parts[:-1])
    return names


def _reject_missing_python_dependencies(
    path: str,
    original: str,
    replacement: str,
    snapshot: Snapshot,
    *,
    allow_declared: bool = True,
    allow_harness_modules: bool = False,
) -> None:
    introduced = {python_top_level(item) for item in python_module_specifiers(replacement) - python_module_specifiers(original)}
    if not introduced:
        return
    local = python_local_modules(snapshot)
    allowed = python_declared_dependencies(snapshot) if allow_declared else set()
    harness_modules = PYTHON_HARNESS_MODULES if allow_harness_modules else frozenset()
    for name in sorted(introduced):
        if name in PYTHON_STDLIB_MODULES or name in local or name == "harness" or name.lower() in allowed:
            continue
        if name in harness_modules:
            continue
        raise PatchPolicyError(
            f"missing_dependency:{name}",
            f"{name!r} is not in the Python standard library, no module of that name is in the snapshot, "
            f"and no requirements file or pyproject in the snapshot declares it. Nothing is installed in "
            f"the sandbox, so a regression test must import only the standard library, repository modules, "
            f"the drivers the harness fakes ({', '.join(sorted(PYTHON_HARNESS_MODULES))}), "
            f"and the service harness at {PYTHON_HARNESS_PATH} (import harness as h). "
            + PYTHON_BEHAVIOR_TEST_GUIDANCE,
        )


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


# A `node --check` diagnostic handed back to the agent: enough for the line, message, and
# caret, never an unbounded subprocess stream.
MAX_SYNTAX_DIAGNOSTIC_CHARS = 600


def _reject_missing_dependencies(
    path: str,
    original: str,
    replacement: str,
    snapshot: Snapshot,
    *,
    allow_declared: bool = True,
    allow_harness_modules: bool = False,
) -> None:
    """Rejects a specifier the sandbox cannot resolve.

    An application file may import what package.json declares: the repository installs it. A
    generated regression test may not, because the sandbox installs nothing, so for tests only
    Node built-ins, relative paths, and the service harness resolve.

    `allow_harness_modules` is the one widening, and it is for generated Python tests only: the
    Python harness installs fakes for a fixed set of drivers before it loads the module under
    test, so a test that imports one of them gets the harness's recorded fake rather than a
    missing module. An application patch never gets this, because a driver the harness fakes in
    the sandbox is still a real dependency the deployment has to install.
    """
    if language_of_path(path) == PYTHON:
        _reject_missing_python_dependencies(
            path,
            original,
            replacement,
            snapshot,
            allow_declared=allow_declared,
            allow_harness_modules=allow_harness_modules,
        )
        return
    introduced = {
        root
        for root in (package_root(item) for item in module_specifiers(replacement) - module_specifiers(original))
        if root
    }
    if not introduced:
        return
    allowed = declared_dependencies(snapshot) if allow_declared else set()
    for name in sorted(introduced):
        if _is_builtin(name) or name.removeprefix("node:") in allowed or name in allowed:
            continue
        raise PatchPolicyError(
            f"missing_dependency:{name}",
            f"{name!r} is not a Node built-in and no package.json in the snapshot declares it. "
            f"The snapshot declares: {', '.join(sorted(allowed)) or 'nothing'}. Nothing is installed in "
            "the sandbox, so a regression test must require only Node built-ins, relative repository "
            f"paths, and the service harness at {HARNESS_PATH} (require('../harness') from the test "
            "directory); never supertest, express, pg, jest, or any other package. "
            + BEHAVIOR_TEST_GUIDANCE,
        )


def _syntax_check(path: str, replacement: str) -> str | None:
    """Runs `node --check` on a candidate JavaScript file. Returns a limitation, or None.

    A parse failure raises; an unavailable Node toolchain or an unsupported extension is
    recorded as an explicit limitation rather than treated as a passing check.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in PYTHON_SYNTAX_SUFFIXES:
        return _python_syntax_check(path, replacement)
    if suffix not in NODE_SYNTAX_SUFFIXES:
        return f"syntax check skipped for {path}: only .js, .cjs, .mjs, and .py are parsed"
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
            # Node already says which line of the candidate fails and why. Handing that back
            # names the mistake the agent can actually correct; "check your brackets" does not.
            # The diagnostic quotes the agent's own candidate, so it never leaves the tool result.
            diagnostic = (completed.stderr or completed.stdout or "").replace(directory, "").replace(
                f"/candidate{suffix}", f" {path}"
            )
            raise PatchPolicyError(
                f"candidate_syntax_invalid:{path}",
                f"The patched {path} does not parse under `node --check`. Node reports:\n"
                f"{diagnostic.strip()[:MAX_SYNTAX_DIAGNOSTIC_CHARS]}\n"
                "The line number is in the patched file. Re-read that range and send hunks whose "
                "replacement_lines leave the file balanced.",
            )
    return None


def _python_syntax_check(path: str, replacement: str) -> str | None:
    """Runs `python -m py_compile` on a candidate Python file. Returns a limitation, or None."""
    with tempfile.TemporaryDirectory(prefix="mitig8it-syntax-") as directory:
        target = Path(directory) / "candidate.py"
        target.write_text(replacement, encoding="utf-8")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, temporary file only.
                [sys.executable, "-m", "py_compile", str(target)],
                cwd=directory,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return f"syntax check unavailable for {path}: no usable python toolchain"
        if completed.returncode != 0:
            diagnostic = (completed.stderr or completed.stdout or "").replace(directory, "").replace("/candidate.py", f" {path}")
            raise PatchPolicyError(
                f"candidate_syntax_invalid:{path}",
                f"The patched {path} does not compile under `python -m py_compile`. Python reports:\n"
                f"{diagnostic.strip()[:MAX_SYNTAX_DIAGNOSTIC_CHARS]}\n"
                "The line number is in the patched file. Re-read that range and send hunks whose "
                "replacement_lines keep the indentation consistent.",
            )
    return None


# Names every Python module can load without binding them itself.
_PYTHON_IMPLICIT_NAMES = frozenset(
    {
        "__file__", "__name__", "__doc__", "__builtins__", "__spec__", "__loader__", "__package__",
        "__path__", "__debug__", "__annotations__", "__dict__", "__module__", "__qualname__",
        "__class__", "__cached__",
    }
)
_PYTHON_DYNAMIC_SCOPE_RE = re.compile(r"\b(?:exec|globals|locals|vars)\s*\(")
MAX_UNDEFINED_NAMES_REPORTED = 5


def python_free_names(source: str) -> set[str] | None:
    """Names loaded anywhere in `source` that nothing in the file binds.

    Flow-insensitive on purpose: a name assigned anywhere, bound as a parameter, imported,
    defined, or declared global counts as bound everywhere, so the check can only miss a
    real error, never invent one from ordering. Returns None when the file cannot be parsed
    or binds names the parser cannot see (a star import or a dynamic-scope call), in which
    case the check abstains.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    if _PYTHON_DYNAMIC_SCOPE_RE.search(source):
        return None
    bound: set[str] = set(dir(builtins)) | set(_PYTHON_IMPLICIT_NAMES)
    loaded: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            return None
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update((alias.asname or alias.name).split(".", 1)[0] for alias in node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                loaded.add(node.id)
            else:
                bound.add(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    return loaded - bound


# JavaScript and TypeScript names every module can use without binding them.
JS_GLOBAL_NAMES = frozenset(
    """
    require module exports process console Buffer global globalThis __dirname __filename
    setTimeout clearTimeout setInterval clearInterval setImmediate clearImmediate queueMicrotask
    structuredClone fetch URL URLSearchParams TextEncoder TextDecoder AbortController AbortSignal
    Headers Request Response FormData Blob File WebSocket EventTarget Event CustomEvent
    performance crypto atob btoa navigator window document self location localStorage
    sessionStorage alert requestAnimationFrame cancelAnimationFrame XMLHttpRequest HTMLElement
    Object Array String Number Boolean Symbol BigInt Function Math JSON Date RegExp Promise
    Error TypeError RangeError SyntaxError ReferenceError EvalError URIError AggregateError
    Map Set WeakMap WeakSet WeakRef FinalizationRegistry Proxy Reflect Intl Atomics
    ArrayBuffer SharedArrayBuffer DataView Int8Array Uint8Array Uint8ClampedArray Int16Array
    Uint16Array Int32Array Uint32Array Float32Array Float64Array BigInt64Array BigUint64Array
    ReadableStream WritableStream TransformStream Iterator Generator
    parseInt parseFloat isNaN isFinite encodeURIComponent decodeURIComponent encodeURI decodeURI
    escape unescape eval undefined NaN Infinity arguments this super new typeof instanceof
    void delete in of if else for while do switch case default break continue return throw try
    catch finally function class extends const let var import export from as async await yield
    with debugger static get set enum interface type namespace declare implements private
    protected public readonly abstract keyof satisfies unknown any never object string number
    boolean symbol bigint null true false
    describe it test expect beforeEach afterEach beforeAll afterAll jest vi
    """.split()
)
_JS_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_JS_STRING_RE = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`", re.S)
# An identifier used as a call target or a member root, not preceded by `.` (member access),
# `$`, or a word character.
_JS_USE_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?=[.(])")


def _js_strip(source: str) -> str:
    return _JS_STRING_RE.sub('""', _JS_COMMENT_RE.sub(" ", source))


def _js_binds(source: str, name: str) -> bool:
    """True when the stripped file plausibly binds `name` anywhere, by any declaration form."""
    ident = re.escape(name)
    patterns = (
        rf"\b(?:const|let|var|function|class|enum|interface|type|namespace|declare)\s+(?:async\s+)?(?:function\s+)?{ident}\b",
        rf"\b(?:const|let|var)\s*\{{[^}}]*\b{ident}\b[^}}]*\}}",
        rf"\b(?:const|let|var)\s*\[[^\]]*\b{ident}\b[^\]]*\]",
        rf"\bimport\b[^;\n]*\b{ident}\b[^;\n]*\bfrom\b",
        rf"\bimport\s+(?:\*\s+as\s+)?{ident}\b",
        rf"\bfunction\b[^(]*\(([^)]*\b{ident}\b[^)]*)\)",
        rf"\(([^()]*\b{ident}\b[^()]*)\)\s*(?::[^=]*)?=>",
        rf"(?<![\w$.]){ident}\s*=>",
        rf"\bcatch\s*\(\s*{ident}\b",
        rf"(?m)^\s*(?:static\s+|async\s+|get\s+|set\s+|public\s+|private\s+|protected\s+)*{ident}\s*\([^)]*\)\s*(?::[^{{]*)?\{{",
        rf"(?<![\w$.]){ident}\s*=[^=>]",
    )
    return any(re.search(pattern, source) for pattern in patterns)


def javascript_free_names(original: str, replacement: str) -> set[str]:
    """Identifiers the change introduces that are used as calls or member roots and bound nowhere.

    A bounded lexical check, not a parser: only identifiers absent from the original file and
    used as `name(` or `name.` in the candidate are considered, and any declaration form that
    could bind the name anywhere in the candidate file clears it. It catches `execFile(...)`
    added without a require or import; anything less clear-cut is left to the load check.
    """
    stripped_original = _js_strip(original)
    stripped_replacement = _js_strip(replacement)
    candidates = {
        match.group(1)
        for match in _JS_USE_RE.finditer(stripped_replacement)
        if match.group(1) not in JS_GLOBAL_NAMES and not re.search(rf"(?<![\w$]){re.escape(match.group(1))}(?![\w$])", stripped_original)
    }
    return {name for name in candidates if not _js_binds(stripped_replacement, name)}


def _reject_undefined_names(path: str, original: str, replacement: str) -> None:
    """Rejects a candidate that loads a name nothing in the file binds.

    `py_compile` and `node --check` prove a file parses; a name used without its import is a
    NameError or ReferenceError at call time, which no parse catches and a load check only
    catches at module top level. Only names the change introduces are held against it: a name
    the original file already used unbound is not the candidate's mistake.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in PYTHON_SYNTAX_SUFFIXES:
        after = python_free_names(replacement)
        before = python_free_names(original)
        if after is None:
            return
        undefined = sorted(after - (before or set()))
        runtime = "NameError"
    elif suffix in APPLICATION_SUFFIXES:
        undefined = sorted(javascript_free_names(original, replacement))
        runtime = "ReferenceError"
    else:
        return
    if not undefined:
        return
    names = ", ".join(undefined[:MAX_UNDEFINED_NAMES_REPORTED])
    raise PatchPolicyError(
        f"undefined_name:{undefined[0]}",
        f"The patched {path} uses {names} without importing or defining it, which raises {runtime} "
        "when that line runs. Add the import or definition in another hunk of the same "
        "propose_patch call (for Python eval fixes, `import ast` for ast.literal_eval).",
    )


def _reject_service_path(path: str) -> None:
    """Rejects a proposal that targets the service-owned `.mitig8it/` tree.

    The harness and the generated tests are evidence the service materializes into the sandbox;
    a proposal that writes there could replace the harness the verifier trusts to record calls.
    """
    normalized = path.strip().strip("/")
    if is_harness_path(normalized):
        raise PatchPolicyError(
            f"harness_path_protected:{normalized}",
            f"{normalized} is the service test harness and is materialized by the sandbox; a "
            "proposal may not write it. Change only application files and load the harness "
            "from a regression test with require('../harness') or import harness as h.",
        )
    if normalized == ".mitig8it" or normalized.startswith(".mitig8it/"):
        raise PatchPolicyError(
            f"protected_path:{normalized}",
            "The .mitig8it directory is owned by the service. Regression tests go in "
            f"{GENERATED_TEST_DIRECTORY}/ through propose_patch.regression_tests, not through changes.",
        )


def _path_forbidden(path: str, request: RepairRequest) -> bool:
    lowered = path.lower()
    name = PurePosixPath(path).name.lower()
    if name in {item.lower() for item in request.policy.forbidden_filenames}:
        return True
    return any(lowered.startswith(prefix.lower().rstrip("/") + "/") for prefix in request.policy.forbidden_path_prefixes)


# A regression test proves behavior only by loading the changed module and invoking it. One that
# reads the changed file as text passes or fails on wording alone, so it is rejected.
_FS_READ_RE = re.compile(r"\b(?:readFileSync|readFile)\s*\(")
_DIRNAME_REQUIRE_RE = re.compile(r"\brequire\s*\([^)]*__dirname")
_HARNESS_LOAD_RE = re.compile(r"\.load\s*\(\s*['\"]")
BEHAVIOR_TEST_GUIDANCE = (
    "Plain Node only: no jest, mocha, or supertest. Use the service harness: const h = "
    "require('../harness'); const app = h.load('<repository path of the changed file>'); it fakes "
    "express, pg, child_process, and fs and records every call. Then await h.invoke(app, 'get', "
    "'/route/:id', { params, query, body }) or call the exported function with an injection "
    "payload, and assert on h.pg.queries (text must not contain the payload, values must), "
    "h.child_process.calls (fn is execFile or spawn, args carries the payload, options.shell is "
    "unset), or h.fs.reads (a traversal payload records no read at all and every other read stays under the base directory). Wrap the body in "
    "h.run(async () => { ... }); it exits non-zero on the first failed h.assert."
)


PYTHON_BEHAVIOR_TEST_GUIDANCE = (
    "Plain python3 only: no pytest, flask test client, or requests. Use the service harness: "
    "import harness as h; m = h.load('<repository path of the changed file>', env={...}); it fakes "
    "flask, sqlite3, psycopg, sqlalchemy, subprocess, os.system, os.environ, and open() and records "
    "every call. Then h.invoke(m.app, 'GET', '/route/<id>', params=..., query=..., json=...) or "
    "h.call(m.function, payload), and assert with h.assert_param(h.db.queries[0], payload), "
    "h.assert_argv(h.subprocess.calls[0], payload), h.assert_inside(h.fs.reads, base, payload=payload), "
    "h.assert_equal(m.NAME, value) with h.assert_env_read('NAME') and h.assert_not_in_source(m, literal), "
    "or h.assert_no_commands(). Wrap the body in h.run(body); it exits non-zero on the first failed assertion."
)
_PYTHON_OPEN_RE = re.compile(r"\bopen\s*\(|\bread_text\s*\(|\bread_bytes\s*\(")
_PYTHON_HARNESS_LOAD_RE = re.compile(r"""\b(?:h|harness)\.load\s*\(\s*['"]""")


def _python_requires_repository_module(content: str, snapshot: Snapshot) -> bool:
    """True when the test loads a repository module through the harness or imports one."""
    if _PYTHON_HARNESS_LOAD_RE.search(content) or _PYTHON_RELATIVE_IMPORT_RE.search(content):
        return True
    local = python_local_modules(snapshot)
    return any(python_top_level(item) in local for item in python_module_specifiers(content))


def _requires_repository_module(content: str) -> bool:
    """True when the test loads a repository module, by relative specifier or via __dirname.

    The service harness is a relative specifier too, but loading it alone proves nothing about
    the repository, so it does not count; its `load(<repository path>)` call does.
    """
    if any(
        specifier.startswith(".") and PurePosixPath(specifier).stem != "harness"
        for specifier in module_specifiers(content)
    ):
        return True
    return bool(_DIRNAME_REQUIRE_RE.search(content) or _HARNESS_LOAD_RE.search(content))


def build_generated_tests(
    request: RepairRequest,
    snapshot: Snapshot,
    specs: list[dict[str, Any]] | None,
) -> tuple[list[GeneratedTest], list[str]]:
    """Validates agent-authored regression tests under the same policy as any other file.

    A test is accepted only when it names one of the task's findings, is a new
    `.mitig8it/regression/*.test.{js,cjs,mjs}` file that no repository path occupies, parses
    under `node --check`, imports nothing beyond Node built-ins, the repository's declared
    dependencies, and relative repository paths, and exercises behavior rather than reading the
    changed file as text.
    """
    if not specs:
        return [], []
    if len(specs) > MAX_GENERATED_TESTS:
        raise PatchPolicyError("generated_test_limit_exceeded")
    tests: list[GeneratedTest] = []
    limitations: list[str] = []
    seen: set[str] = set()
    claimed: list[str] = []
    known = sorted(finding.stable_id for finding in request.findings)
    for spec in specs:
        if not isinstance(spec, dict) or set(spec) != {"finding_id", "path", "content"}:
            raise PatchPolicyError(
                "regression_test_schema_invalid",
                "regression_tests is a list of {finding_id, path, content}, one entry per finding "
                "this patch repairs.",
            )
        finding_id = spec["finding_id"]
        if not isinstance(finding_id, str) or finding_id not in known:
            raise PatchPolicyError(
                "regression_test_finding_unknown",
                f"finding_id must be one of the task's finding ids: {', '.join(known)}.",
            )
        if claimed.count(finding_id) >= MAX_TESTS_PER_FINDING:
            raise PatchPolicyError(
                "duplicate_regression_test_finding",
                f"Send at most one regression test per finding beside the service-generated proof; {finding_id} has more.",
            )
        claimed.append(finding_id)
        if is_harness_path(str(spec["path"]).strip().strip("/")):
            raise PatchPolicyError(
                f"harness_path_protected:{str(spec['path']).strip().strip('/')}",
                "The service test harness may be loaded by a regression test but never replaced. "
                f"Name the test {GENERATED_TEST_DIRECTORY}/<finding-id>.test.js or .test.py.",
            )
        try:
            path = validate_repo_path(str(spec["path"]))
        except SnapshotError as exc:
            raise PatchPolicyError(f"regression_test_path_invalid:{exc}") from exc
        pure = PurePosixPath(path)
        if pure.parent.as_posix() != GENERATED_TEST_DIRECTORY:
            raise PatchPolicyError(
                f"regression_test_outside_generated_directory:{path}",
                f"The regression test path must be {GENERATED_TEST_DIRECTORY}/<name>.test.js or .test.py.",
            )
        if not pure.name.endswith(GENERATED_TEST_SUFFIXES) or pure.name.startswith("."):
            raise PatchPolicyError(
                f"regression_test_name_invalid:{path}",
                "The regression test file name must end in .test.js, .test.cjs, .test.mjs, or .test.py.",
            )
        if path in snapshot.paths:
            raise PatchPolicyError(f"regression_test_overwrites_repository_file:{path}")
        if _path_forbidden(path, request):
            raise PatchPolicyError(f"protected_path:{path}")
        if path in seen:
            raise PatchPolicyError("duplicate_regression_test_path")
        seen.add(path)
        content = spec["content"]
        if not isinstance(content, str) or not content.strip():
            raise PatchPolicyError("regression_test_content_required")
        if len(content.encode("utf-8")) > MAX_GENERATED_TEST_BYTES:
            raise PatchPolicyError(f"regression_test_too_large:{path}")
        if pure.name.endswith(PYTHON_GENERATED_TEST_SUFFIX):
            if _PYTHON_OPEN_RE.search(content) and not _python_requires_repository_module(content, snapshot):
                raise PatchPolicyError(
                    f"regression_test_reads_source_as_text:{path}",
                    "The test reads a file as text and never loads a repository module, so it proves "
                    "nothing about behavior. " + PYTHON_BEHAVIOR_TEST_GUIDANCE,
                )
        elif _FS_READ_RE.search(content) and not _requires_repository_module(content):
            raise PatchPolicyError(
                f"regression_test_reads_source_as_text:{path}",
                "The test reads a file as text and never requires a repository module, so it proves "
                "nothing about behavior. " + BEHAVIOR_TEST_GUIDANCE,
            )
        _reject_missing_dependencies(path, "", content, snapshot, allow_declared=False, allow_harness_modules=True)
        limitation = _syntax_check(path, content)
        if limitation:
            limitations.append(limitation)
        tests.append(GeneratedTest(path, content, content_sha256(content), finding_id))
    tests.sort(key=lambda item: item.path)
    return tests, limitations


# Runtime load of each changed module. `node --check` proves the file parses; only loading it
# proves its top level runs, which is where an identifier used without an import fails.
LOAD_CHECK_TIMEOUT_SECONDS = 10
MAX_LOAD_DIAGNOSTIC_CHARS = 600
MAX_LOAD_LIMITATION_CHARS = 240
LOAD_REPORT_KEY = "mitig8it_load"
# The loader prints one classification line so a missing dependency is a limitation and a
# thrown error is a rejection. It exits as soon as the module has loaded, so a module that
# starts a server at its top level does not keep the check alive.
_LOAD_SCRIPT = """
const target = process.argv[1];
const { pathToFileURL } = require('node:url');
const report = (value) => process.stdout.write('\\n' + JSON.stringify(value) + '\\n');
const unavailable = new Set(['MODULE_NOT_FOUND', 'ERR_MODULE_NOT_FOUND', 'ERR_REQUIRE_ESM',
  'ERR_REQUIRE_ASYNC_MODULE', 'ERR_UNKNOWN_FILE_EXTENSION']);
const load = target.endsWith('.mjs')
  ? () => import(pathToFileURL(target).href)
  : () => Promise.resolve().then(() => require(target));
load().then(() => { report({ mitig8it_load: 'ok' }); process.exit(0); }, (error) => {
  const code = error && error.code;
  const message = String((error && error.message) || error).slice(0, 400);
  if (unavailable.has(code)) { report({ mitig8it_load: 'unavailable', code, message }); process.exit(0); }
  report({ mitig8it_load: 'error', name: String((error && error.name) || 'Error'), message });
  process.exit(1);
});
"""


# The Python loader runs the module the way `import` would (`__name__` is not `__main__`, so a
# `if __name__ == "__main__":` server start does not fire). A missing third-party import is a
# limitation, an environment variable the module reads at import time and the check did not
# set is a limitation naming the variable, and any other exception is a rejection.
_PYTHON_LOAD_SCRIPT = """
import json, os, runpy, sys, traceback
target = sys.argv[1]
report = lambda value: sys.stdout.write("\\n" + json.dumps(value) + "\\n")
sys.path.insert(0, os.path.dirname(os.path.abspath(target)))
try:
    runpy.run_path(target, run_name="mitig8it_load_check")
except ImportError as error:
    report({"mitig8it_load": "unavailable", "code": type(error).__name__, "message": str(error)[:400]})
    sys.exit(0)
except KeyError as error:
    frames = traceback.extract_tb(sys.exc_info()[2])
    last = frames[-1] if frames else None
    if last is not None and last.name == "__getitem__" and (last.filename.endswith("os.py") or last.filename == "<frozen os>"):
        report({"mitig8it_load": "unavailable", "code": "environment_variable_missing", "message": "environment variable %r is not set" % (error.args[0] if error.args else "")})
        sys.exit(0)
    report({"mitig8it_load": "error", "name": "KeyError", "message": str(error)[:400]})
    sys.exit(1)
except SystemExit as error:
    if not error.code:
        report({"mitig8it_load": "ok"})
        sys.exit(0)
    report({"mitig8it_load": "error", "name": "SystemExit", "message": "the module exited with %r at import time" % (error.code,)})
    sys.exit(1)
except BaseException as error:
    report({"mitig8it_load": "error", "name": type(error).__name__, "message": str(error)[:400]})
    sys.exit(1)
report({"mitig8it_load": "ok"})
sys.exit(0)
"""


def _materialize_snapshot(root: Path, snapshot: Snapshot, replacements: dict[str, str]) -> None:
    for path in snapshot.paths:
        target = root.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(replacements.get(path, snapshot.full_content(path)), encoding="utf-8")


def _load_report(output: str) -> dict[str, Any] | None:
    found = None
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{") or LOAD_REPORT_KEY not in line:
            continue
        try:
            document = json.loads(line)
        except ValueError:
            continue
        if isinstance(document, dict) and isinstance(document.get(LOAD_REPORT_KEY), str):
            found = document
    return found


def _load_module(root: Path, path: str) -> dict[str, Any]:
    """Loads one file from a materialized tree. Returns `{state: ok|unavailable|error|timeout}`."""
    target = root.joinpath(*PurePosixPath(path).parts)
    python = language_of_path(path) == PYTHON
    argv = [sys.executable, "-c", _PYTHON_LOAD_SCRIPT, str(target)] if python else ["node", "-e", _LOAD_SCRIPT, str(target)]
    # A Python module that reads a literal environment name at import time gets a placeholder,
    # so the check reaches the imports and identifiers after it instead of stopping at KeyError.
    placeholders = (
        {name: "mitig8it-load-check" for name in _PYTHON_ENV_READ_RE.findall(target.read_text(encoding="utf-8", errors="replace"))}
        if python
        else {}
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, temporary tree only.
            argv,
            cwd=root,
            env={
                **placeholders,
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(root.parent / "no-home"),
                "CI": "true",
                "NO_COLOR": "1",
                "NODE_OPTIONS": "--disable-proto=throw",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONSAFEPATH": "1",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=LOAD_CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"state": "timeout", "message": f"the module did not finish loading within {LOAD_CHECK_TIMEOUT_SECONDS} seconds"}
    except (OSError, subprocess.SubprocessError):
        return {"state": "toolchain", "message": f"no usable {'python' if python else 'node'} toolchain"}
    report = _load_report(completed.stdout or "")
    scrub = str(root.parent)
    if report is None:
        detail = ((completed.stderr or "").strip() or f"exit code {completed.returncode}").replace(scrub, "")
        return {"state": "error", "name": "Error", "message": f"the module exited before it finished loading: {detail[:MAX_LOAD_DIAGNOSTIC_CHARS]}"}
    message = str(report.get("message", "")).replace(scrub, "")
    if report[LOAD_REPORT_KEY] == "ok":
        return {"state": "ok", "message": ""}
    if report[LOAD_REPORT_KEY] == "unavailable":
        return {"state": "unavailable", "code": str(report.get("code", "")), "message": message}
    return {"state": "error", "name": str(report.get("name", "Error")), "message": message}


def _load_checks(snapshot: Snapshot, replacements: dict[str, str]) -> list[str]:
    """Loads every changed JavaScript file from the candidate tree. Returns limitations.

    A module that throws on load is rejected with Node's own diagnostic, unless the original
    module throws too, in which case the check is recorded as inconclusive. A dependency the
    snapshot declares but does not carry, or a module Node cannot load through `require`, is a
    limitation rather than a failure: nothing about the candidate was shown wrong.
    """
    targets = [path for path in sorted(replacements) if PurePosixPath(path).suffix.lower() in SYNTAX_CHECKED_SUFFIXES]
    if not targets:
        return []
    limitations: list[str] = []
    if shutil.which("node") is None:
        limitations.extend(f"runtime load check unavailable for {path}: no usable node toolchain" for path in targets if language_of_path(path) != PYTHON)
        targets = [path for path in targets if language_of_path(path) == PYTHON]
        if not targets:
            return limitations
    with tempfile.TemporaryDirectory(prefix="mitig8it-load-") as directory:
        candidate_root = Path(directory) / "candidate"
        _materialize_snapshot(candidate_root, snapshot, replacements)
        baseline_root: Path | None = None
        for path in targets:
            outcome = _load_module(candidate_root, path)
            state = outcome["state"]
            if state == "ok":
                continue
            if state == "error":
                if baseline_root is None:
                    baseline_root = Path(directory) / "baseline"
                    _materialize_snapshot(baseline_root, snapshot, {})
                original = _load_module(baseline_root, path)
                if original["state"] == "error":
                    limitations.append(
                        f"runtime load check inconclusive for {path}: the original module does not load "
                        f"either ({original['message'][:MAX_LOAD_LIMITATION_CHARS]})"
                    )
                    continue
                runtime = "Python" if language_of_path(path) == PYTHON else "Node"
                raise PatchPolicyError(
                    f"candidate_load_failed:{path}",
                    f"The patched {path} parses but raises when loaded. {runtime} reports: "
                    f"{outcome.get('name', 'Error')}: {outcome['message'][:MAX_LOAD_DIAGNOSTIC_CHARS]}\n"
                    "Every identifier a hunk uses must be imported or defined by the same proposal: "
                    "add the require or import in another hunk of the same propose_patch call.",
                )
            if state == "unavailable":
                limitations.append(
                    f"runtime load check skipped for {path}: {outcome['message'][:MAX_LOAD_LIMITATION_CHARS]}"
                )
            else:
                limitations.append(f"runtime load check unavailable for {path}: {outcome['message'][:MAX_LOAD_LIMITATION_CHARS]}")
    return limitations


# A hunk states the lines it replaces verbatim, and the service finds them in the exact
# snapshot. The text is the anchor, not the numbers: `start_line` is a hint that only
# disambiguates a block occurring more than once, and `end_line` and `replaced_sha256` are
# tolerated from callers that already send them. Nothing asks a caller to count or to hash.
HUNK_REQUIRED_FIELDS = {"path", "original_lines", "replacement_lines"}
# `finding_id` names the finding the hunk fixes. The proposer tool schema requires it; a caller
# that omits it gets proximity attribution in the engine, and one that sends an unknown id is
# rejected against the task's findings.
HUNK_OPTIONAL_FIELDS = {"start_line", "end_line", "replaced_sha256", "finding_id"}
HUNK_FIELDS = HUNK_REQUIRED_FIELDS | HUNK_OPTIONAL_FIELDS
# Candidate line numbers named in an ambiguity rejection, so the message stays bounded.
MAX_REPORTED_OCCURRENCES = 10
MAX_GUIDANCE_LINE_CHARS = 200


def _quote(line: str) -> str:
    trimmed = line.rstrip("\n\r")
    if len(trimmed) > MAX_GUIDANCE_LINE_CHARS:
        trimmed = trimmed[:MAX_GUIDANCE_LINE_CHARS] + "..."
    return json.dumps(trimmed)


def _normalized_digest(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().lower()
    return candidate if candidate.startswith("sha256:") else f"sha256:{candidate}"


def _occurrences(file_lines: list[str], supplied: list[str]) -> list[int]:
    """Every 1-based line where `supplied` occurs verbatim in the file, ignoring line endings."""
    body = [line.rstrip("\n\r") for line in file_lines]
    wanted = [line.rstrip("\n\r") for line in supplied]
    span = len(wanted)
    return [index + 1 for index in range(len(body) - span + 1) if body[index : index + span] == wanted]


def _first_mismatch(file_lines: list[str], supplied: list[str], start: int) -> str:
    """Why the quoted block is not at `start`: the first line that differs, both sides quoted."""
    body = [line.rstrip("\n\r") for line in file_lines]
    wanted = [line.rstrip("\n\r") for line in supplied]
    for offset, got in enumerate(wanted):
        number = start + offset
        if number > len(body):
            return f"{number} is past the end of the file, which has {len(body)} lines"
        if body[number - 1] != got:
            return f"{number} is {_quote(body[number - 1])}, but original_lines gave {_quote(got)}"
    return f"{start} matches, but the block does not"


def locate_hunk(path: str, file_lines: list[str], hunk: dict[str, Any]) -> tuple[int, int]:
    """Finds the range `original_lines` occupies in the exact snapshot, or rejects with guidance.

    The quoted text is the anchor and `start_line` is only a hint, so an agent that miscounts a
    line number still lands on the right range. A block that occurs once is unambiguous; one that
    repeats is resolved by the hint, and a repeat the hint cannot resolve is rejected by naming
    the candidate line numbers rather than guessing which one the agent meant.
    """
    supplied = hunk["original_lines"]
    if not isinstance(supplied, list) or any(not isinstance(line, str) for line in supplied):
        raise PatchPolicyError(
            "original_lines_must_be_a_list_of_strings",
            "original_lines must be the exact snapshot lines this hunk replaces, one string per "
            "line, without newline characters.",
        )
    if not supplied:
        raise PatchPolicyError(
            "original_lines_required",
            "Quote at least one line to replace. To insert, quote the line you are inserting "
            "after and repeat it in replacement_lines.",
        )
    hint = hunk.get("start_line")
    hint_line = int(hint) if isinstance(hint, int) or (isinstance(hint, str) and str(hint).isdigit()) else None
    found = _occurrences(file_lines, supplied)
    if not found:
        anchor = hint_line if hint_line and 1 <= hint_line <= len(file_lines) else 1
        raise PatchPolicyError(
            f"original_lines_not_found:{path}",
            f"These lines are not in {path}. Line {_first_mismatch(file_lines, supplied, anchor)}. "
            "Copy the lines exactly as read_file returned them, including leading whitespace.",
        )
    if len(found) == 1:
        start = found[0]
    elif hint_line in found:
        start = hint_line
    else:
        candidates = ", ".join(str(number) for number in found[:MAX_REPORTED_OCCURRENCES])
        raise PatchPolicyError(
            f"original_lines_ambiguous:{path}",
            f"These lines occur {len(found)} times in {path}, at lines {candidates}. Set "
            "start_line to the one you mean, or quote more surrounding lines so the block is "
            "unique.",
        )
    end = start + len(supplied) - 1
    if "end_line" in hunk:
        try:
            stated_end = int(hunk["end_line"])
        except (TypeError, ValueError) as exc:
            raise PatchPolicyError("hunk_line_range_invalid", "end_line must be an integer.") from exc
        if stated_end != end:
            raise PatchPolicyError(
                f"hunk_line_range_inconsistent:{path}@{start}-{stated_end}",
                f"original_lines holds {len(supplied)} lines beginning at line {start} of {path}, "
                f"so end_line is {end}. Omit end_line and the service derives it.",
            )
    supplied_digest = _normalized_digest(hunk.get("replaced_sha256"))
    if supplied_digest is not None and supplied_digest != content_sha256("".join(file_lines[start - 1 : end])):
        raise PatchPolicyError(
            f"stale_hunk_digest:{path}@{start}-{end}",
            f"replaced_sha256 does not match {path} lines {start}-{end}. It is optional: omit it "
            "and the service derives it from original_lines.",
        )
    return start, end


def _hunk_text(replacement_lines: Any, replaced_block: str) -> str:
    """Renders a hunk's replacement lines, preserving the replaced block's trailing newline."""
    if not isinstance(replacement_lines, list) or any(not isinstance(line, str) for line in replacement_lines):
        raise PatchPolicyError(
            "replacement_lines_must_be_a_list_of_strings",
            "replacement_lines must be a list of strings, one per new line. Send an empty list to "
            "delete the range.",
        )
    if any("\n" in line or "\r" in line for line in replacement_lines):
        raise PatchPolicyError(
            "replacement_lines_must_not_contain_newlines",
            "Split the replacement on newlines and send one string per line.",
        )
    if not replacement_lines:
        return ""
    trailing = "\n" if replaced_block.endswith(("\n", "\r")) else ""
    return "\n".join(replacement_lines) + trailing


def locate_hunks(snapshot: Snapshot, proposed_changes: list[dict[str, Any]]) -> list[LocatedHunk]:
    """Validates line-range hunks against the exact snapshot and locates each one.

    A hunk quotes the lines it replaces and the service finds them in the exact snapshot, so the
    agent can never edit a range it did not read, never has to compute a hash, and is not held to
    a line number it miscounted. Two hunks on one file may not cover the same line.
    """
    by_path: dict[str, list[dict[str, Any]]] = {}
    for change in proposed_changes:
        if not isinstance(change, dict) or not HUNK_REQUIRED_FIELDS <= set(change) or not set(change) <= HUNK_FIELDS:
            raise PatchPolicyError(
                "change_schema_invalid",
                "Each change must be {path, finding_id, start_line, original_lines, replacement_lines}, "
                "where original_lines are the snapshot lines the hunk replaces, finding_id is the "
                "finding the hunk fixes, and start_line is a hint used only when those lines occur "
                "more than once.",
            )
        _reject_service_path(str(change.get("path", "")))
        try:
            path = validate_repo_path(str(change["path"]))
            snapshot.full_content(path)
        except SnapshotError as exc:
            raise PatchPolicyError(str(exc), f"{change.get('path')!r} is not a readable snapshot path.") from exc
        by_path.setdefault(path, []).append(change)

    located: list[LocatedHunk] = []
    for path, hunks in by_path.items():
        original_lines = snapshot.full_content(path).splitlines(keepends=True)
        prepared: list[LocatedHunk] = []
        for hunk in hunks:
            # The quoted lines are the anchor: the service finds them and derives the range, so a
            # miscounted start_line never decides which lines are replaced.
            start, end = locate_hunk(path, original_lines, hunk)
            replaced_block = "".join(original_lines[start - 1 : end])
            _hunk_text(hunk["replacement_lines"], replaced_block)
            finding_id = hunk.get("finding_id")
            if finding_id is not None and (not isinstance(finding_id, str) or not finding_id.strip()):
                raise PatchPolicyError("hunk_finding_id_invalid", "finding_id must be one of the task's finding ids.")
            prepared.append(
                LocatedHunk(
                    path,
                    start,
                    end,
                    tuple(line.rstrip("\n\r") for line in original_lines[start - 1 : end]),
                    tuple(hunk["replacement_lines"]),
                    finding_id,
                )
            )
        prepared.sort(key=lambda item: (item.start_line, item.end_line))
        for earlier, later in zip(prepared, prepared[1:]):
            if later.start_line <= earlier.end_line:
                raise PatchPolicyError(
                    f"overlapping_hunks:{path}",
                    f"Two hunks on {path} cover line {later.start_line}. Send one hunk per line range.",
                )
        located.extend(prepared)
    return located


def render_hunks(snapshot: Snapshot, hunks: list[LocatedHunk] | tuple[LocatedHunk, ...]) -> dict[str, str]:
    """Applies located hunks to the exact snapshot, bottom-up so earlier line numbers stay valid."""
    by_path: dict[str, list[LocatedHunk]] = {}
    for hunk in hunks:
        by_path.setdefault(hunk.path, []).append(hunk)
    contents: dict[str, str] = {}
    for path, items in by_path.items():
        original_lines = snapshot.full_content(path).splitlines(keepends=True)
        updated = list(original_lines)
        for hunk in sorted(items, key=lambda item: (item.start_line, item.end_line), reverse=True):
            replaced_block = "".join(original_lines[hunk.start_line - 1 : hunk.end_line])
            text = _hunk_text(list(hunk.replacement_lines), replaced_block)
            updated[hunk.start_line - 1 : hunk.end_line] = [text] if text else []
        contents[path] = "".join(updated)
    return contents


def apply_hunks(snapshot: Snapshot, proposed_changes: list[dict[str, Any]]) -> dict[str, str]:
    """Applies line-range hunks to the exact snapshot and returns each file's new content."""
    return render_hunks(snapshot, locate_hunks(snapshot, proposed_changes))


def environment_notes(path: str, original: str, replacement: str) -> list[str]:
    """One note per environment variable a Python candidate newly reads.

    A hardcoded-credential repair moves the value out of the source; the deployment now has to
    supply it. The note is recorded with the candidate's limitations so a reviewer sees which
    variables the patched module expects before it is applied.
    """
    if language_of_path(path) != PYTHON:
        return []
    before = set(_PYTHON_ENV_READ_RE.findall(original))
    return [
        f"{path} now reads {name} from the environment; the deployment must provide it"
        for name in sorted(set(_PYTHON_ENV_READ_RE.findall(replacement)) - before)
    ]


def build_patch_bundle(
    request: RepairRequest,
    snapshot: Snapshot,
    proposed_changes: list[dict[str, Any]],
    regression_tests: list[dict[str, Any]] | None = None,
) -> PatchBundle:
    """Builds a bundle from the agent's line-range hunks against the exact snapshot."""
    if not proposed_changes:
        raise PatchPolicyError("proposal_contains_no_changes", "Send at least one change hunk.")
    hunks = locate_hunks(snapshot, proposed_changes)
    known = sorted(finding.stable_id for finding in request.findings)
    for hunk in hunks:
        if hunk.finding_id is not None and hunk.finding_id not in known:
            raise PatchPolicyError(
                "hunk_finding_unknown",
                f"Each hunk's finding_id must be one of the task's finding ids: {', '.join(known)}. "
                "An import-only hunk names the finding whose fix needs it.",
            )
    return _build_bundle_from_contents(request, snapshot, render_hunks(snapshot, hunks), regression_tests, tuple(hunks))


def _build_bundle_from_contents(
    request: RepairRequest,
    snapshot: Snapshot,
    replacements: dict[str, str],
    regression_tests: list[dict[str, Any]] | None = None,
    hunks: tuple[LocatedHunk, ...] = (),
) -> PatchBundle:
    if not replacements:
        raise PatchPolicyError("proposal_contains_no_changes")
    if len(replacements) > request.policy.max_files:
        raise PatchPolicyError(
            "changed_file_limit_exceeded",
            f"The proposal changes {len(replacements)} files and policy allows {request.policy.max_files}.",
        )

    patches: list[FilePatch] = []
    limitations: list[str] = []
    total_changed = 0
    for path, replacement in sorted(replacements.items()):
        _reject_service_path(path)
        original = snapshot.full_content(path)
        if _path_forbidden(path, request):
            raise PatchPolicyError(f"protected_path:{path}")
        if PurePosixPath(path).suffix.lower() not in APPLICATION_SUFFIXES:
            raise PatchPolicyError(f"unsupported_application_file:{path}")

        base_digest = content_sha256(original)
        if not isinstance(replacement, str):
            raise PatchPolicyError("replacement_content_must_be_string")
        if replacement == original:
            raise PatchPolicyError(
                f"unchanged_file:{path}",
                f"The hunks leave {path} byte-identical to the snapshot. Propose a real change or abstain.",
            )
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
            raise PatchPolicyError(
                "changed_line_limit_exceeded",
                f"The proposal changes {total_changed} lines and policy allows "
                f"{request.policy.max_changed_lines}. Make the change smaller.",
            )
        _reject_missing_dependencies(path, original, replacement, snapshot)
        limitation = _syntax_check(path, replacement)
        if limitation:
            limitations.append(limitation)
        limitations.extend(environment_notes(path, original, replacement))
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

    limitations.extend(_load_checks(snapshot, replacements))
    for path, replacement in sorted(replacements.items()):
        # After the load check: a name used at module top level already failed there with the
        # runtime's own diagnostic, and this catches the ones inside function bodies.
        _reject_undefined_names(path, snapshot.full_content(path), replacement)
    generated_tests, generated_limitations = build_generated_tests(request, snapshot, regression_tests)
    limitations.extend(generated_limitations)
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
        "generated_tests": [test.manifest_entry() for test in generated_tests],
    }
    return PatchBundle(
        tuple(patches),
        digest_json(artifact),
        total_changed,
        tuple(sorted(set(limitations))),
        tuple(generated_tests),
        tuple(hunks),
    )


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

    Candidate contents are reduced to their changed line ranges against the exact snapshot.
    Two candidates whose ranges intersect on one file cannot be combined mechanically, so the
    batch is rejected as `overlapping_candidates` instead of silently preferring one candidate.
    """
    if not bundles:
        raise PatchPolicyError("batch_contains_no_candidates")
    if len(bundles) == 1:
        return bundles[0]
    # Every accepted candidate's reproducer runs against the combined tree: a batch must still
    # demonstrate each finding's vulnerability on the baseline and its repair on the union.
    combined_tests = {test.path: test.spec() for bundle in bundles for test in bundle.generated_tests}
    # The union of every candidate's located hunks, the same change at the same place kept once.
    merged_hunks: dict[tuple[str, int, int, tuple[str, ...]], LocatedHunk] = {}
    for bundle in bundles:
        for hunk in bundle.hunks:
            merged_hunks.setdefault(hunk.key, hunk)
    by_path: dict[str, list[FilePatch]] = {}
    for bundle in bundles:
        for patch in bundle.patches:
            by_path.setdefault(patch.path, []).append(patch)
    replacements: dict[str, str] = {}
    for path, patches in sorted(by_path.items()):
        original = snapshot.full_content(path)
        if len(patches) == 1:
            replacements[path] = patches[0].replacement_content
            continue
        original_lines = original.splitlines(keepends=True)
        accepted: list[tuple[int, int, list[str]]] = []
        for patch in patches:
            for candidate_range in _changed_ranges(original_lines, patch.replacement_content.splitlines(keepends=True)):
                # Per-finding candidates from one group may share a prerequisite change (an
                # added import both fixes need): the same lines at the same place are applied
                # once. A different change on an overlapping range cannot be combined.
                if candidate_range in accepted:
                    continue
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
        replacements[path] = "".join(merged)
    return _build_bundle_from_contents(
        request,
        snapshot,
        replacements,
        [combined_tests[path] for path in sorted(combined_tests)],
        tuple(sorted(merged_hunks.values(), key=lambda item: (item.path, item.start_line, item.end_line))),
    )


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
