"""Installing a repository's declared dependencies into a verification workspace.

`docs/validation/pairs-2026-09.md` measured why a pair that exists does not verify and found one
binding constraint: 84 supported-family findings get no proof because the module under test
imports a package the sandbox has no copy of, and every pair that does verify is a module with
no imports beyond the standard library. Faking the packages does not scale. This is the other
way out.

The install is the one step of a verification run that is allowed to reach a package registry,
and everything here exists to keep it that one step:

* **Only what the repository declares.** `npm ci` from the lockfile the repository carries, and
  `pip install` from its requirements. Nothing is chosen by a model, and nothing is chosen here.
* **No package code runs.** `--ignore-scripts` for npm, and `--only-binary=:all:` for pip, which
  is pip's equivalent: a wheel is unpacked, a source distribution's `setup.py` is executed. A
  requirement with no wheel is a recorded install failure rather than an arbitrary build.
* **Bounded.** One wall clock over the whole install and one cap on the bytes it may leave
  behind. Over either, the tree is removed and the run carries the reason.
* **Recorded.** Every command, its exit code, its duration and the tail of its output, plus a
  digest over the lockfiles the install resolved, so the evidence says what was installed and a
  reader can tell two runs apart.

The checks themselves never run while this is happening and never have network afterwards: the
driver runs this during materialization and re-denies the network before the first check. The
verification level does not change, because installing a dependency says nothing about how
isolated the run was; what the evidence gains is `dependencies_installed` and the digest.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NODE_MANIFEST = "package.json"
# The lockfiles `npm ci` will accept. A repository that carries neither gets one resolved first,
# in a step that writes only the lockfile, so the install proper is still lockfile-driven.
NODE_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
NODE_MODULES = "node_modules"
# Lockfiles of package managers this does not drive. Their presence is recorded, because "yarn
# repository installed through npm" is the kind of thing that explains a strange result later.
FOREIGN_LOCKFILES = ("yarn.lock", "pnpm-lock.yaml", "bun.lockb")

PYTHON_REQUIREMENTS_PREFIX = "requirements"
PYTHON_PROJECT_FILES = ("pyproject.toml", "setup.py", "setup.cfg")
PYTHON_LOCKFILES = ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock")
# Inside the workspace, beside the tree, and dotted so the snapshot walkers that skip dotted
# directories skip it.
VENV_DIRECTORY = ".mitig8it-sandbox-venv"

NPM_INSTALL_ARGV = ("npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund")
NPM_LOCKFILE_ARGV = ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock-only")
PIP_INSTALL_FLAGS = ("--disable-pip-version-check", "--no-input", "--only-binary=:all:")

MAX_STEP_OUTPUT_CHARS = 4_000
MAX_REQUIREMENTS_FILES = 5
# Ecosystem names, as the evidence spells them.
NODE = "node"
PYTHON = "python"

INSTALL_TIMED_OUT = "dependency_install_timed_out"
INSTALL_TOO_LARGE = "dependency_install_exceeded_size_cap"
INSTALL_FAILED = "dependency_install_failed"
NO_MANIFEST = "no_dependency_manifest"


@dataclass(frozen=True)
class InstallStep:
    """One command the install ran, as the evidence carries it."""

    ecosystem: str
    argv: tuple[str, ...]
    exit_code: int | None
    duration_ms: int
    output_tail: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output_tail": self.output_tail,
        }


@dataclass(frozen=True)
class InstallRecord:
    """What the install did, for the evidence and for a measurement's table."""

    installed: bool
    ecosystems: tuple[str, ...] = ()
    steps: tuple[InstallStep, ...] = ()
    lockfile_digest: str | None = None
    bytes_installed: int = 0
    duration_ms: int = 0
    reason_code: str | None = None
    # Where the installed Python packages ended up, for a workspace that has to be told.
    site_packages: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()
    foreign_lockfiles: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "dependencies_installed": self.installed,
            "ecosystems": list(self.ecosystems),
            "steps": [step.as_dict() for step in self.steps],
            "lockfile_digest": self.lockfile_digest,
            "bytes_installed": self.bytes_installed,
            "duration_ms": self.duration_ms,
            "reason_code": self.reason_code,
            "lockfiles": list(self.lockfiles),
            "foreign_lockfiles": list(self.foreign_lockfiles),
        }


@dataclass
class _Accumulator:
    steps: list[InstallStep] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    site_packages: list[str] = field(default_factory=list)
    reason: str | None = None


def _tail(text: str) -> str | None:
    text = text.strip()
    return text[-MAX_STEP_OUTPUT_CHARS:] if text else None


def _install_env() -> dict[str, str]:
    """The environment an install command runs with: a registry client and nothing else.

    `HOME` is left as the process has it, because npm and pip read their registry configuration
    and their caches from it and a deployment that wants a private registry configures it there.
    No repository value reaches this environment.
    """
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    for name, value in os.environ.items():
        # A deployment points the install at its own registry and proxy through these.
        if name.startswith(("NPM_CONFIG_", "PIP_", "npm_config_")) or name in {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}:
            env[name] = value
    env.update({"CI": "true", "NO_COLOR": "1", "npm_config_audit": "false", "npm_config_fund": "false",
                "npm_config_ignore_scripts": "true", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    return env


def _run(acc: _Accumulator, ecosystem: str, argv: tuple[str, ...], cwd: Path, remaining: float) -> bool:
    """Runs one install command under what is left of the wall clock. False ends the install."""
    if remaining <= 0:
        acc.reason = INSTALL_TIMED_OUT
        return False
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no repository input.
            list(argv), cwd=str(cwd), env=_install_env(), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=remaining, check=False,
        )
    except subprocess.TimeoutExpired:
        acc.steps.append(InstallStep(ecosystem, argv, None, round((time.monotonic() - started) * 1000), None))
        acc.reason = INSTALL_TIMED_OUT
        return False
    except (OSError, ValueError) as error:
        acc.steps.append(InstallStep(ecosystem, argv, None, round((time.monotonic() - started) * 1000),
                                     f"{type(error).__name__}: {error}"[:MAX_STEP_OUTPUT_CHARS]))
        acc.reason = f"{INSTALL_FAILED}:{argv[0]}_not_executable"
        return False
    step = InstallStep(ecosystem, argv, completed.returncode, round((time.monotonic() - started) * 1000),
                       _tail((completed.stdout or "") + (completed.stderr or "")))
    acc.steps.append(step)
    if completed.returncode != 0:
        acc.reason = f"{INSTALL_FAILED}:{ecosystem}"
        return False
    return True


def _requirements_files(repository: Path) -> list[Path]:
    """`requirements.txt` and its siblings at the tree root, in a stable order."""
    found = sorted(
        path for path in repository.glob(f"{PYTHON_REQUIREMENTS_PREFIX}*.txt")
        if path.is_file() and not path.is_symlink()
    )
    return found[:MAX_REQUIREMENTS_FILES]


def _install_node(acc: _Accumulator, repository: Path, deadline: float) -> None:
    if not (repository / NODE_MANIFEST).is_file():
        return
    acc.ecosystems.append(NODE)
    if not any((repository / name).is_file() for name in NODE_LOCKFILES):
        # No lockfile to install from, so one is resolved first. `--package-lock-only` writes the
        # lockfile and nothing else, which keeps the install itself lockfile-driven either way.
        if not _run(acc, NODE, NPM_LOCKFILE_ARGV, repository, deadline - time.monotonic()):
            return
    _run(acc, NODE, NPM_INSTALL_ARGV, repository, deadline - time.monotonic())


def _install_python(acc: _Accumulator, repository: Path, deadline: float) -> None:
    requirements = _requirements_files(repository)
    project = [name for name in PYTHON_PROJECT_FILES if (repository / name).is_file()]
    if not requirements and not project:
        return
    acc.ecosystems.append(PYTHON)
    venv = repository / VENV_DIRECTORY
    if not _run(acc, PYTHON, ("python3", "-m", "venv", VENV_DIRECTORY), repository, deadline - time.monotonic()):
        return
    pip = str(venv / "bin" / "pip")
    if requirements:
        argv: tuple[str, ...] = (pip, "install", *PIP_INSTALL_FLAGS)
        for path in requirements:
            argv += ("-r", path.name)
    else:
        # A project with no requirements file installs itself, which pulls its declared
        # dependencies. `--no-deps` is deliberately not passed: the point is the closure.
        argv = (pip, "install", *PIP_INSTALL_FLAGS, ".")
    if not _run(acc, PYTHON, argv, repository, deadline - time.monotonic()):
        return
    acc.site_packages.extend(str(path) for path in sorted(venv.glob("lib/python*/site-packages")) if path.is_dir())


def _tree_bytes(root: Path) -> int:
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in files:
            path = os.path.join(current, name)
            if not os.path.islink(path):
                try:
                    total += os.path.getsize(path)
                except OSError:
                    continue
    return total


def _installed_bytes(repository: Path) -> int:
    roots = [repository / NODE_MODULES, repository / VENV_DIRECTORY]
    return sum(_tree_bytes(root) for root in roots if root.is_dir())


def _lockfile_digest(repository: Path) -> tuple[str | None, tuple[str, ...]]:
    """One digest over every lockfile and requirements file the install resolved from.

    Two runs of the same repository at the same ref produce the same digest, and a run whose
    registry handed it something else does not. That is what makes the evidence comparable.
    """
    names = [*NODE_LOCKFILES, *PYTHON_LOCKFILES, *(path.name for path in _requirements_files(repository))]
    present: list[str] = []
    accumulator = hashlib.sha256()
    for name in sorted(set(names)):
        path = repository / name
        if not path.is_file() or path.is_symlink():
            continue
        present.append(name)
        accumulator.update(name.encode("utf-8"))
        accumulator.update(hashlib.sha256(path.read_bytes()).digest())
    if not present:
        return None, ()
    return f"sha256:{accumulator.hexdigest()}", tuple(present)


def install_dependencies(repository: Path, timeout_seconds: int, max_bytes: int) -> InstallRecord:
    """Installs what `repository` declares, in place, under one wall clock and one size cap."""
    started = time.monotonic()
    deadline = started + max(1.0, float(timeout_seconds))
    acc = _Accumulator()
    _install_node(acc, repository, deadline)
    if acc.reason is None:
        _install_python(acc, repository, deadline)
    digest, lockfiles = _lockfile_digest(repository)
    foreign = tuple(name for name in FOREIGN_LOCKFILES if (repository / name).is_file())
    size = _installed_bytes(repository)
    duration = round((time.monotonic() - started) * 1000)

    if not acc.ecosystems:
        return InstallRecord(False, (), tuple(acc.steps), digest, 0, duration, NO_MANIFEST, (), lockfiles, foreign)
    if acc.reason is None and size > max_bytes:
        # Over the cap the installed tree is removed rather than carried: a workspace that is
        # already too large is not made safer by keeping it, and a half-kept tree would make the
        # checks report a dependency failure whose cause is not in the evidence.
        for name in (NODE_MODULES, VENV_DIRECTORY):
            shutil.rmtree(repository / name, ignore_errors=True)
        acc.reason = INSTALL_TOO_LARGE
        size = 0
    return InstallRecord(
        installed=acc.reason is None,
        ecosystems=tuple(acc.ecosystems),
        steps=tuple(acc.steps),
        lockfile_digest=digest,
        bytes_installed=size,
        duration_ms=duration,
        reason_code=acc.reason,
        site_packages=tuple(acc.site_packages),
        lockfiles=lockfiles,
        foreign_lockfiles=foreign,
    )


# --- pre-installed trees ----------------------------------------------------------------------
#
# A workspace can also be handed a tree that was installed elsewhere. The measurement behind this
# work does exactly that: it installs each corpus repository once and then materializes hundreds
# of workspaces against it, which copying could not pay for. Nothing in production takes this
# path; the local driver reads it from an environment variable and says so.

DEPENDENCY_ROOTS_ENV = "SANDBOX_LOCAL_DEPENDENCY_ROOTS"


def dependency_roots_from_env() -> dict[str, Any]:
    """`{"node_modules": path, "site_packages": [path, ...]}`, or empty when unset or malformed."""
    raw = os.getenv(DEPENDENCY_ROOTS_ENV)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def attach_dependency_roots(repository: Path, roots: dict[str, Any]) -> tuple[str, ...]:
    """Links a pre-installed `node_modules` into `repository`; returns the site-packages to add.

    A symlink rather than a copy: Node resolves through one, and the alternative is copying a
    several-hundred-megabyte tree once per check variant.
    """
    node_modules = roots.get(NODE_MODULES)
    if isinstance(node_modules, str) and node_modules:
        target = Path(node_modules)
        link = repository / NODE_MODULES
        if target.is_dir() and not link.exists() and not link.is_symlink():
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                pass
    supplied = roots.get("site_packages")
    if isinstance(supplied, str):
        supplied = [supplied]
    return tuple(str(item) for item in (supplied or []) if isinstance(item, str) and item)


def python_path_value(site_packages: tuple[str, ...], existing: str | None = None) -> str | None:
    """`PYTHONPATH` for a check that has to see an installed site-packages directory."""
    parts = [item for item in site_packages if item]
    if existing:
        parts.append(existing)
    return os.pathsep.join(parts) if parts else None
