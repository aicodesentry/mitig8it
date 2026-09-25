"""Verifying with the repository's dependencies installed.

`docs/validation/pairs-2026-09.md` named one binding constraint: 84 supported-family findings
get no proof because the module under test imports a package the sandbox has no copy of, and
every pair that verifies is a module with no imports beyond the standard library. Installing the
repository's dependencies is the way out of that, and it introduces the only step of a run that
reaches a package registry. These tests hold the properties that make it safe to take.

The first of them is not about the install at all. The proofs assert **through** the harness
fakes: `h.pg.queries`, `h.child_process.calls`, `h.fs.reads`, `h.express` routing, and their
Python counterparts. A workspace that now carries a real `express` or a real `psycopg` must not
shadow them, or every proof that already verified would start asserting on a package instead of
on a recorder, and would stop proving the repair. Precedence is structural in both harnesses and
these tests hold it there:

* JavaScript: `Module._load` answers from `fakes` before it ever calls Node's own loader, and the
  `module.registerHooks` resolver returns the fake's synthetic URL before `nextResolve`. A
  `node_modules` beside the module is never consulted for a faked name.
* Python: `_install` writes the fake into `sys.modules` before the module is executed, and
  `sys.modules` is consulted before any finder on `sys.meta_path`. `os.system`, `os.popen`,
  `os.environ` and `open` are replaced on the real objects, so an installed package cannot
  reintroduce them either.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.families import HARDCODED_CREDENTIAL, JAVASCRIPT
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sandbox.dependencies import (
    DEPENDENCY_ROOTS_ENV,
    NODE_MODULES,
    VENV_DIRECTORY,
    attach_dependency_roots,
    dependency_roots_from_env,
    install_dependencies,
    python_path_value,
)
from src.sandbox.harness import (
    HARNESS_PATH,
    HARNESS_SOURCE_FILE,
    PYTHON_HARNESS_PATH,
    PYTHON_HARNESS_SOURCE_FILE,
)
from src.sandbox.local_driver import LocalSubprocessDriver
from tests.conftest import git_blob

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the harness runs under node")
requires_npm = pytest.mark.skipif(shutil.which("npm") is None, reason="the install step runs npm")

SECRET = 'const apiKey = "sk-live-abc123def456";\nmodule.exports = { apiKey };\n'


# --- the fakes still win, with the real packages installed beside them -------------------------
#
# Each of these writes a real package into `node_modules` or onto the Python path whose exports
# are deliberately wrong: a marker the recorder does not have, and for the recording fakes a
# `query` or `exec` that records nothing. A proof that got the installed package instead of the
# fake would see the marker and would record nothing, and the test says so by name.

JS_SHADOWED = ("express", "pg", "child_process", "fs")
JS_IMPOSTOR = {
    "express": "module.exports = function express() { return { installed: true }; };\n"
               "module.exports.Router = () => ({ installed: true });\n"
               "module.exports.installedImpostor = true;\n",
    "pg": "class Pool { query() { return { rows: [], installed: true }; } }\n"
          "module.exports = { Pool, Client: Pool, installedImpostor: true };\n",
    "child_process": "module.exports = { exec() {}, execSync() {}, spawn() {}, installedImpostor: true };\n",
    "fs": "module.exports = { readFileSync() { return ''; }, existsSync() { return false; }, installedImpostor: true };\n",
}


def _node_workspace(tmp_path: Path, subject: str, source: str) -> Path:
    """A workspace laid out as the sandbox lays one out, with an installed `node_modules`.

    The harness sits at `.mitig8it/harness.js` because that is where the materializer puts it and
    because its own `ROOT` is one directory above itself.
    """
    root = tmp_path / "workspace"
    (root / NODE_MODULES).mkdir(parents=True)
    (root / ".mitig8it").mkdir(parents=True)
    (root / HARNESS_PATH).write_text(HARNESS_SOURCE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    for name, body in JS_IMPOSTOR.items():
        package = root / NODE_MODULES / name
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0", "main": "index.js"}), encoding="utf-8")
        (package / "index.js").write_text(body, encoding="utf-8")
    (root / subject).parent.mkdir(parents=True, exist_ok=True)
    (root / subject).write_text(source, encoding="utf-8")
    return root


def _run_node(root: Path, program: str) -> subprocess.CompletedProcess:
    test = root / ".mitig8it" / "probe.test.js"
    test.write_text(program, encoding="utf-8")
    return subprocess.run(
        ["node", str(test)],
        cwd=root, env={"PATH": os.environ.get("PATH", ""), "NO_COLOR": "1"},
        capture_output=True, text=True, timeout=120, check=False,
    )


@requires_node
@pytest.mark.parametrize("name", JS_SHADOWED)
def test_a_javascript_fake_is_not_shadowed_by_an_installed_package_of_the_same_name(tmp_path, name):
    subject = "src/app.js"
    source = (
        f"const mod = require({json.dumps(name)});\n"
        "module.exports = { impostor: Boolean(mod && mod.installedImpostor) };\n"
    )
    root = _node_workspace(tmp_path, subject, source)
    completed = _run_node(root, (
        "const h = require('./harness');\n"
        "h.run(async () => {\n"
        f"  const m = h.load('{subject}');\n"
        "  h.assert(m.impostor === false, 'the module got the installed package instead of the harness fake');\n"
        "});\n"
    ))
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]


@requires_node
def test_an_es_module_also_gets_the_fake_rather_than_the_installed_package(tmp_path):
    # The CommonJS loader and the ES module loader are two different resolvers and the fakes are
    # served to both. An installed package is what the ES loader would otherwise find first.
    subject = "src/app.mjs"
    source = (
        "import express from 'express';\n"
        "import pg from 'pg';\n"
        "export const impostor = Boolean(express.installedImpostor || pg.installedImpostor);\n"
    )
    root = _node_workspace(tmp_path, subject, source)
    completed = _run_node(root, (
        "const h = require('./harness');\n"
        "h.run(async () => {\n"
        "  h.load('src/app.mjs');\n"
        f"  const m = await import('file://' + require('node:path').resolve('{subject}'));\n"
        "  h.assert(m.impostor === false, 'the ES module got the installed package instead of the fake');\n"
        "});\n"
    ))
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]


@requires_node
def test_the_recorders_a_proof_asserts_on_still_record_with_packages_installed(tmp_path):
    """The point of precedence: `h.pg.queries` and `h.child_process.calls` still fill up."""
    subject = "src/orders.js"
    source = (
        "const { Pool } = require('pg');\n"
        "const { execSync } = require('child_process');\n"
        "const pool = new Pool();\n"
        "exports.lookup = (id) => { pool.query('SELECT 1 FROM t WHERE id = $1', [id]); execSync('ls', ['-l']); };\n"
    )
    root = _node_workspace(tmp_path, subject, source)
    completed = _run_node(root, (
        "const h = require('./harness');\n"
        "h.run(async () => {\n"
        f"  const m = h.load('{subject}');\n"
        "  m.lookup('7');\n"
        "  h.assert(h.pg.queries.length === 1, 'the pg recorder saw no query');\n"
        "  h.assert(h.child_process.calls.length === 1, 'the child_process recorder saw no call');\n"
        "});\n"
    ))
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]


PY_SHADOWED = ("flask", "sqlite3", "psycopg", "subprocess")
PY_IMPOSTOR = (
    "installed_impostor = True\n"
    "def connect(*args, **kwargs):\n"
    "    return None\n"
    "def run(*args, **kwargs):\n"
    "    return None\n"
    "class Flask:\n"
    "    def __init__(self, *args, **kwargs):\n"
    "        pass\n"
)


def _python_site_packages(tmp_path: Path) -> Path:
    site = tmp_path / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for name in PY_SHADOWED:
        (site / f"{name}.py").write_text(PY_IMPOSTOR, encoding="utf-8")
    return site


def _python_workspace(tmp_path: Path, module: str, test: str) -> Path:
    """The sandbox's layout: the harness at `.mitig8it/harness.py`, the tree above it."""
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / ".mitig8it").mkdir(parents=True)
    (root / PYTHON_HARNESS_PATH).write_text(PYTHON_HARNESS_SOURCE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "src" / "app.py").write_text(module, encoding="utf-8")
    (root / ".mitig8it" / "probe.test.py").write_text(test, encoding="utf-8")
    return root


def _run_python(root: Path, site: Path) -> subprocess.CompletedProcess:
    """Runs the harness the way `verification.checks` builds its argv, with `site` importable."""
    return subprocess.run(
        [sys.executable, PYTHON_HARNESS_PATH, ".mitig8it/probe.test.py"],
        cwd=root,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(site), "NO_COLOR": "1",
             "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"},
        capture_output=True, text=True, timeout=120, check=False,
    )


@pytest.mark.parametrize("name", PY_SHADOWED)
def test_a_python_fake_is_not_shadowed_by_an_installed_package_of_the_same_name(tmp_path, name):
    root = _python_workspace(
        tmp_path,
        f"import {name}\nimpostor = getattr({name}, 'installed_impostor', False)\n",
        "import harness as h\n"
        "def body():\n"
        "    m = h.load('src/app.py')\n"
        "    h.assert_true(m.impostor is False, 'the module got the installed package, not the fake')\n"
        "h.run(body)\n",
    )
    completed = _run_python(root, _python_site_packages(tmp_path))
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]


def test_os_environ_and_the_recorders_survive_a_site_packages_on_the_path(tmp_path):
    """`os` and `open` are replaced on the real objects, so nothing installed can take them back."""
    root = _python_workspace(
        tmp_path,
        "import os\n"
        "token = os.environ.get('APP_TOKEN', '')\n"
        "def run_it():\n"
        "    os.system('echo hi')\n",
        "import harness as h\n"
        "def body():\n"
        "    m = h.load('src/app.py', env={'APP_TOKEN': 'from-the-test'})\n"
        "    h.assert_equal(m.token, 'from-the-test')\n"
        "    h.assert_env_read('APP_TOKEN')\n"
        "    m.run_it()\n"
        "    h.assert_true(len(h.subprocess.calls) == 1, 'os.system was not recorded')\n"
        "h.run(body)\n",
    )
    completed = _run_python(root, _python_site_packages(tmp_path))
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]


# --- the loadability gate opens only for what a manifest declares ------------------------------

def _proof(request_payload: dict, files: dict[str, str], install: bool, subject: str = "src/config.js"):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(text)) for path, text in files.items()]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": text, "sha": git_blob(text)} for path, text in files.items()]
    line = next(index for index, text in enumerate(files[subject].splitlines(), start=1) if "sk-live" in text)
    payload["findings"] = [{
        "snapshot_id": "secret-1", "rule_id": "cwe-798.js-credential-constant", "cwe_id": "CWE-798",
        "file_path": subject, "line_start": line, "line_end": line,
    }]
    payload["policy"] = {**dict(payload.get("policy") or {}), "install_dependencies": install}
    request = RepairRequest.model_validate(payload)
    return generate_proof(Snapshot(request), request.findings[0], HARDCODED_CREDENTIAL, JAVASCRIPT)


MANIFEST = json.dumps({"name": "app", "dependencies": {"body-parser": "^1.20.2"},
                       "devDependencies": {"@scope/thing": "^1.0.0"}})


def test_a_package_is_loadable_only_once_the_install_is_on(request_payload):
    files = {"package.json": MANIFEST, "src/config.js": "var bodyParser = require('body-parser');\n" + SECRET}
    refused = _proof(request_payload, files, install=False)
    assert isinstance(refused, ProofFallback)
    assert refused.reason == "dependency_not_available_in_sandbox:body-parser"
    assert not isinstance(_proof(request_payload, files, install=True), ProofFallback)


def test_a_transitive_package_the_manifest_never_names_is_loadable_too(request_payload):
    """`npm ci` installs the lockfile's closure, not the names a manifest happens to list.

    This is the case the whole measurement turned on: dvna's `server.js` imports `body-parser`,
    which arrives behind `express`, and juice-shop's modules import `@angular` packages its root
    manifest does not name. A gate that refused those refused every one of the 81 findings the
    install was meant to reach.
    """
    files = {"package.json": json.dumps({"name": "app", "dependencies": {"express": "^4.19.2"}}),
             "src/config.js": "var bodyParser = require('body-parser');\n" + SECRET}
    assert not isinstance(_proof(request_payload, files, install=True), ProofFallback)


def test_a_scoped_package_is_loadable_with_the_install_on(request_payload):
    files = {"package.json": MANIFEST, "src/config.js": "import t from '@scope/thing/sub'\n" + SECRET}
    assert not isinstance(_proof(request_payload, files, install=True), ProofFallback)


def test_a_manifest_in_a_workspace_directory_counts_too(request_payload):
    files = {
        "packages/api/package.json": json.dumps({"dependencies": {"winston": "^3.0.0"}}),
        "src/config.js": "const log = require('winston');\n" + SECRET,
    }
    assert not isinstance(_proof(request_payload, files, install=True), ProofFallback)


def test_a_tree_with_no_manifest_is_still_refused_with_the_install_on(request_payload):
    # There is nothing for an install to read, so nothing reaches the workspace and the refusal
    # is as true with the flag on as without it.
    files = {"src/config.js": "const m = require('mongoose');\n" + SECRET}
    refused = _proof(request_payload, files, install=True)
    assert isinstance(refused, ProofFallback)
    assert refused.reason == "dependency_not_available_in_sandbox:mongoose"


def test_a_faked_package_is_never_taken_from_the_installed_tree(request_payload):
    # The gate has to keep naming the fakes as available even with the install on, because the
    # harness serves them ahead of anything in node_modules and the proofs assert through them.
    files = {"package.json": MANIFEST,
             "src/config.js": "const express = require('express');\nconst { Pool } = require('pg');\n" + SECRET}
    assert not isinstance(_proof(request_payload, files, install=True), ProofFallback)


def test_unstrippable_typescript_is_still_refused_with_the_install_on(request_payload):
    # Installing a package does not teach Node's type stripper to emit an enum.
    files = {"package.json": MANIFEST,
             "src/config.ts": "import { Tier } from './tier'\n" + SECRET,
             "src/tier.ts": "export enum Tier { Free, Paid }\n"}
    refused = _proof(request_payload, files, install=True, subject="src/config.ts")
    assert isinstance(refused, ProofFallback)
    assert refused.reason == "typescript_syntax_not_strippable:enum"


# --- the install step itself -------------------------------------------------------------------
#
# These run npm against a pre-populated local registry directory: a `file:` dependency resolves
# from disk, so the install is a real `npm ci` with a real lockfile and no network at all.


def _local_package(tmp_path: Path, name: str, *, install_script: bool = False, filler: int = 0) -> Path:
    """Packs a real npm tarball into a local registry directory and returns its path.

    A tarball rather than a directory: npm links a `file:` directory dependency instead of
    copying it, and a symlinked tree would make the size cap and the script guard untestable.
    """
    source = tmp_path / "packages" / name
    source.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": "1.0.0", "main": "index.js"}
    if install_script:
        # `--ignore-scripts` has to stop this from running. It writes into the package directory
        # it is installed into, which is inside the workspace, so the assertion can look for it.
        manifest["scripts"] = {"preinstall": "node -e \"require('fs').writeFileSync('SCRIPT-RAN','1')\""}
    (source / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    (source / "index.js").write_text("module.exports = { name: '%s' };\n" % name, encoding="utf-8")
    if filler:
        (source / "payload.js").write_text("// " + ("x" * filler) + "\n", encoding="utf-8")
    registry = tmp_path / "registry"
    registry.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["npm", "pack", "--silent", "--pack-destination", str(registry), str(source)],
        cwd=source, capture_output=True, text=True, timeout=120, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return registry / f"{name}-1.0.0.tgz"


def _node_repository(tmp_path: Path, dependencies: dict[str, str]) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(parents=True, exist_ok=True)
    (repository / "package.json").write_text(
        json.dumps({"name": "subject", "version": "1.0.0", "dependencies": dependencies}), encoding="utf-8")
    return repository


@requires_npm
def test_the_install_resolves_a_lockfile_when_the_repository_carries_none(tmp_path):
    package = _local_package(tmp_path, "left-pad-ish")
    repository = _node_repository(tmp_path, {"left-pad-ish": f"file:{package}"})
    record = install_dependencies(repository, 300, 1_000_000_000)

    assert record.installed, record.as_dict()
    assert record.ecosystems == ("node",)
    # The lockfile step ran first, then the install proper: two commands, `npm install
    # --package-lock-only` and `npm ci`.
    assert [step.argv[1] for step in record.steps] == ["install", "ci"]
    assert (repository / "package-lock.json").is_file()
    assert (repository / NODE_MODULES / "left-pad-ish" / "index.js").is_file()
    assert record.lockfile_digest and record.lockfile_digest.startswith("sha256:")
    assert record.lockfiles == ("package-lock.json",)
    assert record.bytes_installed > 0


@requires_npm
def test_an_existing_lockfile_is_installed_from_directly(tmp_path):
    package = _local_package(tmp_path, "pinned-thing")
    repository = _node_repository(tmp_path, {"pinned-thing": f"file:{package}"})
    install_dependencies(repository, 300, 1_000_000_000)
    shutil.rmtree(repository / NODE_MODULES)

    record = install_dependencies(repository, 300, 1_000_000_000)
    assert record.installed, record.as_dict()
    assert [step.argv[1] for step in record.steps] == ["ci"]


@requires_npm
def test_a_packages_install_script_does_not_run(tmp_path):
    package = _local_package(tmp_path, "scripted", install_script=True)
    repository = _node_repository(tmp_path, {"scripted": f"file:{package}"})
    record = install_dependencies(repository, 300, 1_000_000_000)

    assert record.installed, record.as_dict()
    assert not (repository / NODE_MODULES / "scripted" / "SCRIPT-RAN").exists()
    assert all("--ignore-scripts" in step.argv for step in record.steps)


@requires_npm
def test_the_same_lockfile_gives_the_same_digest_and_a_different_one_does_not(tmp_path):
    one = _local_package(tmp_path, "one")
    two = _local_package(tmp_path, "two")
    first = _node_repository(tmp_path / "a", {"one": f"file:{one}"})
    again = _node_repository(tmp_path / "b", {"one": f"file:{one}"})
    other = _node_repository(tmp_path / "c", {"two": f"file:{two}"})

    assert install_dependencies(first, 300, 1_000_000_000).lockfile_digest == \
        install_dependencies(again, 300, 1_000_000_000).lockfile_digest
    assert install_dependencies(other, 300, 1_000_000_000).lockfile_digest != \
        install_dependencies(first, 300, 1_000_000_000).lockfile_digest


@requires_npm
def test_an_install_over_the_size_cap_leaves_no_tree_behind(tmp_path):
    package = _local_package(tmp_path, "biggish", filler=200_000)
    repository = _node_repository(tmp_path, {"biggish": f"file:{package}"})

    record = install_dependencies(repository, 300, 1_000)
    assert not record.installed
    assert record.reason_code == "dependency_install_exceeded_size_cap"
    assert record.bytes_installed == 0
    assert not (repository / NODE_MODULES).exists()


@requires_npm
def test_a_failed_install_is_reported_with_the_command_that_failed(tmp_path):
    repository = _node_repository(tmp_path, {"nothing-resolves-here": f"file:{tmp_path / 'absent.tgz'}"})
    record = install_dependencies(repository, 300, 1_000_000_000)

    assert not record.installed
    assert record.reason_code == "dependency_install_failed:node"
    assert record.steps and record.steps[-1].exit_code not in (0, None)
    assert record.steps[-1].output_tail


def test_a_repository_that_declares_nothing_installs_nothing(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("no manifests here\n", encoding="utf-8")

    record = install_dependencies(repository, 300, 1_000_000_000)
    assert not record.installed
    assert record.reason_code == "no_dependency_manifest"
    assert record.ecosystems == ()
    assert record.steps == ()


def test_a_python_project_installs_into_a_venv_inside_the_workspace(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    # An empty requirements file installs nothing and still proves the shape: a venv beside the
    # tree, pip driven with the wheel-only flags, and the requirements file in the digest.
    (repository / "requirements.txt").write_text("\n", encoding="utf-8")

    record = install_dependencies(repository, 600, 2_000_000_000)
    assert record.installed, record.as_dict()
    assert record.ecosystems == ("python",)
    assert (repository / VENV_DIRECTORY).is_dir()
    assert record.site_packages and all(Path(item).is_dir() for item in record.site_packages)
    assert record.lockfiles == ("requirements.txt",)
    pip_step = record.steps[-1]
    assert "--only-binary=:all:" in pip_step.argv, pip_step.argv


def test_a_requirement_with_no_wheel_fails_the_install_rather_than_building_it(tmp_path):
    # `--only-binary=:all:` is pip's `--ignore-scripts`: a source distribution's setup.py is
    # arbitrary code, so a requirement that has no wheel is a recorded failure instead.
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "requirements.txt").write_text("./local-sdist\n", encoding="utf-8")
    sdist = repository / "local-sdist"
    sdist.mkdir()
    (sdist / "setup.py").write_text("raise SystemExit('setup.py must not run')\n", encoding="utf-8")

    record = install_dependencies(repository, 300, 1_000_000_000)
    assert not record.installed
    assert record.reason_code == "dependency_install_failed:python"


# --- attaching a tree installed elsewhere -------------------------------------------------------

def test_a_preinstalled_tree_is_linked_in_and_its_site_packages_reach_pythonpath(tmp_path, monkeypatch):
    installed = tmp_path / "installed"
    (installed / NODE_MODULES / "left-pad").mkdir(parents=True)
    site = installed / "venv" / "site-packages"
    site.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    roots = {NODE_MODULES: str(installed / NODE_MODULES), "site_packages": [str(site)]}
    monkeypatch.setenv(DEPENDENCY_ROOTS_ENV, json.dumps(roots))
    assert dependency_roots_from_env() == roots

    site_packages = attach_dependency_roots(workspace, dependency_roots_from_env())
    assert (workspace / NODE_MODULES).is_symlink()
    assert (workspace / NODE_MODULES / "left-pad").is_dir()
    assert python_path_value(site_packages) == str(site)


def test_a_malformed_dependency_roots_variable_is_ignored(monkeypatch):
    monkeypatch.setenv(DEPENDENCY_ROOTS_ENV, "not json at all")
    assert dependency_roots_from_env() == {}
    monkeypatch.setenv(DEPENDENCY_ROOTS_ENV, "[1, 2, 3]")
    assert dependency_roots_from_env() == {}


def test_attaching_never_overwrites_a_node_modules_the_snapshot_carried(tmp_path):
    installed = tmp_path / "installed" / NODE_MODULES
    installed.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    (workspace / NODE_MODULES).mkdir(parents=True)
    (workspace / NODE_MODULES / "keep.txt").write_text("from the snapshot\n", encoding="utf-8")

    attach_dependency_roots(workspace, {NODE_MODULES: str(installed)})
    assert not (workspace / NODE_MODULES).is_symlink()
    assert (workspace / NODE_MODULES / "keep.txt").is_file()


# --- what the driver puts in the evidence -------------------------------------------------------

def _policy(**overrides) -> dict:
    return {"image_digest": None, "network": "deny", "read_only_root": True,
            "max_output_chars": 100_000, "deadline_seconds": 60, **overrides}


def _payload(commands: list[dict], **policy) -> dict:
    return {
        "execution_id": "exec-1", "request_digest": "sha256:0", "request_nonce": "n",
        "repository": {"original_tree_digest": "sha256:a", "candidate_tree_digest": "sha256:b",
                       "head_tree_oid": "0" * 40, "verified_tree_oid": "0" * 40},
        "snapshot": [], "patches": [], "execution_policy": _policy(commands=commands, **policy),
    }


def test_a_run_without_the_flag_reports_no_install_and_runs_none(tmp_path):
    driver = LocalSubprocessDriver(str(tmp_path))
    result = driver.execute(_payload([
        {"check_id": "c", "kind": "behavior", "argv": [sys.executable, "-c", "pass"], "timeout_seconds": 10},
    ]), 60)
    assert result["dependencies"] == {"dependencies_installed": False}


def test_a_run_with_the_flag_records_the_install_and_its_digest(tmp_path):
    driver = LocalSubprocessDriver(str(tmp_path))
    payload = _payload(
        [{"check_id": "c", "kind": "behavior", "argv": [sys.executable, "-c", "pass"], "timeout_seconds": 20}],
        install_dependencies=True, dependency_install_timeout_seconds=600,
        max_dependency_install_bytes=2_000_000_000,
    )
    payload["snapshot"] = [{"path": "requirements.txt", "content": "\n"}]
    result = driver.execute(payload, 300)

    dependencies = result["dependencies"]
    assert dependencies["dependencies_installed"] is True, dependencies
    assert dependencies["ecosystems"] == ["python"]
    assert dependencies["lockfile_digest"].startswith("sha256:")
    # Two workspaces, one per variant, each installed on its own.
    assert dependencies["workspaces"] == 2
    assert dependencies["limitations"]


@pytest.mark.asyncio
async def test_the_verifier_hands_the_policy_down_to_the_sandbox(tmp_path, request_payload):
    """The driver cannot install what the request never told it to."""
    from src.verification import Verifier
    from tests.test_harness import _bundle, _orders_payload

    payload = _orders_payload(request_payload)
    payload["policy"] = {**dict(payload.get("policy") or {}), "install_dependencies": True,
                         "dependency_install_timeout_seconds": 120, "max_dependency_install_bytes": 1_000_000}
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)

    captured: list[dict] = []

    class _Driver(LocalSubprocessDriver):
        def execute(self, sandbox_payload, deadline_seconds):
            captured.append(sandbox_payload["execution_policy"])
            return {"outcome": "inconclusive", "checks": []}

    from src.sandbox import InProcessSandboxBroker

    await Verifier(InProcessSandboxBroker(_Driver(str(tmp_path)))).verify(request, snapshot, _bundle(request, snapshot))
    assert captured and captured[0]["install_dependencies"] is True
    assert captured[0]["dependency_install_timeout_seconds"] == 120
    assert captured[0]["max_dependency_install_bytes"] == 1_000_000
    # The checks themselves are unchanged: the install is not a network the checks get.
    assert captured[0]["network"] == "deny"


# --- what the local driver puts in the evidence -------------------------------------------------


def test_a_preinstalled_run_says_so_rather_than_claiming_an_install(tmp_path, monkeypatch):
    installed = tmp_path / "installed" / NODE_MODULES
    installed.mkdir(parents=True)
    monkeypatch.setenv(DEPENDENCY_ROOTS_ENV, json.dumps({NODE_MODULES: str(installed)}))
    driver = LocalSubprocessDriver(str(tmp_path / "workspaces"))
    result = driver.execute(_payload([
        {"check_id": "c", "kind": "behavior", "argv": [sys.executable, "-c", "pass"], "timeout_seconds": 10},
    ]), 60)

    dependencies = result["dependencies"]
    assert dependencies["reason_code"] == "preinstalled_tree_attached"
    assert dependencies["lockfile_digest"] is None
    assert any("no install ran here" in item for item in dependencies["limitations"])
