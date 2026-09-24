"""The program one Cloud Run Job sandbox task runs.

The driver (`cloud_run_job_driver.py`) materializes the baseline and candidate trees on the
control-plane side, packages each into a deterministic tar.gz, uploads them, and starts one
job execution per check with two tasks. Task 0 runs the baseline tree, task 1 the candidate
tree; both run the same fixed argv, so the two halves of one check pair execute concurrently
and never share a container.

This module is the trusted half of that container. In order it:

1. reads its configuration from container-override environment variables;
2. downloads its variant's archive and refuses it unless the bytes hash to the sha256 the
   driver passed in the overrides, so a substituted object cannot be executed;
3. extracts it into a fresh workspace with the same path rules the shared materializer
   enforces (no absolute paths, no `..`, no links, no device nodes);
4. applies what network denial this container can actually apply, drops to a separate
   unprivileged user that holds none of this process's credentials, and then measures what
   that user can still reach;
5. runs the check as that user with a bounded timeout and a sanitized environment;
6. writes one result object per task, HMAC-signed with a per-execution nonce the check's
   user never sees.

It exits 0 whenever it managed to write a result. The check's own exit code is data in that
result, never this task's exit status: a failing check is evidence, not an infrastructure
failure, and Cloud Run must not retry it.

What this file can and cannot enforce is spelled out at `apply_network_isolation`.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import hmac
import io
import json
import os
import pwd
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Callable

# Container-override environment variables. The driver writes every one of them; none carries
# a default that would let a misconfigured job run against the wrong bucket or without a nonce.
ENV_SNAPSHOT_BUCKET = "SANDBOX_JOB_SNAPSHOT_BUCKET"
ENV_SNAPSHOT_MANIFEST = "SANDBOX_JOB_SNAPSHOT_MANIFEST"
ENV_RESULT_BUCKET = "SANDBOX_JOB_RESULT_BUCKET"
ENV_RESULT_PREFIX = "SANDBOX_JOB_RESULT_PREFIX"
ENV_CHECK = "SANDBOX_JOB_CHECK"
ENV_NONCE = "SANDBOX_JOB_NONCE"
ENV_CHECK_USER = "SANDBOX_JOB_CHECK_USER"
ENV_PROJECT = "SANDBOX_JOB_PROJECT"
ENV_REGION = "SANDBOX_JOB_REGION"
ENV_JOB = "SANDBOX_JOB_NAME"

# Cloud Run sets these on every job task; their absence is how the task learns it is not
# running where the verification level claims it runs.
ENV_EXECUTION = "CLOUD_RUN_EXECUTION"
ENV_TASK_INDEX = "CLOUD_RUN_TASK_INDEX"

DEFAULT_CHECK_USER = "sandboxcheck"
ENVIRONMENT_KIND = "cloud-run-job"
RESULT_SCHEMA_VERSION = "v1"
VARIANTS = ("baseline", "candidate")

# Matches the local driver, so the two drivers truncate a check's output at the same size and
# an evidence digest means the same thing at either verification level.
MAX_CAPTURED_CHARS = 200_000

METADATA_HOST = "169.254.169.254"
METADATA_TOKEN_URL = f"http://{METADATA_HOST}/computeMetadata/v1/instance/service-accounts/default/token"
# An address in the reserved 240.0.0.0/4 block: no Google client library can obtain a token
# from it, and nothing routes there.
UNROUTABLE_METADATA_HOST = "240.0.0.0"

PROBES = (
    {"target": "metadata", "kind": "tcp", "endpoint": f"{METADATA_HOST}:80"},
    {"target": "internet", "kind": "tcp", "endpoint": "1.1.1.1:443"},
    {"target": "dns", "kind": "dns", "endpoint": "example.com"},
)
PROBE_TIMEOUT_SECONDS = 2

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1


class JobConfigurationError(RuntimeError):
    """The overrides this task was started with do not describe a runnable check."""


# --------------------------------------------------------------------------------------
# Snapshot transport
# --------------------------------------------------------------------------------------


def download_object(bucket: str, name: str) -> bytes:
    """Reads one object with the task's own Google credentials. Imported lazily for tests."""
    from google.cloud import storage  # noqa: PLC0415 - keeps the import out of the local driver path.

    return storage.Client().bucket(bucket).blob(name).download_as_bytes()


def upload_object(bucket: str, name: str, body: bytes) -> None:
    from google.cloud import storage  # noqa: PLC0415

    storage.Client().bucket(bucket).blob(name).upload_from_string(body, content_type="application/json")


def _safe_member_path(root: Path, name: str) -> Path:
    """The same path rules `sandbox/runner.py` applies, enforced again on the extract side."""
    path = PurePosixPath(name)
    if path.is_absolute() or "\\" in name or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe archive path")
    target = root.joinpath(*path.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("archive path escapes workspace")
    return target


def extract_archive(archive: bytes, root: Path) -> None:
    """Writes the archive under `root`. Only directories and regular files are accepted.

    A link, device, or FIFO member is refused outright rather than filtered away, because a
    snapshot that contains one is not the snapshot the driver packaged.
    """
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        for member in bundle.getmembers():
            target = _safe_member_path(root, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("archive contains a non-regular member")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ValueError("duplicate archive path")
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("archive member is unreadable")
            with target.open("wb") as handle:
                handle.write(source.read())
            target.chmod(0o644)


# --------------------------------------------------------------------------------------
# Identity of the container this task runs in
# --------------------------------------------------------------------------------------


def environment_kind(environ: dict[str, str] | None = None) -> str:
    source = os.environ if environ is None else environ
    return ENVIRONMENT_KIND if source.get(ENV_EXECUTION) else "unknown"


def _http_get(url: str, headers: dict[str, str], timeout: float = 5.0) -> bytes:
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed http(s) URLs.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def read_image_digest(
    project: str,
    region: str,
    job: str,
    fetch: Callable[[str, dict[str, str]], bytes] = _http_get,
) -> tuple[str | None, str | None]:
    """The image this job is configured to run, read from the Cloud Run Admin API.

    It is read here, while the task still holds its credentials, because the driver compares
    it to the digest the deployment pinned. A task cannot mint a digest it likes: this is the
    control plane's own record of the job, fetched with the job identity's token. It returns
    `(digest, error)` and never raises, so a permission gap is reported rather than crashing a
    verification; the driver treats an absent digest as a failed match.
    """
    try:
        token = json.loads(fetch(METADATA_TOKEN_URL, {"Metadata-Flavor": "Google"}))["access_token"]
        url = f"https://{region}-run.googleapis.com/v2/projects/{project}/locations/{region}/jobs/{job}"
        document = json.loads(fetch(url, {"Authorization": f"Bearer {token}"}))
        containers = document["template"]["template"]["containers"]
        image = containers[0]["image"]
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError) as error:
        return None, type(error).__name__
    return (image, None) if isinstance(image, str) and image else (None, "image_absent")


# --------------------------------------------------------------------------------------
# Network denial
# --------------------------------------------------------------------------------------


def _bring_loopback_up() -> None:
    """Inside a fresh network namespace `lo` starts down; a check that binds localhost needs it."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            request = struct.pack("16sh", b"lo", IFF_UP)
            fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, request)
        finally:
            sock.close()
    except OSError:
        # A check that needs loopback will fail its own way; silently losing the namespace
        # would be worse, because that is the only control that actually denies the network.
        pass


def apply_network_isolation() -> None:
    """Moves the calling process into a private user and network namespace with only loopback.

    This is the one control in this file that genuinely removes network reachability rather
    than merely withholding credentials. A container on Cloud Run holds neither CAP_NET_ADMIN
    nor CAP_SYS_ADMIN, so it cannot write firewall rules or unshare a network namespace
    directly; it can, however, create an unprivileged *user* namespace, and inside that
    namespace it holds CAP_NET_ADMIN over a network namespace of its own. The new namespace
    has no route to the VPC, to the internet, or to the link-local metadata server at
    169.254.169.254, which no VPC or IAM configuration can take away from a Cloud Run
    container.

    The uid and gid are mapped to themselves so the workspace the task already chowned stays
    readable. `setgroups` is denied first, which the kernel requires before an unprivileged
    process may write `gid_map`.

    It raises on any failure. Callers feature-detect it in a throwaway child first
    (`network_isolation_available`) so a kernel that forbids unprivileged user namespaces
    degrades to "the probes report what is actually reachable" instead of breaking every check.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    uid, gid = os.getuid(), os.getgid()
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWUSER|CLONE_NEWNET) failed")
    Path("/proc/self/setgroups").write_bytes(b"deny")
    Path("/proc/self/uid_map").write_bytes(f"{uid} {uid} 1\n".encode("ascii"))
    Path("/proc/self/gid_map").write_bytes(f"{gid} {gid} 1\n".encode("ascii"))
    _bring_loopback_up()


def network_isolation_available() -> bool:
    """Tries the namespace once in a throwaway child, so a failure costs no check."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns to the test process.
        try:
            apply_network_isolation()
        except (OSError, ValueError):
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def disable_dns_resolution() -> str:
    """Empties `/etc/resolv.conf` while this process is still privileged enough to do it.

    Cloud Run's filesystem is a writable overlay, so this removes every configured resolver
    for the whole container, including the check. It is a real control and an independent one:
    it holds even where an unprivileged user namespace is unavailable.
    """
    try:
        Path("/etc/resolv.conf").write_text("", encoding="utf-8")
    except OSError as error:
        return f"unavailable:{type(error).__name__}"
    return "cleared"


PROBE_PROGRAM = """
import json, socket, sys
timeout = float(sys.argv[1])
targets = json.loads(sys.argv[2])
results = {}
for probe in targets:
    name = probe["target"]
    try:
        if probe["kind"] == "tcp":
            host, port = probe["endpoint"].rsplit(":", 1)
            socket.create_connection((host, int(port)), timeout).close()
            results[name] = {"reached": True, "detail": "connected", "endpoint": probe["endpoint"]}
        else:
            socket.setdefaulttimeout(timeout)
            socket.getaddrinfo(probe["endpoint"], 443, socket.AF_INET)
            results[name] = {"reached": True, "detail": "resolved", "endpoint": probe["endpoint"]}
    except Exception as error:
        results[name] = {"reached": False, "detail": type(error).__name__, "endpoint": probe["endpoint"]}
print(json.dumps(results))
"""


def unreachable(detail: str) -> dict[str, Any]:
    return {"reached": None, "detail": detail, "endpoint": None}


def run_probes(runner: Callable[[list[str]], subprocess.CompletedProcess[str]]) -> dict[str, Any]:
    """Measures what the check's own user can reach, in the check's own isolation context.

    `reached: null` is not `reached: false`. A probe that could not be run proves nothing, and
    the driver refuses evidence whose probes are anything other than an explicit false.
    """
    argv = [sys.executable, "-c", PROBE_PROGRAM, str(PROBE_TIMEOUT_SECONDS), json.dumps(list(PROBES))]
    try:
        completed = runner(argv)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {probe["target"]: unreachable(f"probe_failed:{type(error).__name__}") for probe in PROBES}
    try:
        measured = json.loads(completed.stdout or "")
    except ValueError:
        return {probe["target"]: unreachable("probe_output_unreadable") for probe in PROBES}
    if not isinstance(measured, dict):
        return {probe["target"]: unreachable("probe_output_unreadable") for probe in PROBES}
    return {
        probe["target"]: measured.get(probe["target"]) or unreachable("probe_missing")
        for probe in PROBES
    }


# --------------------------------------------------------------------------------------
# Running the check
# --------------------------------------------------------------------------------------


def check_environment(home: Path) -> dict[str, str]:
    """The check's whole environment. Nothing from this process's environment survives.

    The nonce, the bucket names, and every Google credential variable are absent by
    construction: this dictionary is built, not filtered.
    """
    return {
        "PATH": "/usr/local/bin:/usr/local/sbin:/usr/bin:/bin",
        "HOME": str(home),
        "CI": "true",
        "NO_COLOR": "1",
        "NODE_OPTIONS": "--disable-proto=throw",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        # A Google client library inside the check resolves the metadata server through these
        # rather than the well-known address, so it asks an address that does not route.
        "GCE_METADATA_HOST": UNROUTABLE_METADATA_HOST,
        "GCE_METADATA_IP": UNROUTABLE_METADATA_HOST,
        "GCE_METADATA_ROOT": UNROUTABLE_METADATA_HOST,
        "NO_GCE_CHECK": "true",
    }


def demote(user: str, isolate_network: bool) -> Callable[[], None]:
    """Builds the child's pre-exec step: become `user`, then leave the network behind.

    The order matters. Dropping privileges first means the check never runs as the identity
    that holds the task's credentials; creating the user namespace afterwards is exactly the
    unprivileged case the kernel allows.
    """
    entry = pwd.getpwnam(user)

    def apply() -> None:  # pragma: no cover - runs only in the forked child.
        os.setgroups([])
        os.setgid(entry.pw_gid)
        os.setuid(entry.pw_uid)
        if isolate_network:
            apply_network_isolation()

    return apply


def run_check(
    argv: list[str],
    workspace: Path,
    timeout_seconds: float,
    preexec: Callable[[], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    home = workspace / "no-home"
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv from the trusted control plane.
            list(argv),
            cwd=workspace / "repo",
            env=check_environment(home),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            preexec_fn=preexec,  # noqa: PLW1509 - dropping privileges is the point.
        )
    except subprocess.TimeoutExpired:
        return {"completed": False, "timed_out": True, "exit_code": None, "output": "", "output_truncated": False,
                "duration_ms": round((time.monotonic() - started) * 1000), "reason_code": "check_timed_out"}
    except (OSError, ValueError) as error:
        return {"completed": False, "timed_out": False, "exit_code": None, "output": "", "output_truncated": False,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "reason_code": f"check_not_executable:{type(error).__name__}"}
    output = (completed.stdout or "") + (completed.stderr or "")
    return {
        "completed": True,
        "timed_out": False,
        "exit_code": completed.returncode,
        "output": output[:MAX_CAPTURED_CHARS],
        "output_truncated": len(output) > MAX_CAPTURED_CHARS,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


# --------------------------------------------------------------------------------------
# Result transport
# --------------------------------------------------------------------------------------


def canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_result(result: dict[str, Any], nonce: str) -> bytes:
    """Binds the result to this execution's nonce.

    The nonce reaches this process through a container override and is never placed in the
    check's environment, so a check cannot forge a result even though it can write to the
    results bucket with the job identity. The nonce is not a substitute for the driver's own
    checks: it proves the result came from a task the driver started, not that the task was
    correct.
    """
    payload = canonical(result)
    signature = hmac.new(nonce.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return canonical({"schema_version": RESULT_SCHEMA_VERSION, "payload": payload.decode("utf-8"), "signature": signature})


# --------------------------------------------------------------------------------------
# Task body
# --------------------------------------------------------------------------------------


def _config(environ: dict[str, str]) -> dict[str, Any]:
    missing = [
        name
        for name in (ENV_SNAPSHOT_BUCKET, ENV_SNAPSHOT_MANIFEST, ENV_RESULT_BUCKET, ENV_RESULT_PREFIX, ENV_CHECK, ENV_NONCE)
        if not environ.get(name)
    ]
    if missing:
        raise JobConfigurationError(f"missing container overrides: {','.join(missing)}")
    try:
        manifest = json.loads(environ[ENV_SNAPSHOT_MANIFEST])
        check = json.loads(environ[ENV_CHECK])
        index = int(environ.get(ENV_TASK_INDEX, "0"))
    except ValueError as error:
        raise JobConfigurationError("container overrides are not valid JSON") from error
    if index not in range(len(VARIANTS)):
        raise JobConfigurationError("task index does not name a variant")
    variant = VARIANTS[index]
    if not isinstance(manifest, dict) or variant not in manifest:
        raise JobConfigurationError("snapshot manifest does not carry this task's variant")
    if not isinstance(check, dict) or not isinstance(check.get("argv"), list) or not check["argv"]:
        raise JobConfigurationError("check override does not carry an argv")
    return {
        "variant": variant,
        "task_index": index,
        "snapshot_bucket": environ[ENV_SNAPSHOT_BUCKET],
        "entry": manifest[variant],
        "result_bucket": environ[ENV_RESULT_BUCKET],
        "result_prefix": environ[ENV_RESULT_PREFIX].rstrip("/"),
        "check": check,
        "nonce": environ[ENV_NONCE],
        "check_user": environ.get(ENV_CHECK_USER) or DEFAULT_CHECK_USER,
        "project": environ.get(ENV_PROJECT, ""),
        "region": environ.get(ENV_REGION, ""),
        "job": environ.get(ENV_JOB, ""),
        "execution": environ.get(ENV_EXECUTION, ""),
    }


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    os.chown(root, uid, gid)
    for path in root.rglob("*"):
        os.chown(path, uid, gid, follow_symlinks=False)


def execute_task(
    config: dict[str, Any],
    *,
    download: Callable[[str, str], bytes],
    workspace_root: str | None = None,
    isolate_network: bool | None = None,
    image_digest_reader: Callable[[str, str, str], tuple[str | None, str | None]] | None = None,
    probe_runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    check_runner: Callable[[list[str], Path, float, Callable[[], None] | None], dict[str, Any]] = run_check,
) -> dict[str, Any]:
    """Runs one variant of one check and returns the unsigned result document."""
    check = config["check"]
    base = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "check_id": check.get("check_id"),
        "kind": check.get("kind"),
        "argv": list(check["argv"]),
        "variant": config["variant"],
        "runner": {
            "job_execution": config["execution"],
            "task_index": config["task_index"],
            "environment_kind": environment_kind(os.environ),
        },
    }
    workspace = Path(tempfile.mkdtemp(prefix="mitig8it-job-", dir=workspace_root))
    try:
        archive = download(config["snapshot_bucket"], config["entry"]["object"])
        digest = hashlib.sha256(archive).hexdigest()
        if not hmac.compare_digest(f"sha256:{digest}", str(config["entry"]["sha256"])):
            return {**base, "completed": False, "reason_code": "snapshot_digest_mismatch", "duration_ms": 0,
                    "timed_out": False, "exit_code": None, "output": "", "output_truncated": False, "probes": {}}
        extract_archive(archive, workspace / "repo")
        (workspace / "no-home").mkdir(parents=True, exist_ok=True)
    except (ValueError, OSError, KeyError, TypeError) as error:
        return {**base, "completed": False, "reason_code": f"materializer_failed:{type(error).__name__}",
                "duration_ms": 0, "timed_out": False, "exit_code": None, "output": "", "output_truncated": False,
                "probes": {}}

    reader = image_digest_reader or read_image_digest
    image_digest, image_error = reader(config["project"], config["region"], config["job"])
    base["runner"]["image_digest"] = image_digest
    if image_error:
        base["runner"]["image_digest_error"] = image_error

    try:
        entry = pwd.getpwnam(config["check_user"])
        _chown_tree(workspace, entry.pw_uid, entry.pw_gid)
    except (KeyError, OSError) as error:
        # Without the separate user the check would run as this process's identity, which
        # holds the nonce and the job's credentials. That is not a sandbox, so the task
        # reports it instead of quietly running the check anyway.
        return {**base, "completed": False, "reason_code": f"check_user_unavailable:{type(error).__name__}",
                "duration_ms": 0, "timed_out": False, "exit_code": None, "output": "", "output_truncated": False,
                "probes": {probe["target"]: unreachable("check_user_unavailable") for probe in PROBES}}

    base["runner"]["dns_resolution"] = disable_dns_resolution()
    isolate = network_isolation_available() if isolate_network is None else isolate_network
    base["runner"]["network_namespace"] = "applied" if isolate else "unavailable"
    preexec = demote(config["check_user"], isolate)

    runner = probe_runner or (
        lambda argv: subprocess.run(  # noqa: S603 - fixed argv built in this module.
            argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS * len(PROBES) + 5,
            check=False, cwd=str(workspace), env=check_environment(workspace / "no-home"), preexec_fn=preexec,
        )
    )
    probes = run_probes(runner)

    result = check_runner(list(check["argv"]), workspace, float(check.get("timeout_seconds") or 60), preexec)
    return {**base, **result, "probes": probes}


def main(environ: dict[str, str] | None = None) -> int:
    source = dict(os.environ if environ is None else environ)
    try:
        config = _config(source)
    except JobConfigurationError as error:
        print(json.dumps({"job_entrypoint_error": str(error)}), file=sys.stderr)
        return 78
    try:
        result = execute_task(config, download=download_object)
    except Exception as error:  # noqa: BLE001 - a crash must still become evidence, not a retry.
        result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "check_id": config["check"].get("check_id"),
            "kind": config["check"].get("kind"),
            "argv": list(config["check"]["argv"]),
            "variant": config["variant"],
            "completed": False,
            "timed_out": False,
            "exit_code": None,
            "output": "",
            "output_truncated": False,
            "duration_ms": 0,
            "probes": {},
            "reason_code": f"job_entrypoint_failed:{type(error).__name__}",
            "runner": {"job_execution": config["execution"], "task_index": config["task_index"],
                       "environment_kind": environment_kind(source)},
        }
    upload_object(config["result_bucket"], f"{config['result_prefix']}/{config['variant']}.json",
                  sign_result(result, config["nonce"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
