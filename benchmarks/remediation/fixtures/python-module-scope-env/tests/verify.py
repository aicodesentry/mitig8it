"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

The module runs its command when it is imported, so the test sets the environment first and then
imports it. subprocess.run is replaced with a recorder, so nothing runs and the test can tell an
argument list from a shell command string.
"""
import importlib.util
import json
import os
import subprocess
import sys

ATTACK = "/mnt/backup; rm -rf /"
LEGITIMATE = "/mnt/backup"
CALLS = []


def recording_run(args, **kwargs):
    CALLS.append({"args": args, "shell": bool(kwargs.get("shell"))})
    return None


subprocess.run = recording_run


def load(path, target, name="app_under_test"):
    del CALLS[:]
    os.environ["BACKUP_TARGET"] = target
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    load(local_path(), ATTACK)
    call = CALLS[0]
    if call["shell"] or isinstance(call["args"], str):
        sys.stderr.write("vulnerability present: the backup target reaches a shell command string\n")
        sys.exit(1)
    assert ATTACK in call["args"]
    sys.exit(0)


def behavior():
    module = load(local_path(), LEGITIMATE)
    assert module.TARGET == LEGITIMATE
    rendered = json.dumps(CALLS[0]["args"])
    assert "rsync" in rendered and LEGITIMATE in rendered
    sys.exit(0)


def compare(original_path, repaired_path):
    load(original_path, ATTACK, "original")
    assert CALLS[0]["shell"] is True
    assert "rm -rf /" in CALLS[0]["args"]
    load(repaired_path, ATTACK, "repaired")
    assert CALLS[0] == {"args": ["rsync", "-a", "/var/data", ATTACK], "shell": False}
    load(repaired_path, LEGITIMATE, "repaired_legit")
    assert CALLS[0]["args"] == ["rsync", "-a", "/var/data", LEGITIMATE]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
