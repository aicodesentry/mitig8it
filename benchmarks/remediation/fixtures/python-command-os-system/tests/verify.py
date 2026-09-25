"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import subprocess
import sys

ATTACK = "/var/log/app.log; rm -rf /"
LEGITIMATE = "/var/log/app.log"
CALLS = []


def recording_system(command):
    CALLS.append({"args": command, "shell": True})
    return 0


def recording_run(args, **kwargs):
    CALLS.append({"args": args, "shell": bool(kwargs.get("shell"))})
    return None


os.system = recording_system
subprocess.run = recording_run


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    del CALLS[:]
    load(local_path()).archive_log(ATTACK)
    call = CALLS[0]
    if call["shell"] or isinstance(call["args"], str):
        sys.stderr.write("vulnerability present: the argument reaches a shell command string\n")
        sys.exit(1)
    assert ATTACK in call["args"]
    sys.exit(0)


def behavior():
    del CALLS[:]
    assert load(local_path()).archive_log(LEGITIMATE) == LEGITIMATE + ".gz"
    rendered = json.dumps(CALLS[0]["args"])
    assert "gzip" in rendered and LEGITIMATE in rendered
    sys.exit(0)


def compare(original_path, repaired_path):
    del CALLS[:]
    load(original_path, "original").archive_log(ATTACK)
    assert CALLS[0]["shell"] is True
    assert "rm -rf /" in CALLS[0]["args"]
    del CALLS[:]
    load(repaired_path, "repaired").archive_log(ATTACK)
    assert CALLS[0] == {"args": ["gzip", "--force", ATTACK], "shell": False}
    del CALLS[:]
    load(repaired_path, "repaired_legit").archive_log(LEGITIMATE)
    assert CALLS[0]["args"] == ["gzip", "--force", LEGITIMATE]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
