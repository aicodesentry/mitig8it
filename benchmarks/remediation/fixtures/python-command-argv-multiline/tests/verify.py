"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

The command is assembled across five source lines by a helper, so the repair has to rewrite the
helper's return value and the call that passes it. subprocess.check_call is a recorder; nothing
is executed.
"""
import importlib.util
import json
import os
import subprocess
import sys

ATTACK = "/srv/data; rm -rf /"
LEGITIMATE = "/srv/data"
DESTINATION = "/backups/nightly.tgz"
CALLS = []


def recording_check_call(args, **kwargs):
    CALLS.append({"args": args, "shell": bool(kwargs.get("shell"))})
    return 0


subprocess.check_call = recording_check_call


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    del CALLS[:]
    load(local_path()).run_backup(ATTACK, DESTINATION)
    call = CALLS[0]
    if call["shell"] or isinstance(call["args"], str):
        sys.stderr.write("vulnerability present: the source path reaches a shell command string\n")
        sys.exit(1)
    assert ATTACK in call["args"]
    sys.exit(0)


def behavior():
    del CALLS[:]
    assert load(local_path()).run_backup(LEGITIMATE, DESTINATION) == DESTINATION
    rendered = json.dumps(CALLS[0]["args"])
    assert "tar" in rendered and LEGITIMATE in rendered and DESTINATION in rendered
    sys.exit(0)


def compare(original_path, repaired_path):
    del CALLS[:]
    load(original_path, "original").run_backup(ATTACK, DESTINATION)
    assert CALLS[0]["shell"] is True
    assert "rm -rf /" in CALLS[0]["args"]
    del CALLS[:]
    repaired = load(repaired_path, "repaired")
    repaired.run_backup(ATTACK, DESTINATION)
    assert CALLS[0] == {"args": ["tar", "-czf", DESTINATION, "--", ATTACK], "shell": False}
    assert repaired.backup_command(LEGITIMATE, DESTINATION) == ["tar", "-czf", DESTINATION, "--", LEGITIMATE]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
