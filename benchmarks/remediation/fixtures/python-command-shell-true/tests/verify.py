"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import subprocess
import sys

ATTACK = "photo.png; rm -rf /"
LEGITIMATE = "photo.png"
CALLS = []


def recording_run(args, **kwargs):
    CALLS.append({"args": args, "shell": bool(kwargs.get("shell"))})
    return None


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
    load(local_path()).render_thumbnail(ATTACK)
    call = CALLS[0]
    if call["shell"] or isinstance(call["args"], str):
        sys.stderr.write("vulnerability present: the argument reaches a shell command string\n")
        sys.exit(1)
    assert ATTACK in call["args"]
    sys.exit(0)


def behavior():
    del CALLS[:]
    assert load(local_path()).render_thumbnail(LEGITIMATE) == "thumb.png"
    rendered = json.dumps(CALLS[0]["args"])
    assert "convert" in rendered and LEGITIMATE in rendered and "200x200" in rendered
    sys.exit(0)


def compare(original_path, repaired_path):
    del CALLS[:]
    load(original_path, "original").render_thumbnail(ATTACK)
    assert CALLS[0]["shell"] is True
    assert "rm -rf /" in CALLS[0]["args"]
    del CALLS[:]
    load(repaired_path, "repaired").render_thumbnail(ATTACK)
    assert CALLS[0]["shell"] is False
    assert CALLS[0]["args"] == ["convert", ATTACK, "-resize", "200x200", "thumb.png"]
    del CALLS[:]
    load(repaired_path, "repaired_legit").render_thumbnail(LEGITIMATE)
    assert CALLS[0]["args"] == ["convert", LEGITIMATE, "-resize", "200x200", "thumb.png"]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
