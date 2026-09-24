"""Abstention fixture: the shell pipeline's quoting and output semantics are undocumented,
so an argv rewrite may change what the dashboard reads; no candidate should reach these checks.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
"""
import importlib.util
import os
import subprocess
import sys

ATTACK = "api; rm -rf /"
CALLS = []


def recording_check_output(args, **kwargs):
    CALLS.append({"args": args, "shell": bool(kwargs.get("shell"))})
    return "3\n"


subprocess.check_output = recording_check_output


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    del CALLS[:]
    load(local_path()).error_counts(ATTACK)
    call = CALLS[0]
    if call["shell"] or isinstance(call["args"], str):
        sys.stderr.write("vulnerability present: the argument reaches a shell command string\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    del CALLS[:]
    assert load(local_path()).error_counts("api") == "3\n"
    assert "journalctl" in str(CALLS[0]["args"])
    sys.exit(0)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        sys.stderr.write("this abstention fixture has no reference repair to compare\n")
        sys.exit(2)
