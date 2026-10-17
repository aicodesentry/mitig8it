"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the shop/settings.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

The settings module is loaded on its own, as Django does, and SESSION_COOKIE_SECURE is read back from it.
"""
import importlib.util
import json
import os
import sys


def load(path, name="settings_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shop/settings.py")


def kept(m):
    assert m.SESSION_COOKIE_AGE == 1209600
    assert m.ALLOWED_HOSTS == ["shop.example.com"]


def exploit():
    m = load(local_path())
    if m.SESSION_COOKIE_SECURE is not True:
        sys.stderr.write("vulnerability present: SESSION_COOKIE_SECURE is not True\n")
        sys.exit(1)
    kept(m)
    sys.exit(0)


def behavior():
    kept(load(local_path()))
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    assert original.SESSION_COOKIE_SECURE is False
    kept(original)
    repaired = load(repaired_path, "repaired")
    assert repaired.SESSION_COOKIE_SECURE is True
    kept(repaired)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
