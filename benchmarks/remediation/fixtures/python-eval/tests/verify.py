"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import sys

PAYLOAD = "__import__('os').system('id')"
LITERAL = "{'retries': 3, 'hosts': ['a', 'b']}"
EXPECTED = {"retries": 3, "hosts": ["a", "b"]}
executed = []


def stub_system(command):
    executed.append(command)
    return 0


os.system = stub_system


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def attempt(module, raw):
    try:
        return module.parse_settings(raw)
    except (ValueError, SyntaxError):
        return None


def exploit():
    module = load(local_path())
    attempt(module, PAYLOAD)
    if executed:
        sys.stderr.write("vulnerability present: the payload ran a system command\n")
        sys.exit(1)
    assert module.parse_settings(LITERAL) == EXPECTED
    sys.exit(0)


def behavior():
    module = load(local_path())
    assert module.parse_settings(LITERAL) == EXPECTED
    assert module.parse_settings("[1, 2]") == [1, 2]
    sys.exit(0)


def compare(original_path, repaired_path):
    attempt(load(original_path, "original"), PAYLOAD)
    assert executed == ["id"]
    del executed[:]
    repaired = load(repaired_path, "repaired")
    attempt(repaired, PAYLOAD)
    assert executed == []
    assert repaired.parse_settings(LITERAL) == EXPECTED
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
