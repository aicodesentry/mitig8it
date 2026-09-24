"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

os.system is replaced with a recorder before the module under test is imported, so the payload
records a command instead of running one.
"""
import importlib.util
import json
import os
import sys

PAYLOAD = "__import__('os').system('id')"
LITERAL = "{'discount': 10, 'tiers': [1, 2]}"
EXPECTED = {"discount": 10, "tiers": [1, 2]}
EXECUTED = []


def stub_system(command):
    EXECUTED.append(command)
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
        return module.parse_rule(raw)
    except (ValueError, SyntaxError, KeyError, TypeError):
        return None


def exploit():
    del EXECUTED[:]
    module = load(local_path())
    attempt(module, PAYLOAD)
    if EXECUTED:
        sys.stderr.write("vulnerability present: the payload ran a system command\n")
        sys.exit(1)
    assert module.parse_rule(LITERAL) == EXPECTED
    sys.exit(0)


def behavior():
    module = load(local_path())
    assert module.parse_rule(LITERAL) == EXPECTED
    assert module.parse_rule("[1, 2]") == [1, 2]
    sys.exit(0)


def compare(original_path, repaired_path):
    del EXECUTED[:]
    attempt(load(original_path, "original"), PAYLOAD)
    assert EXECUTED == ["id"]
    del EXECUTED[:]
    repaired = load(repaired_path, "repaired")
    attempt(repaired, PAYLOAD)
    assert EXECUTED == []
    assert repaired.parse_rule(LITERAL) == EXPECTED
    assert repaired.parse_rule("[1, 2]") == [1, 2]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
