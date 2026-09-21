"""Abstention fixture: the checks exist so the verification profile is complete, but the
query is handed to a helper whose placeholder syntax the snapshot does not show, so no
candidate should reach them.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
"""
import importlib.util
import os
import sys
import types

ATTACK = "1 OR 1=1"
observed = []

storage = types.ModuleType("storage")
storage.execute_query = lambda query: observed.append(str(query)) or []
sys.modules["storage"] = storage


def load_local():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")
    spec = importlib.util.spec_from_file_location("app_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exploit():
    load_local().get_user(ATTACK)
    if ATTACK in observed[0]:
        sys.stderr.write("vulnerability present: untrusted input is interpolated into the statement\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    load_local().get_user("7")
    assert "FROM users" in observed[0]
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
