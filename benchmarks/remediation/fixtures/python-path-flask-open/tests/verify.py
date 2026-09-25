"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import builtins
import importlib.util
import io
import json
import os
import sys
import types

ATTACK = "../../etc/passwd"
LEGITIMATE = "2024/march.pdf"
BASE = "/srv/invoices"

class HTTPError(Exception):
    def __init__(self, code):
        Exception.__init__(self, str(code))
        self.code = code


class FakeRequest:
    def __init__(self):
        self.args = {}


REQUEST = FakeRequest()
ROUTES = {}
READS = []


def route(rule, **kwargs):
    def decorate(view):
        ROUTES[rule] = view
        return view

    return decorate


class FakeFlask:
    def __init__(self, name):
        self.name = name

    route = staticmethod(route)


def send_file(target, **kwargs):
    with open_recorded(target) as handle:
        return handle.read()


def open_recorded(target, mode="rb"):
    READS.append(str(target))
    return io.BytesIO(b"%PDF-1.4 fixture")


flask = types.ModuleType("flask")
flask.Flask = FakeFlask
flask.request = REQUEST
flask.abort = lambda code, *a, **k: (_ for _ in ()).throw(HTTPError(code))
flask.send_file = send_file
sys.modules.setdefault("flask", flask)
builtins.open = lambda target, mode="r", *a, **k: open_recorded(target, mode)

def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def fetch(module, name):
    del READS[:]
    REQUEST.args = {"name": name}
    try:
        return module and ROUTES["/invoices"](), None
    except HTTPError as error:
        return None, error.code


def exploit():
    module = load(local_path())
    fetch(module, ATTACK)
    escaped = [item for item in READS if not os.path.normpath(item).startswith(BASE + os.sep)]
    if escaped:
        sys.stderr.write("vulnerability present: the resolved path escapes the base directory\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    module = load(local_path())
    body, code = fetch(module, LEGITIMATE)
    assert code is None and body is not None
    assert READS and os.path.normpath(READS[0]) == os.path.join(BASE, LEGITIMATE)
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    ROUTES.clear()
    load(original_path, "original_again")
    fetch(original, ATTACK)
    assert os.path.normpath(READS[0]) == "/etc/passwd"
    ROUTES.clear()
    repaired = load(repaired_path, "repaired")
    body, code = fetch(repaired, ATTACK)
    assert READS == [] and code == 400
    body, code = fetch(repaired, LEGITIMATE)
    assert code is None and os.path.normpath(READS[0]) == os.path.join(BASE, LEGITIMATE)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
