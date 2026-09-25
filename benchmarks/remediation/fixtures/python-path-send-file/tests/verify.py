"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

Flask is not installed in the sandbox, so the module is replaced by recording doubles before
the module under test is imported. send_file records the path it was handed; it opens nothing.
"""
import importlib.util
import json
import os
import sys
import types

ATTACK = "../../etc/passwd"
LEGITIMATE = "2026/march.pdf"
BASE = "/srv/reports"
SENT = []
ROUTES = {}


class HTTPError(Exception):
    def __init__(self, code):
        Exception.__init__(self, str(code))
        self.code = code


class FakeRequest:
    def __init__(self):
        self.args = {}


REQUEST = FakeRequest()


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
    SENT.append(str(target))
    return b"%PDF-1.4 fixture"


flask = types.ModuleType("flask")
flask.Flask = FakeFlask
flask.request = REQUEST
flask.abort = lambda code, *a, **k: (_ for _ in ()).throw(HTTPError(code))
flask.send_file = send_file
sys.modules.setdefault("flask", flask)


def load(path, name="app_under_test"):
    ROUTES.clear()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def fetch(name):
    del SENT[:]
    REQUEST.args = {"name": name}
    try:
        return ROUTES["/reports"](), None
    except HTTPError as error:
        return None, error.code


def exploit():
    load(local_path())
    fetch(ATTACK)
    escaped = [item for item in SENT if not os.path.normpath(item).startswith(BASE + os.sep)]
    if escaped:
        sys.stderr.write("vulnerability present: the resolved path escapes the report directory\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    load(local_path())
    body, code = fetch(LEGITIMATE)
    assert code is None and body is not None
    assert SENT and os.path.normpath(SENT[0]) == os.path.join(BASE, LEGITIMATE)
    sys.exit(0)


def compare(original_path, repaired_path):
    load(original_path, "original")
    fetch(ATTACK)
    assert os.path.normpath(SENT[0]) == "/etc/passwd"
    load(repaired_path, "repaired")
    body, code = fetch(ATTACK)
    assert SENT == [] and code == 400
    body, code = fetch(LEGITIMATE)
    assert code is None and os.path.normpath(SENT[0]) == os.path.join(BASE, LEGITIMATE)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
