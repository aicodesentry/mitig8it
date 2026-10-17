"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

Flask is stood in for here, because nothing is installed: the stand-in keeps the application's
config, records its routes, and records every cookie a response sets with its flags.
"""
import importlib.util
import json
import os
import sys
import types

cookies = []
views = {}


class Response:
    def __init__(self, body=""):
        self.body = body

    def set_cookie(self, key, value="", max_age=None, expires=None, path="/", domain=None, secure=False, httponly=False, samesite=None):
        cookies.append({"name": key, "value": value, "max_age": max_age, "secure": secure, "httponly": httponly, "samesite": samesite})


class Flask:
    def __init__(self, name):
        self.config = {}

    def route(self, rule, **options):
        def decorator(view):
            views[rule] = view
            return view
        return decorator


flask = types.ModuleType("flask")
flask.Flask, flask.make_response = Flask, Response
flask.request = types.SimpleNamespace(args={"user": "u"}, form={"user": "u"})
sys.modules["flask"] = flask


def load(path, name="app_under_test"):
    del cookies[:]
    views.clear()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def vulnerable(m):
    return m.app.config["SESSION_COOKIE_HTTPONLY"] is not True


def kept(m):
    assert m.app.config["SESSION_COOKIE_NAME"] == "tracker_session"
    assert views["/health"]() == "ok"


def exploit():
    m = load(local_path())
    if vulnerable(m):
        sys.stderr.write("vulnerability present: SESSION_COOKIE_HTTPONLY is not True\n")
        sys.exit(1)
    kept(m)
    sys.exit(0)


def behavior():
    kept(load(local_path()))
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    assert vulnerable(original)
    kept(original)
    repaired = load(repaired_path, "repaired")
    assert not vulnerable(repaired)
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
