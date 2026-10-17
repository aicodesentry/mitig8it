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


def run(m):
    views["/remember"]()
    found = [cookie for cookie in cookies if cookie["name"] == "remember_token"]
    assert found, "expected the remember_token cookie to be set"
    return found[0]


def vulnerable(cookie):
    return cookie["secure"] is not True or cookie["httponly"] is not True or str(cookie["samesite"]).lower() not in ("lax", "strict")


def kept(cookie):
    assert cookie["max_age"] == 3600
    assert len(cookie["value"]) == 32


def exploit():
    cookie = run(load(local_path()))
    if vulnerable(cookie):
        sys.stderr.write("vulnerability present: the cookie is missing Secure, HttpOnly or SameSite\n")
        sys.exit(1)
    kept(cookie)
    sys.exit(0)


def behavior():
    kept(run(load(local_path())))
    sys.exit(0)


def compare(original_path, repaired_path):
    original = run(load(original_path, "original"))
    assert vulnerable(original)
    kept(original)
    repaired = run(load(repaired_path, "repaired"))
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
