"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

The token is read through a helper, so the repair has to keep the header shape the helper
builds while taking the value from the environment. No request is ever sent.
"""
import importlib.util
import json
import os
import sys

LITERAL = "ntfy-7c1f0b9a4d2e6853"
FROM_ENVIRONMENT = "value-from-environment"
URL = "https://notify.internal/v1/events"


def load(path, name="app_under_test"):
    os.environ["NOTIFY_TOKEN"] = FROM_ENVIRONMENT
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def headers_of(module):
    request = module.build_request(URL, {"event": "deploy"})
    return {str(key).lower(): value for key, value in request.headers.items()}


def exploit():
    module = load(local_path())
    if module.NOTIFY_TOKEN != FROM_ENVIRONMENT or LITERAL in source(local_path()):
        sys.stderr.write("vulnerability present: the service token is a literal in the source\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    module = load(local_path())
    headers = headers_of(module)
    assert headers["authorization"] == "Token " + module.NOTIFY_TOKEN
    assert headers["content-type"] == "application/json"
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    repaired = load(repaired_path, "repaired")
    assert original.NOTIFY_TOKEN == LITERAL
    assert headers_of(original)["authorization"] == "Token " + LITERAL
    assert repaired.NOTIFY_TOKEN == FROM_ENVIRONMENT
    assert LITERAL not in source(repaired_path)
    assert headers_of(repaired) == {
        "authorization": "Token " + FROM_ENVIRONMENT,
        "content-type": "application/json",
    }
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
