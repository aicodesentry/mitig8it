"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import sys

ATTACK = "../../etc/passwd"
LEGITIMATE = "invoice.txt"
BASE = "/srv/attachments"


def load(path):
    spec = importlib.util.spec_from_file_location("fixture_app_%d" % abs(hash(path)), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve(module, name):
    """(escaped, value): a repair may refuse by raising; what it may not do is hand back a path
    outside the base directory.

    The value is normalised before it is judged, because `os.path.join` keeps the `..` segments
    verbatim: the unrepaired helper returns a string that still starts with the base directory and
    names a file well outside it.
    """
    try:
        value = module.resolve_attachment(name)
    except Exception:
        return False, None
    resolved = os.path.normpath(str(value))
    return resolved != BASE and not resolved.startswith(BASE + os.sep), value


def local():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def exploit():
    escaped, _ = resolve(load(local()), ATTACK)
    if escaped:
        sys.stderr.write("vulnerability present: the resolved path escapes the base directory\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    escaped, value = resolve(load(local()), LEGITIMATE)
    assert not escaped, "a legitimate name must stay inside the base directory"
    assert value == os.path.join(BASE, LEGITIMATE), value
    sys.exit(0)


def compare(original_path, repaired_path):
    original_escaped, original_value = resolve(load(original_path), ATTACK)
    repaired_escaped, _ = resolve(load(repaired_path), ATTACK)
    legitimate_escaped, legitimate_value = resolve(load(repaired_path), LEGITIMATE)
    assert original_escaped, "the original resolves outside the base directory"
    assert os.path.normpath(str(original_value)) == "/etc/passwd", original_value
    assert not repaired_escaped, "the repair must not resolve outside the base directory"
    assert not legitimate_escaped and legitimate_value == os.path.join(BASE, LEGITIMATE)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
