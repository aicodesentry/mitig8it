"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the security.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

The password is vulnerable when hashing it twice gives the same value, or when that value is a
fast digest of it. Behaviour is the module's own verifier accepting the right password and
rejecting a wrong one against a hash the module produced.
"""
import base64
import hashlib
import importlib.util
import json
import os
import sys

PASSWORD = "correct horse battery staple"


def load(path, name="module_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security.py")


def fast_digest(value):
    for algorithm in ("md5", "sha1", "sha256", "sha512"):
        raw = hashlib.new(algorithm, PASSWORD.encode()).digest()
        if value in (raw.hex(), base64.b64encode(raw).decode()):
            return True
    return False


def vulnerable(m):
    first = m.hash_pwd(PASSWORD)
    return first == m.hash_pwd(PASSWORD) or fast_digest(first)


def verifies(m, password, stored):
    return bool(m.is_valid(password, stored))


def behaves(m):
    stored = m.hash_pwd(PASSWORD)
    assert verifies(m, PASSWORD, stored) is True
    assert verifies(m, "wrong horse battery staple", stored) is False


def exploit():
    m = load(local_path())
    if vulnerable(m):
        sys.stderr.write("vulnerability present: the password is stored as an unsalted fast digest\n")
        sys.exit(1)
    behaves(m)
    sys.exit(0)


def behavior():
    behaves(load(local_path()))
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    assert vulnerable(original)
    behaves(original)
    repaired = load(repaired_path, "repaired")
    assert not vulnerable(repaired)
    behaves(repaired)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
