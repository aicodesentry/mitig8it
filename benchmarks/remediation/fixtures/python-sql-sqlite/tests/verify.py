"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import sys

ATTACK = "x' OR '1'='1"
LEGITIMATE = "person@example.com"


class RecordingCursor:
    def __init__(self, queries):
        self.queries = queries

    def execute(self, sql, params=None):
        self.queries.append((str(sql), params))
        return self

    def fetchone(self):
        return (1, LEGITIMATE)


class RecordingConnection:
    def __init__(self):
        self.queries = []

    def cursor(self):
        return RecordingCursor(self.queries)


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_local():
    return load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py"))


def exploit():
    conn = RecordingConnection()
    load_local().find_user(conn, ATTACK)
    sql, params = conn.queries[0]
    if ATTACK in sql:
        sys.stderr.write("vulnerability present: untrusted input is interpolated into SQL text\n")
        sys.exit(1)
    assert params is not None and ATTACK in list(params)
    sys.exit(0)


def behavior():
    conn = RecordingConnection()
    row = load_local().find_user(conn, LEGITIMATE)
    sql, params = conn.queries[0]
    assert "FROM users" in sql
    assert LEGITIMATE in sql or (params is not None and LEGITIMATE in list(params))
    assert row == (1, LEGITIMATE)
    sys.exit(0)


def compare(original_path, repaired_path):
    original, repaired = RecordingConnection(), RecordingConnection()
    load(original_path, "original").find_user(original, ATTACK)
    load(repaired_path, "repaired").find_user(repaired, ATTACK)
    legitimate = RecordingConnection()
    load(repaired_path, "repaired_legit").find_user(legitimate, LEGITIMATE)
    assert "OR '1'='1" in original.queries[0][0]
    assert repaired.queries[0] == ("SELECT id, email FROM users WHERE email = ?", (ATTACK,))
    assert legitimate.queries[0][1] == (LEGITIMATE,)
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
