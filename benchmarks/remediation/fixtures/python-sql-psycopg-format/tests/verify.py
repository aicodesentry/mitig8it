"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import sys
import types

ATTACK = "open' OR '1'='1"
LEGITIMATE = "open"
ROWS = [(11, "Printer jam")]

psycopg = types.ModuleType("psycopg")
psycopg.connect = lambda dsn: None
sys.modules.setdefault("psycopg", psycopg)


class RecordingCursor:
    def __init__(self):
        self.queries = []

    def execute(self, sql, params=None):
        self.queries.append((str(sql), params))
        return self

    def fetchall(self):
        return list(ROWS)


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    cursor = RecordingCursor()
    load(local_path()).find_tickets(cursor, ATTACK)
    sql, params = cursor.queries[0]
    if ATTACK in sql:
        sys.stderr.write("vulnerability present: untrusted input is interpolated into SQL text\n")
        sys.exit(1)
    assert params is not None and ATTACK in list(params)
    sys.exit(0)


def behavior():
    cursor = RecordingCursor()
    rows = load(local_path()).find_tickets(cursor, LEGITIMATE)
    sql, params = cursor.queries[0]
    assert "FROM tickets" in sql
    assert LEGITIMATE in sql or (params is not None and LEGITIMATE in list(params))
    assert rows == ROWS
    sys.exit(0)


def compare(original_path, repaired_path):
    original, repaired, legitimate = RecordingCursor(), RecordingCursor(), RecordingCursor()
    load(original_path, "original").find_tickets(original, ATTACK)
    load(repaired_path, "repaired").find_tickets(repaired, ATTACK)
    load(repaired_path, "repaired_legit").find_tickets(legitimate, LEGITIMATE)
    assert "OR '1'='1" in original.queries[0][0]
    assert repaired.queries[0] == ("SELECT id, subject FROM tickets WHERE status = %s", (ATTACK,))
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
