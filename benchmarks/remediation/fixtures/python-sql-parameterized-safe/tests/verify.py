"""Abstention fixture: the statement is already parameterized, so the exploit check cannot
demonstrate a vulnerability on the baseline tree and no candidate can be verified.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
"""
import importlib.util
import os
import sys

ATTACK = "root' OR '1'='1"
LEGITIMATE = "amina"
ROWS = [(3, "login")]


class RecordingCursor:
    def __init__(self, queries):
        self.queries = queries

    def execute(self, sql, params=None):
        self.queries.append((str(sql), params))
        return self

    def fetchall(self):
        return list(ROWS)


class RecordingConnection:
    def __init__(self):
        self.queries = []

    def cursor(self):
        return RecordingCursor(self.queries)


def load_local():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")
    spec = importlib.util.spec_from_file_location("app_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exploit():
    conn = RecordingConnection()
    load_local().events_for_actor(conn, ATTACK)
    sql, params = conn.queries[0]
    if ATTACK in sql:
        sys.stderr.write("vulnerability present: untrusted input is interpolated into SQL text\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    conn = RecordingConnection()
    rows = load_local().events_for_actor(conn, LEGITIMATE)
    assert "FROM audit_events" in conn.queries[0][0]
    assert rows == ROWS
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
