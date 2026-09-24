"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

Two vulnerable statements live in this one file, a concatenation and an f-string, so a repair
that parameterizes only one of them leaves the exploit check failing.
"""
import importlib.util
import json
import os
import sys

ATTACK = "acct-1' OR '1'='1"
LEGITIMATE = "acct-4821"
ROWS = [(1, "first"), (2, "second")]


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


def load(path, name="app_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def collect(module, account):
    conn = RecordingConnection()
    module.contacts_for_account(conn, account)
    module.notes_for_account(conn, account)
    return conn.queries


def exploit():
    queries = collect(load(local_path()), ATTACK)
    interpolated = [sql for sql, _ in queries if ATTACK in sql]
    if interpolated:
        sys.stderr.write(
            "vulnerability present: %d statement(s) interpolate untrusted input into SQL text\n" % len(interpolated)
        )
        sys.exit(1)
    assert len(queries) == 2
    for _, params in queries:
        assert params is not None and ATTACK in list(params)
    sys.exit(0)


def behavior():
    queries = collect(load(local_path()), LEGITIMATE)
    assert len(queries) == 2
    assert "FROM contacts" in queries[0][0]
    assert "FROM notes" in queries[1][0]
    for sql, params in queries:
        assert LEGITIMATE in sql or (params is not None and LEGITIMATE in list(params))
    sys.exit(0)


def compare(original_path, repaired_path):
    original = collect(load(original_path, "original"), ATTACK)
    assert len([sql for sql, _ in original if ATTACK in sql]) == 2
    repaired = collect(load(repaired_path, "repaired"), ATTACK)
    assert repaired == [
        ("SELECT id, email FROM contacts WHERE account = ?", (ATTACK,)),
        ("SELECT id, body FROM notes WHERE account = ?", (ATTACK,)),
    ]
    legitimate = collect(load(repaired_path, "repaired_legit"), LEGITIMATE)
    assert [params for _, params in legitimate] == [(LEGITIMATE,), (LEGITIMATE,)]
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
