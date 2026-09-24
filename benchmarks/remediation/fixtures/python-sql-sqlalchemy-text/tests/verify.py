"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.

SQLAlchemy is not installed in the sandbox, so `text` and `create_engine` are replaced by
recording doubles before the module under test is imported.
"""
import importlib.util
import json
import os
import sys
import types

ATTACK = "eu' OR '1'='1"
LEGITIMATE = "eu-west"
ROWS = [("eu-west", 1200)]
QUERIES = []


class Statement:
    def __init__(self, sql):
        self.sql = str(sql)

    def __str__(self):
        return self.sql


class RecordingEngine:
    def execute(self, statement, parameters=None):
        QUERIES.append((str(statement), parameters))
        return self

    def fetchall(self):
        return list(ROWS)


sqlalchemy = types.ModuleType("sqlalchemy")
sqlalchemy.text = Statement
sqlalchemy.create_engine = lambda url: RecordingEngine()
sys.modules.setdefault("sqlalchemy", sqlalchemy)


def load(path, name="app_under_test"):
    del QUERIES[:]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    load(local_path()).revenue_by_region(ATTACK)
    sql, params = QUERIES[0]
    if ATTACK in sql:
        sys.stderr.write("vulnerability present: untrusted input is interpolated into SQL text\n")
        sys.exit(1)
    assert params is not None and ATTACK in list(params.values())
    sys.exit(0)


def behavior():
    rows = load(local_path()).revenue_by_region(LEGITIMATE)
    sql, params = QUERIES[0]
    assert "FROM orders" in sql and "GROUP BY region" in sql
    assert LEGITIMATE in sql or (params is not None and LEGITIMATE in list(params.values()))
    assert rows == ROWS
    sys.exit(0)


def compare(original_path, repaired_path):
    load(original_path, "original").revenue_by_region(ATTACK)
    assert "OR '1'='1" in QUERIES[0][0]
    repaired = load(repaired_path, "repaired")
    repaired.revenue_by_region(ATTACK)
    assert QUERIES[0] == (
        "SELECT region, SUM(total) FROM orders WHERE region = :region GROUP BY region",
        {"region": ATTACK},
    )
    load(repaired_path, "repaired_legit").revenue_by_region(LEGITIMATE)
    assert QUERIES[0][1] == {"region": LEGITIMATE}
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
