"""Two invocation modes.

  python3 tests/verify.py --exploit | --behavior   Sandbox mode: checks the app.py in this tree.
  python3 tests/verify.py <original> <repaired>    Harness mode: compares the checked-in trees.
"""
import importlib.util
import json
import os
import sys

LITERAL = "Pa55w0rd-warehouse-2026"
FROM_ENVIRONMENT = "value-from-environment"


def load(path, name="app_under_test"):
    os.environ["WAREHOUSE_DB_PASSWORD"] = FROM_ENVIRONMENT
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def local_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py")


def exploit():
    module = load(local_path())
    if module.DATABASE["password"] != FROM_ENVIRONMENT or LITERAL in source(local_path()):
        sys.stderr.write("vulnerability present: the database password is a literal in the source\n")
        sys.exit(1)
    sys.exit(0)


def behavior():
    module = load(local_path())
    rendered = module.dsn()
    assert rendered.startswith("postgresql://warehouse_app:")
    assert rendered.endswith("@warehouse.internal:5432/warehouse")
    assert module.DATABASE["password"] in rendered
    sys.exit(0)


def compare(original_path, repaired_path):
    original = load(original_path, "original")
    repaired = load(repaired_path, "repaired")
    assert original.DATABASE["password"] == LITERAL
    assert repaired.DATABASE["password"] == FROM_ENVIRONMENT
    assert LITERAL not in source(repaired_path)
    assert repaired.dsn() == (
        "postgresql://warehouse_app:" + FROM_ENVIRONMENT + "@warehouse.internal:5432/warehouse"
    )
    sys.stdout.write(json.dumps({"vulnerability_observed": True, "behavior_preserved": True}))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--exploit":
        exploit()
    elif mode == "--behavior":
        behavior()
    else:
        compare(sys.argv[1], sys.argv[2])
