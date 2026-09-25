"""Unit spec for the Python sandbox harness, run under plain `python3` from tests/test_python_harness.py.

It materializes the harness into a temporary repository exactly as the sandbox does, loads it
as the `harness` module, and exercises every fake and assertion against small vulnerable and
repaired modules. The harness patches process globals (open, os.environ, sys.meta_path), which
is why this runs in its own interpreter rather than inside pytest.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = os.environ.get("MITIG8IT_PYTHON_HARNESS_SOURCE") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "sandbox", "harness_py.py"
)
ROOT = tempfile.mkdtemp(prefix="mitig8it-python-harness-")
os.makedirs(os.path.join(ROOT, ".mitig8it", "regression"))
os.makedirs(os.path.join(ROOT, "services"))
os.makedirs(os.path.join(ROOT, "reports"))
shutil.copyfile(SOURCE, os.path.join(ROOT, ".mitig8it", "harness.py"))


def write(relative, content):
    target = os.path.join(ROOT, relative)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(content)


write("services/vulnerable.py", '''import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify, abort, send_file
from lxml import etree

app = Flask(__name__)
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
API_KEY = "sk-live-aaaaaaaaaaaaaaaa"


@app.route("/orders/<id>")
def order(id):
    cur = sqlite3.connect("orders.db").cursor()
    cur.execute("SELECT id FROM orders WHERE id = '" + id + "'")
    return jsonify(cur.fetchall())


@app.route("/orders/<id>/invoice", methods=["POST"])
def invoice(id):
    return subprocess.check_output("invoice-render --order " + id, shell=True, text=True), 200


@app.route("/reports/download")
def download():
    return send_file(os.path.join(REPORT_DIR, request.args.get("name", "")))


def process_input(raw):
    return eval(raw)


def parse(payload):
    return etree.fromstring(payload)
''')

write("services/repaired.py", '''import ast
import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify, abort, send_file

app = Flask(__name__)
REPORT_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports"))
API_KEY = os.environ["API_KEY"]


@app.route("/orders/<id>")
def order(id):
    cur = sqlite3.connect("orders.db").cursor()
    cur.execute("SELECT id FROM orders WHERE id = ?", (id,))
    return jsonify(cur.fetchall())


@app.route("/orders/<id>/invoice", methods=["POST"])
def invoice(id):
    return subprocess.check_output(["invoice-render", "--order", id], text=True), 200


@app.route("/reports/download")
def download():
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(REPORT_DIR, name))
    if target != REPORT_DIR and not target.startswith(REPORT_DIR + os.sep):
        abort(400)
    return send_file(target)


@app.route("/settings", methods=["POST"])
def settings():
    body = request.get_json()
    return {"ok": True, "retries": body["retries"]}, 201


def process_input(raw):
    return ast.literal_eval(raw)


def secret():
    return os.getenv("SECRET_TOKEN", "")
''')

write("services/drivers.py", '''import psycopg2
from sqlalchemy import create_engine, text


def by_email(email):
    cur = psycopg2.connect("dbname=x").cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    return cur.fetchone()


def by_name(name):
    with create_engine("postgresql://").connect() as conn:
        return conn.execute(text("SELECT id FROM users WHERE name = :name"), {"name": name}).fetchall()


def shell(name):
    import os
    return os.system("ls " + name)
''')

write(".mitig8it/regression/passing.test.py", '''import harness as h


def body():
    m = h.load("services/repaired.py", env={"API_KEY": "from-env"})
    bad = "1' OR '1'='1"
    h.invoke(m.app, "GET", "/orders/<id>", params={"id": bad})
    h.assert_param(h.db.queries[0], bad)


h.run(body)
''')
write(".mitig8it/regression/failing.test.py", '''import harness as h


def body():
    m = h.load("services/vulnerable.py")
    bad = "1' OR '1'='1"
    h.invoke(m.app, "GET", "/orders/<id>", params={"id": bad})
    h.assert_param(h.db.queries[0], bad)


h.run(body)
''')

# A module inside a package that reaches a sibling through a relative import. pygoat's
# `introduction/views.py` is this shape, and the proof for its path finding failed on both trees
# with `attempted relative import with no known parent package` before the harness gave the
# module a package to be relative to.
write("introduction/forms.py", '''SAFE_NAME = "report.txt"
''')
write("introduction/__init__.py", '''raise AssertionError("the package __init__ must not run")
''')
write("introduction/views.py", '''import os

from .forms import SAFE_NAME

BASE = os.path.dirname(os.path.abspath(__file__))


def read(name):
    with open(os.path.join(BASE, name)) as handle:
        return handle.read()
''')

spec = importlib.util.spec_from_file_location("harness", os.path.join(ROOT, ".mitig8it", "harness.py"))
h = importlib.util.module_from_spec(spec)
sys.modules["harness"] = h
spec.loader.exec_module(h)


class HarnessSpec(unittest.TestCase):
    def test_root_is_the_repository_the_harness_was_materialized_in(self):
        self.assertEqual(os.path.realpath(h.ROOT), os.path.realpath(ROOT))
        self.assertEqual(h.version, 1)

    def test_sql_parameterization_assertion(self):
        bad = "1' OR '1'='1"
        m = h.load("services/vulnerable.py")
        h.invoke(m.app, "GET", "/orders/<id>", params={"id": bad})
        self.assertEqual(h.db.queries[0]["api"], "sqlite3")
        self.assertIn(bad, h.db.queries[0]["sql"])
        with self.assertRaises(h.HarnessAssertion):
            h.assert_param(h.db.queries[0], bad)
        m = h.load("services/repaired.py", env={"API_KEY": "x"}, rows=[(7,)])
        response = h.invoke(m.app, "GET", "/orders/7")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [[7]])
        h.invoke(m.app, "GET", "/orders/<id>", params={"id": bad})
        h.assert_param(h.db.queries[-1], bad)
        self.assertEqual(h.db.queries[-1]["params"], (bad,))

    def test_psycopg_and_sqlalchemy_record_bound_parameters(self):
        m = h.load("services/drivers.py")
        m.by_email("a@example.com")
        m.by_name("bob")
        self.assertEqual([q["api"] for q in h.db.queries], ["psycopg2", "sqlalchemy"])
        h.assert_param(h.db.queries[0], "a@example.com")
        h.assert_param(h.db.queries[1], "bob")
        self.assertEqual(h.db.queries[1]["sql"], "SELECT id FROM users WHERE name = :name")

    def test_command_argument_assertion(self):
        payload = "x; rm -rf /"
        m = h.load("services/vulnerable.py", stdout="rendered")
        response = h.invoke(m.app, "POST", "/orders/<id>/invoice", params={"id": payload})
        self.assertEqual((response.status_code, response.body), (200, "rendered"))
        self.assertTrue(h.subprocess.calls[0]["shell"])
        with self.assertRaises(h.HarnessAssertion):
            h.assert_argv(h.subprocess.calls[0], payload)
        m = h.load("services/repaired.py", env={"API_KEY": "x"}, stdout="rendered")
        h.invoke(m.app, "POST", "/orders/<id>/invoice", params={"id": payload})
        h.assert_argv(h.subprocess.calls[0], payload)
        self.assertEqual(h.subprocess.calls[0]["args"], ["invoice-render", "--order", payload])
        m = h.load("services/drivers.py")
        m.shell("x")
        self.assertEqual(h.subprocess.calls[0]["fn"], "os.system")
        with self.assertRaises(h.HarnessAssertion):
            h.assert_no_commands()

    def test_path_containment_assertion(self):
        base = os.path.join(ROOT, "reports")
        for payload in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd"):
            m = h.load("services/vulnerable.py", content="secret")
            h.fs.reads.clear()
            response = h.invoke(m.app, "GET", "/reports/download", query={"name": payload})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(h.fs.reads), 1)
            with self.assertRaises(h.HarnessAssertion):
                h.assert_inside(h.fs.reads, base, payload=payload)
            m = h.load("services/repaired.py", env={"API_KEY": "x"}, content="secret")
            h.fs.reads.clear()
            response = h.invoke(m.app, "GET", "/reports/download", query={"name": payload})
            self.assertEqual(response.status_code, 400)
            h.assert_inside(h.fs.reads, base, payload=payload)
        h.fs.reads.clear()
        response = h.invoke(m.app, "GET", "/reports/download", query={"name": "q1.csv"})
        self.assertEqual((response.status_code, response.body), (200, b"secret"))
        h.assert_inside(h.fs.reads, base)
        with self.assertRaises(h.HarnessAssertion):
            h.assert_inside(h.fs.reads, os.path.join(ROOT, "elsewhere"))

    def test_hardcoded_credential_assertion(self):
        literal = "sk-live-aaaaaaaaaaaaaaaa"
        m = h.load("services/vulnerable.py", env={"API_KEY": "from-env"})
        self.assertEqual(m.API_KEY, literal)
        with self.assertRaises(h.HarnessAssertion):
            h.assert_env_read("API_KEY")
        with self.assertRaises(h.HarnessAssertion):
            h.assert_not_in_source(m, literal)
        m = h.load("services/repaired.py", env={"API_KEY": "from-env", "SECRET_TOKEN": "t"})
        h.assert_equal(m.API_KEY, "from-env")
        h.assert_env_read("API_KEY")
        h.assert_not_in_source(m, literal)
        self.assertEqual(m.secret(), "t")
        h.assert_env_read("SECRET_TOKEN")

    def test_eval_assertion(self):
        payload = "__import__('os').system('id')"
        m = h.load("services/vulnerable.py")
        result = h.call(m.process_input, payload)
        self.assertTrue(result.ok)
        self.assertEqual(h.subprocess.calls[0]["command"], "id")
        with self.assertRaises(h.HarnessAssertion):
            h.assert_no_commands()
        m = h.load("services/repaired.py", env={"API_KEY": "x"})
        result = h.call(m.process_input, payload)
        self.assertFalse(result.ok)
        self.assertTrue(result.raised(ValueError))
        h.assert_no_commands()
        h.assert_equal(h.call(m.process_input, "[1, 2]").value, [1, 2])

    def test_flask_invoke_covers_json_bodies_tuples_and_missing_routes(self):
        m = h.load("services/repaired.py", env={"API_KEY": "x"})
        response = h.invoke(m.app, "POST", "/settings", json={"retries": 3})
        self.assertEqual((response.status_code, response.get_json()), (201, {"ok": True, "retries": 3}))
        with self.assertRaises(h.HarnessAssertion):
            h.invoke(m.app, "DELETE", "/settings")
        self.assertEqual([r["rule"] for r in h.flask.routes], ["/orders/<id>", "/orders/<id>/invoice", "/reports/download", "/settings"])

    def test_third_party_imports_the_sandbox_lacks_are_stubbed_and_recorded(self):
        m = h.load("services/vulnerable.py")
        self.assertEqual(h.stubbed, ["lxml"])
        self.assertIn("stub", repr(m.parse(b"<x/>")))
        import json as real_json

        self.assertTrue(hasattr(real_json, "dumps"))
        with self.assertRaises(h.HarnessAssertion):
            h.load("services/missing.py")

    def test_a_module_inside_a_package_resolves_its_own_relative_imports(self):
        m = h.load("introduction/views.py")
        self.assertEqual(m.SAFE_NAME, "report.txt")
        self.assertEqual(m.__name__, "introduction.views")
        # The package is synthetic: its __init__ would have raised had the harness run it.
        self.assertEqual(sys.modules["introduction"].__path__, [os.path.join(ROOT, "introduction")])
        # The next load clears it, so one proof cannot see the module another one imported.
        h.load("services/vulnerable.py")
        self.assertNotIn("introduction.views", sys.modules)

    def test_runner_exit_semantics(self):
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        harness = os.path.join(".mitig8it", "harness.py")
        passing = subprocess.run([sys.executable, harness, ".mitig8it/regression/passing.test.py"], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(passing.returncode, 0, passing.stderr)
        self.assertIn("harness: ok", passing.stdout)
        failing = subprocess.run([sys.executable, harness, ".mitig8it/regression/failing.test.py"], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(failing.returncode, 1)
        self.assertIn("HarnessAssertion", failing.stderr)
        self.assertIn("reached the SQL text", failing.stderr)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
