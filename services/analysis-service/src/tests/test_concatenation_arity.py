"""A concatenation sink must be found however many pieces the string was built from.

This file exists because of a defect found on a real pull request. The rule that catches SQL
built by concatenation was written as `$CURSOR.execute("..." + $INPUT)`, with a second clause
for `"..." + $INPUT + "..."`. Both pin a string literal to one operand position, so they match
a two-piece and a three-piece string and nothing longer. Python parses `a + b + c + d` as
`((a + b) + c) + d`, so the outermost left operand of a four-piece string is another
concatenation rather than a literal, and the clause cannot bind.

The shape that got past it was ordinary:

    cursor.execute("SELECT * FROM orders WHERE status = '" + status + "' ORDER BY " + sort_column)

Four pieces, two injected values, the most natural way to write the bug. It was reported by
nothing, on a pull request where that file's two-piece and three-piece siblings were all
reported. JavaScript was worse: its SQL and `exec` rules held only the two-piece clause, so a
three-piece string was already enough to pass unseen. Every language pack had the same flaw,
and C# reported none of these at all.

The fix is the deep expression operator, `<... "..." + $INPUT ...>`, which asks whether a
literal is concatenated with something anywhere inside the argument rather than at one position
in it. That is a property of the argument, so arity stops mattering.

What is asserted here is the property, not the fix: every concatenation sink is reported at two
through six pieces, and the parameterised form of the same statement is not. A rule rewritten
later in some other way passes this file unchanged. A rule that reacquires a position-pinned
clause fails it, which is the point.

Each statement carries a unique name, and the assertions are written against the code snippet
the finding reports rather than against a line number, so the test does not depend on how a
patch maps onto file lines.
"""
from __future__ import annotations

import pytest

from opengrep_runner import run_opengrep, scanner_available

pytestmark = pytest.mark.skipif(
    not scanner_available(), reason="the AST scanner is not installed in this environment"
)


def _added_patch(text: str) -> str:
    lines = text.split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join(f"+{line}" for line in lines)


def _reported_snippets(path: str, text: str) -> list[str]:
    findings = run_opengrep(
        [
            {
                "path": path,
                "patch": _added_patch(text),
                "content": text,
                "reviewable_line_spans": [],
            }
        ]
    )
    return [str(f.get("code_snippet") or "") for f in findings]


# Each sink is named for the number of pieces its string is built from, so `sink_four` is the
# four-piece case. `bound_*` is the same statement with the value passed as a parameter, which
# is what the finding on the concatenated form tells a reader to do.

PYTHON_SQL = '''\
import sqlite3

cursor = sqlite3.connect(":memory:").cursor()


def two(a):
    cursor.execute("SELECT * FROM sink_two WHERE x = " + a)


def three(a):
    cursor.execute("SELECT * FROM sink_three WHERE x = '" + a + "'")


def four(a, b):
    cursor.execute("SELECT * FROM sink_four WHERE x = '" + a + "' ORDER BY " + b)


def five(a, b):
    cursor.execute("SELECT * FROM sink_five WHERE x = '" + a + "' AND y = '" + b + "'")


def six(a, b, c):
    cursor.execute("SELECT " + a + " FROM sink_six WHERE x = " + b + " ORDER BY " + c)


def bound(a):
    cursor.execute("SELECT * FROM bound_query WHERE x = ?", (a,))


def literal():
    cursor.execute("SELECT * FROM bound_literal")
'''

PYTHON_COMMAND = '''\
import os
import subprocess


def two(a):
    os.system("sink_two -f " + a)


def four(a, b):
    os.system("sink_four -f /tmp/" + a + ".tgz " + b)


def six(a, b, c):
    os.system("sink_six -f /tmp/" + a + ".tgz " + b + "/" + c)


def argv(a, b):
    subprocess.run(["bound_argv", "-f", a, b], check=True)
'''

JS_SQL = '''\
const db = require("./db");

function two(a) {
  return db.query("SELECT * FROM sink_two WHERE x = " + a);
}

function three(a) {
  return db.query("SELECT * FROM sink_three WHERE x = '" + a + "'");
}

function four(a, b) {
  return db.query("SELECT * FROM sink_four WHERE x = '" + a + "' ORDER BY " + b);
}

function six(a, b, c) {
  return db.query("SELECT " + a + " FROM sink_six WHERE x = " + b + " ORDER BY " + c);
}

function bound(a) {
  return db.query("SELECT * FROM bound_query WHERE x = ?", [a]);
}
'''

JS_COMMAND = '''\
const { exec } = require("child_process");

function two(a) {
  exec("sink_two " + a, () => {});
}

function four(a, b) {
  exec("sink_four --report " + a + " --format " + b, () => {});
}

function six(a, b, c) {
  exec("sink_six -r " + a + " -f " + b + " -o " + c, () => {});
}
'''

PHP_SQL = '''\
<?php
function two($conn, $a) {
    return mysqli_query($conn, "SELECT * FROM sink_two WHERE x = " . $a);
}

function four($conn, $a, $b) {
    return mysqli_query($conn, "SELECT * FROM sink_four WHERE x = '" . $a . "' ORDER BY " . $b);
}

function bound($conn, $a) {
    $stmt = $conn->prepare("SELECT * FROM bound_query WHERE x = ?");
    $stmt->execute([$a]);
}
'''

JAVA_SQL = '''\
import java.sql.Statement;

class Orders {
    void two(Statement st, String a) throws Exception {
        st.executeQuery("SELECT * FROM sink_two WHERE x = " + a);
    }

    void four(Statement st, String a, String b) throws Exception {
        st.executeQuery("SELECT * FROM sink_four WHERE x = '" + a + "' ORDER BY " + b);
    }
}
'''

GO_SQL = '''\
package main

import "database/sql"

func two(db *sql.DB, a string) {
	db.Query("SELECT * FROM sink_two WHERE x = " + a)
}

func four(db *sql.DB, a string, b string) {
	db.Query("SELECT * FROM sink_four WHERE x = '" + a + "' ORDER BY " + b)
}
'''

CSHARP_SQL = '''\
using System.Data.SqlClient;

class Orders
{
    void Two(string a)
    {
        var cmd = new SqlCommand("SELECT * FROM sink_two WHERE x = " + a);
    }

    void Four(string a, string b)
    {
        var cmd = new SqlCommand("SELECT * FROM sink_four WHERE x = '" + a + "' ORDER BY " + b);
    }
}
'''

# (label, path, source, names that must be reported, names that must not be)
CASES = [
    (
        "python SQL",
        "orders.py",
        PYTHON_SQL,
        ["sink_two", "sink_three", "sink_four", "sink_five", "sink_six"],
        ["bound_query", "bound_literal"],
    ),
    (
        "python command",
        "archive.py",
        PYTHON_COMMAND,
        ["sink_two", "sink_four", "sink_six"],
        ["bound_argv"],
    ),
    (
        "javascript SQL",
        "orders.js",
        JS_SQL,
        ["sink_two", "sink_three", "sink_four", "sink_six"],
        ["bound_query"],
    ),
    (
        "javascript command",
        "chart.js",
        JS_COMMAND,
        ["sink_two", "sink_four", "sink_six"],
        [],
    ),
    ("php SQL", "orders.php", PHP_SQL, ["sink_two", "sink_four"], ["bound_query"]),
    ("java SQL", "Orders.java", JAVA_SQL, ["sink_two", "sink_four"], []),
    ("go SQL", "orders.go", GO_SQL, ["sink_two", "sink_four"], []),
    ("csharp SQL", "Orders.cs", CSHARP_SQL, ["sink_two", "sink_four"], []),
]


@pytest.mark.parametrize(
    "label,path,source,must_report,must_not_report",
    CASES,
    ids=[case[0] for case in CASES],
)
class TestConcatenationArity:
    def test_every_concatenation_length_is_reported(
        self, label, path, source, must_report, must_not_report
    ):
        """A sink built from more pieces is not a sink the rules may miss."""
        snippets = _reported_snippets(path, source)
        joined = "\n".join(snippets)
        missed = [name for name in must_report if name not in joined]
        assert not missed, (
            f"{label}: the concatenated sink(s) named {missed} in {path} were reported by "
            f"nothing. {len(snippets)} finding(s) came back. A rule clause that pins a string "
            f"literal to one operand position cannot bind to a longer concatenation; use the "
            f'deep expression form `<... "..." + $INPUT ...>` instead.'
        )

    def test_the_bound_parameter_form_is_not_reported(
        self, label, path, source, must_report, must_not_report
    ):
        """The change the finding asks for must not itself be reported."""
        if not must_not_report:
            pytest.skip("this case declares no parameterised counterpart")
        joined = "\n".join(_reported_snippets(path, source))
        wrong = [name for name in must_not_report if name in joined]
        assert not wrong, (
            f"{label}: {wrong} in {path} pass the value as a bound parameter, which is what "
            f"the finding on the concatenated form tells a reader to do. Reporting them tells "
            f"a reader that the fix is also a defect."
        )
