#!/usr/bin/env python3
"""Prove the replay harness itself works, on a payload that must produce a repair.

Real merged pull requests in mainstream repositories rarely contain a finding in a
repairable family, so a replay that reports zero candidates is ambiguous: it could mean
the pipeline found nothing, or that the harness never reached the engine. This runs the
same worker over a synthetic pull request with an obvious SQL injection and asserts that
analysis finds it, the template path produces a candidate, and the sandbox regression
check passes on the local driver.

    scripts/replay/selftest.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

VULNERABLE_SOURCE = '''import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cursor.fetchall())
'''


def payload() -> dict:
    lines = VULNERABLE_SOURCE.splitlines()
    patch = f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)
    return {
        "repo": "synthetic/selftest",
        "number": 1,
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "files": [{
            "path": "app.py",
            "patch": patch,
            "content": VULNERABLE_SOURCE,
            "additions": len(lines),
            "deletions": 0,
            "status": "added",
            "reviewable_line_spans": [{"start": 1, "end": len(lines)}],
        }],
        "limitations": [],
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="replay_selftest_") as tmp:
        payload_path = Path(tmp) / "payload.json"
        out_path = Path(tmp) / "result.json"
        payload_path.write_text(json.dumps(payload()), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(HERE / "worker.py"), str(payload_path), str(out_path)],
            capture_output=True, text=True, timeout=900,
        )
        if completed.returncode != 0:
            print(completed.stderr[-3000:], file=sys.stderr)
            print("FAIL: the worker exited non-zero", file=sys.stderr)
            return 1
        record = json.loads(out_path.read_text(encoding="utf-8"))

    problems = []
    if not record["findings"]:
        problems.append("analysis found nothing in a file with an obvious SQL injection")
    remediation = record.get("remediation") or {}
    if not remediation.get("supported_family_findings"):
        problems.append("no finding mapped to a repairable family")
    if not remediation.get("candidates_produced"):
        problems.append("the template path produced no candidate")
    if not remediation.get("verified"):
        problems.append("the sandbox regression check did not pass on the local driver")
    if remediation.get("exceptions"):
        problems.append(f"remediation raised: {remediation['exceptions']}")

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1

    print(
        "ok: findings={} candidates={} verified={} agent_needed={}".format(
            len(record["findings"]), remediation["candidates_produced"],
            remediation["verified"], remediation["agent_needed"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
