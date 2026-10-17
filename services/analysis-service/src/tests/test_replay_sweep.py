"""The replay harness's sweep flag: recorded and fake providers, and separate scoring.

The harness lives in `scripts/replay`, outside the service, and has no tests of its own. These
cover the two parts the tier 3 sweep measurement depends on: the worker can run the sweep
without a model key from recorded responses, and `score.py` keeps sweep hits apart from rule
hits.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

import llm_sweep

REPLAY_DIR = Path(__file__).resolve().parents[4] / "scripts" / "replay"


def _load(name: str):
    saved_env = dict(os.environ)
    saved_path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location(f"replay_{name}", REPLAY_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        # Importing the worker sets LLM_TRIAGE_ENABLED and extends sys.path; neither may leak.
        os.environ.clear()
        os.environ.update(saved_env)
        sys.path[:] = saved_path


@pytest.fixture
def worker(monkeypatch):
    module = _load("worker")
    # run_sweep swaps these on the shared module; put them back after each test.
    monkeypatch.setattr(llm_sweep, "_call_sweep_llm", llm_sweep._call_sweep_llm)
    monkeypatch.setattr(llm_sweep, "is_llm_provider_configured", llm_sweep.is_llm_provider_configured)
    for name in ("LLM_SWEEP_ENABLED", *module.SWEEP_MEASUREMENT_BUDGETS):
        monkeypatch.delenv(name, raising=False)
    yield module
    for name in ("LLM_SWEEP_ENABLED", *module.SWEEP_MEASUREMENT_BUDGETS):
        os.environ.pop(name, None)


PATCHES = {
    "app/db.py": (
        "@@ -0,0 +1,3 @@\n"
        "+def get(name):\n"
        "+    cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
        "+    return cursor.fetchall()\n"
    )
}

ITEM = {
    "internal_type": "sql_injection",
    "file_path": "app/db.py",
    "line": 2,
    "quote": "cursor.execute(",
    "severity": "high",
    "confidence": 0.9,
    "rationale": "name reaches the query string unescaped.",
    "exploit_payload": "GET /user?name=' OR '1'='1",
}


def _record(directory: Path, text: str) -> None:
    block = llm_sweep._render_file("app/db.py", PATCHES["app/db.py"])
    prompt = llm_sweep.build_sweep_prompt([block], None)
    key = _load("worker").sweep_cache_key(llm_sweep.SYSTEM_PROMPT, prompt)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{key}.json").write_text(json.dumps({"text": text, "input_tokens": 10, "output_tokens": 5}))


class TestWorkerSweep:
    def test_a_recorded_response_becomes_a_finding_with_no_key(self, worker, tmp_path, monkeypatch):
        for name in ("GEMINI_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        _record(tmp_path / "rec", json.dumps([ITEM]))
        result = worker.run_sweep(PATCHES, f"recorded:{tmp_path / 'rec'}")
        assert [f["rule_id"] for f in result["findings"]] == ["llm.sweep.sql_injection"]
        assert result["summary"]["status"] == "ok"

    def test_a_missing_recording_is_a_failed_call_not_an_empty_answer(self, worker, tmp_path):
        result = worker.run_sweep(PATCHES, f"recorded:{tmp_path / 'empty'}")
        assert result["findings"] == []
        assert result["summary"]["status"] == "failed"
        assert any(item["kind"] == "provider" for item in result["summary"]["limitations"])

    def test_the_fake_provider_proves_the_plumbing_and_finds_nothing(self, worker):
        result = worker.run_sweep(PATCHES, "fake")
        assert result["findings"] == []
        assert result["summary"]["calls"] == 1

    def test_measurement_budgets_are_raised_unless_set(self, worker, monkeypatch):
        monkeypatch.setenv("LLM_SWEEP_MAX_CALLS", "2")
        worker.run_sweep(PATCHES, "fake")
        assert os.environ["LLM_SWEEP_MAX_CALLS"] == "2"
        assert os.environ["LLM_SWEEP_TOKEN_BUDGET"] == worker.SWEEP_MEASUREMENT_BUDGETS["LLM_SWEEP_TOKEN_BUDGET"]

    def test_an_unknown_provider_is_refused(self, worker):
        with pytest.raises(ValueError):
            worker.sweep_caller("openai")


class TestScoreKeepsTheSweepApart:
    def _run_file(self, tmp_path: Path) -> Path:
        rule = {"rule_id": "opengrep.python.sql", "internal_type": "sql_injection", "file_path": "a.py",
                "line_start": 10, "line_end": 10, "fingerprint": "r1"}
        sweep_same = {"rule_id": "llm.sweep.sql_injection", "internal_type": "sql_injection", "file_path": "a.py",
                      "line_start": 10, "line_end": 10, "fingerprint": "s1"}
        sweep_new = {"rule_id": "llm.sweep.command_injection", "internal_type": "command_injection",
                     "file_path": "b.py", "line_start": 5, "line_end": 5, "fingerprint": "s2"}
        document = {"mode": "snapshot", "repo": "o/r", "ref": "x", "sweep_provider": "fake",
                    "records": [{"findings": [rule], "sweep_findings": [sweep_same, sweep_new]}]}
        path = tmp_path / "run.json"
        path.write_text(json.dumps(document))
        return path

    LABELS = [
        {"id": "L1", "repo": "o/r", "ref": "x", "path": "a.py", "line_range": [10, 10], "cwe": "CWE-89",
         "rule_classes_expected": ["sql_injection"]},
        {"id": "L2", "repo": "o/r", "ref": "x", "path": "b.py", "line_range": [5, 5], "cwe": "CWE-78",
         "rule_classes_expected": ["command_injection"]},
    ]

    def test_rule_recall_is_unchanged_and_the_sweep_addition_is_counted(self, tmp_path):
        score = _load("score")
        path = self._run_file(tmp_path)
        rules = score.load_results([str(path)])
        sweep = score.load_results([str(path)], key="sweep_findings")
        assert [f["fingerprint"] for f in rules] == ["r1"]
        scored, state = score.join(rules, self.LABELS, {}, set())
        sweep_scored, sweep_state = score.join(sweep, self.LABELS, {}, {"llm.sweep.sql_injection"})
        assert [key for key, value in state.items() if value["hits"]] == ["L1"]
        assert {row["tier"] for row in sweep_scored} == {3}
        text = "\n".join(score.sweep_section(sweep_scored, sweep_state, state))
        assert "| Sweep, not hit by any rule | 1 | 0.50 |" in text
        assert "| Rules and sweep together | 2 | 1.00 |" in text
        assert "`L2`" in text
