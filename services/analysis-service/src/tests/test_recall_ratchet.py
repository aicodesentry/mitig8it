"""The recall ratchet's own logic, on synthetic runs, with no network and no scanner.

`scripts/replay/ratchet.py check` is the gate that fails when a labelled vulnerability stops
being detected. It runs over 23 downloaded repositories in its own workflow, so the logic that
decides pass or fail is checked here, in the ordinary suite, where a mistake in it is found
without the corpus.

The last test is the one piece that reads the committed files: the baseline and `labels.json`
have to name the same labels, or the gate refuses to compare at all.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
RATCHET_PY = REPO_ROOT / "scripts" / "replay" / "ratchet.py"
CORPUS = REPO_ROOT / "benchmarks" / "vulnerable-corpus"

REPO = "example/app"
REF = "a" * 40
POSTING_RULE = "opengrep.test.posting"
QUARANTINED_RULE = "opengrep.test.quarantined"


def _load_ratchet():
    spec = importlib.util.spec_from_file_location("ratchet_under_test", RATCHET_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Registered before it runs: a dataclass resolves its annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RATCHET = _load_ratchet()


@pytest.fixture(autouse=True)
def _synthetic_quarantine(monkeypatch):
    """The posting policy of the synthetic rules, so no test depends on the real rule files."""
    monkeypatch.setattr(RATCHET.score, "quarantined_rule_set", lambda: {QUARANTINED_RULE})


def _label(label_id: str, path: str, line: int, expected: str = "sql_injection", repo: str = REPO) -> dict:
    return {
        "id": label_id, "repo": repo, "ref": REF, "path": path, "line_range": [line, line],
        "cwe": "CWE-89", "rule_classes_expected": [expected],
    }


def _finding(path: str, line: int, rule_id: str = POSTING_RULE, internal_type: str = "sql_injection") -> dict:
    return {
        "rule_id": rule_id, "internal_type": internal_type, "file_path": path,
        "line_start": line, "line_end": line, "fingerprint": f"{rule_id}:{path}:{line}",
    }


def _result(findings: list[dict], repo: str = REPO, **record_overrides) -> dict:
    record = {
        "snapshot_batch": 1,
        "analysis": {"tier1": {"ok": True}, "tier2": {"ok": True}},
        "findings": findings,
    }
    record.update(record_overrides)
    return {"repo": repo, "mode": "snapshot", "ref": REF, "records": [record]}


class Corpus:
    """A labels file, a results directory and a baseline under one temporary directory."""

    def __init__(self, root: Path, labels: list[dict]):
        self.labels = root / "labels.json"
        self.baseline = root / "recall-baseline.json"
        self.results = root / "results"
        self.results.mkdir()
        self.set_labels(labels)

    def set_labels(self, labels: list[dict]) -> None:
        self.labels.write_text(json.dumps({"labels": labels}), encoding="utf-8")

    def run(self, *documents: dict) -> None:
        for stale in self.results.glob("*.json"):
            stale.unlink()
        for index, document in enumerate(documents):
            (self.results / f"{index}.json").write_text(json.dumps(document), encoding="utf-8")

    def ratchet(self, command: str) -> int:
        return RATCHET.main([
            command, str(self.results), "--labels", str(self.labels), "--baseline", str(self.baseline),
        ])


LABELS = [
    _label("app-posting", "a.py", 10),
    _label("app-quarantined", "b.py", 20),
    _label("app-missed", "c.py", 30),
]
BASELINE_RUN = [_finding("a.py", 10), _finding("b.py", 20, QUARANTINED_RULE)]


@pytest.fixture
def corpus(tmp_path, capsys) -> Corpus:
    """Three labels with a baseline: one posting hit, one quarantined-only hit, one miss."""
    built = Corpus(tmp_path, LABELS)
    built.run(_result(BASELINE_RUN))
    assert built.ratchet("update") == RATCHET.EXIT_OK
    capsys.readouterr()
    return built


def test_update_records_hit_and_posting_hit_per_label(corpus):
    document = json.loads(corpus.baseline.read_text(encoding="utf-8"))
    assert document["summary"] == {"labels": 3, "hit": 2, "posting_hit": 1}
    assert document["labels"]["app-posting"] == {
        "hit": True, "posting_hit": True, "posting_rules": [POSTING_RULE], "quarantined_rules": [],
    }
    assert document["labels"]["app-quarantined"] == {
        "hit": True, "posting_hit": False, "posting_rules": [], "quarantined_rules": [QUARANTINED_RULE],
    }
    assert document["labels"]["app-missed"]["hit"] is False


def test_an_unchanged_run_passes(corpus, capsys):
    assert corpus.ratchet("check") == RATCHET.EXIT_OK
    out = capsys.readouterr().out
    assert "result: PASS" in out
    assert "2/3 labels hit, 1 by a posting rule" in out


def test_a_lost_hit_fails_and_names_the_label_and_the_rule_that_used_to_match(corpus, capsys):
    corpus.run(_result([_finding("b.py", 20, QUARANTINED_RULE)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED
    out = capsys.readouterr().out
    assert "REGRESSION, no longer hit (1):" in out
    assert f"app-posting {REPO} a.py:10-10: was hit by {POSTING_RULE}" in out
    assert "result: FAIL" in out


def test_a_lost_quarantined_hit_fails_too(corpus, capsys):
    """The baseline holds every hit, not only the posting ones: a quarantined rule that stops
    matching has lost the evidence it would need to come back."""
    corpus.run(_result([_finding("a.py", 10)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED
    assert "app-quarantined" in capsys.readouterr().out


def test_a_posting_hit_that_becomes_quarantined_only_fails_separately(corpus, capsys):
    corpus.run(_result([_finding("a.py", 10, QUARANTINED_RULE), _finding("b.py", 20, QUARANTINED_RULE)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED
    out = capsys.readouterr().out
    assert "REGRESSION, now hit only by a quarantined rule (1):" in out
    assert "no longer hit" not in out
    assert f"was hit by {POSTING_RULE}, now by {QUARANTINED_RULE} (quarantined)" in out


def test_a_posting_hit_survives_when_another_posting_rule_takes_over(corpus):
    corpus.run(_result([_finding("a.py", 10, "opengrep.test.other"), _finding("b.py", 20, QUARANTINED_RULE)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_OK


def test_a_finding_of_the_wrong_class_on_the_labelled_line_is_not_a_hit(corpus):
    corpus.run(_result([
        _finding("a.py", 10, internal_type="command_injection"), _finding("b.py", 20, QUARANTINED_RULE),
    ]))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED


def test_new_hits_are_improvements_and_do_not_fail(corpus, capsys):
    corpus.run(_result(BASELINE_RUN + [_finding("b.py", 20), _finding("c.py", 30)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_OK
    out = capsys.readouterr().out
    assert "improvement, newly hit (1):" in out and "app-missed" in out
    assert "improvement, now hit by a posting rule (1):" in out and "app-quarantined" in out
    assert "result: PASS" in out
    assert "not protected until the baseline is refreshed" in out


def test_an_improvement_does_not_hide_a_regression(corpus):
    corpus.run(_result([_finding("b.py", 20, QUARANTINED_RULE), _finding("c.py", 30)]))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED


def test_refreshing_the_baseline_protects_an_improvement(corpus, capsys):
    improved = BASELINE_RUN + [_finding("c.py", 30)]
    corpus.run(_result(improved))
    assert corpus.ratchet("update") == RATCHET.EXIT_OK
    corpus.run(_result(BASELINE_RUN))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED
    assert "app-missed" in capsys.readouterr().out


def test_refreshing_the_baseline_accepts_a_loss_and_says_so(corpus, capsys):
    corpus.run(_result([_finding("b.py", 20, QUARANTINED_RULE)]))
    assert corpus.ratchet("update") == RATCHET.EXIT_OK
    assert "REGRESSION, no longer hit (1):" in capsys.readouterr().out
    assert corpus.ratchet("check") == RATCHET.EXIT_OK


def test_a_repository_with_no_result_is_unusable_not_a_regression(tmp_path, capsys):
    labels = LABELS + [_label("other-hit", "d.py", 5, repo="example/other")]
    corpus = Corpus(tmp_path, labels)
    corpus.run(_result(BASELINE_RUN), _result([_finding("d.py", 5)], repo="example/other"))
    assert corpus.ratchet("update") == RATCHET.EXIT_OK
    corpus.run(_result(BASELINE_RUN))
    assert corpus.ratchet("check") == RATCHET.EXIT_UNUSABLE
    out = capsys.readouterr().out
    assert "example/other: no result file" in out
    assert "result: UNUSABLE" in out


@pytest.mark.parametrize("overrides, expected", [
    ({"fatal": {"kind": "timeout"}, "analysis": None}, "batch 1 died (timeout)"),
    ({"analysis": {"tier1": {"ok": True}, "tier2": {"ok": False, "error_type": "RuntimeError"}}},
     "batch 1 tier2 failed (RuntimeError)"),
])
def test_a_batch_that_died_is_unusable(corpus, capsys, overrides, expected):
    corpus.run(_result([], **overrides))
    assert corpus.ratchet("check") == RATCHET.EXIT_UNUSABLE
    out = capsys.readouterr().out
    assert expected in out
    assert "result: UNUSABLE" in out and "result: FAIL" not in out


def test_a_run_at_another_ref_is_unusable(corpus, capsys):
    document = _result(BASELINE_RUN)
    document["ref"] = "b" * 40
    corpus.run(document)
    assert corpus.ratchet("check") == RATCHET.EXIT_UNUSABLE
    assert "labels pin" in capsys.readouterr().out


def test_update_refuses_an_incomplete_measurement(corpus):
    before = corpus.baseline.read_text(encoding="utf-8")
    corpus.run(_result([], fatal={"kind": "timeout"}))
    assert corpus.ratchet("update") == RATCHET.EXIT_UNUSABLE
    assert corpus.baseline.read_text(encoding="utf-8") == before


def test_a_label_the_baseline_does_not_know_is_unusable(corpus, capsys):
    corpus.set_labels(LABELS + [_label("app-new", "e.py", 1)])
    assert corpus.ratchet("check") == RATCHET.EXIT_UNUSABLE
    out = capsys.readouterr().out
    assert "NOT IN THE BASELINE (1)" in out and "app-new" in out


def test_a_label_removed_from_the_corpus_is_unusable(corpus, capsys):
    """Deleting a label is not a way past the gate: the baseline has to be refreshed, and the
    refresh shows the label leaving."""
    corpus.set_labels(LABELS[1:])
    assert corpus.ratchet("check") == RATCHET.EXIT_UNUSABLE
    out = capsys.readouterr().out
    assert "NOT IN labels.json (1)" in out and "app-posting" in out


def test_a_scanner_limitation_on_the_labelled_file_is_named_beside_the_regression(corpus, capsys):
    analysis = {
        "tier1": {"ok": True},
        "tier2": {"ok": True, "analysis_limitations": [{"path": "a.py", "kind": "scanner_error", "type": "Timeout"}]},
    }
    corpus.run(_result([_finding("b.py", 20, QUARANTINED_RULE)], analysis=analysis))
    assert corpus.ratchet("check") == RATCHET.EXIT_REGRESSED
    assert "[scanner limitation on this file: Timeout]" in capsys.readouterr().out


def test_compare_reads_only_the_two_booleans():
    before = {"x": {"hit": True, "posting_hit": True, "posting_rules": ["one"]}}
    now = {"x": {"hit": True, "posting_hit": True, "posting_rules": ["two"]}}
    comparison = RATCHET.compare(before, now)
    assert not comparison.regressed and not comparison.improved and not comparison.out_of_step


def test_the_baseline_is_written_one_label_per_line_and_reads_back(corpus):
    text = corpus.baseline.read_text(encoding="utf-8")
    assert sum(1 for line in text.splitlines() if line.startswith('    "app-')) == 3
    assert set(RATCHET.load_baseline(corpus.baseline)) == {label["id"] for label in LABELS}


def test_the_committed_baseline_names_exactly_the_committed_labels():
    labels = json.loads((CORPUS / "labels.json").read_text(encoding="utf-8"))["labels"]
    document = json.loads((CORPUS / "recall-baseline.json").read_text(encoding="utf-8"))
    baseline = document["labels"]
    assert set(baseline) == {label["id"] for label in labels}
    assert document["summary"] == {
        "labels": len(baseline),
        "hit": sum(1 for entry in baseline.values() if entry["hit"]),
        "posting_hit": sum(1 for entry in baseline.values() if entry["posting_hit"]),
    }
    # A posting hit is a hit; the reverse would be a baseline no run could have written.
    assert all(entry["hit"] for entry in baseline.values() if entry["posting_hit"])
