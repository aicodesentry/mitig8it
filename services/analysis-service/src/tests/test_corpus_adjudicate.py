"""`benchmarks/vulnerable-corpus/adjudicate.py` with a fake provider: no network, no key."""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
ADJUDICATE_PY = REPO_ROOT / "benchmarks" / "vulnerable-corpus" / "adjudicate.py"
REPO = "example/app"
REF = "b" * 40


def _load():
    spec = importlib.util.spec_from_file_location("adjudicate_under_test", ADJUDICATE_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ADJ = _load()

SOURCE = "\n".join(
    [
        "import hashlib",
        "def token(user):",
        "    return hashlib.md5(user.name.encode()).hexdigest()",
        "def run(cmd):",
        "    os.system(cmd)",
        "def query(db, name):",
        "    db.execute('SELECT * FROM t WHERE n = ' + name)",
        "def other():",
        "    eval(input())",
    ]
) + "\n"


@dataclass
class FakeResponse:
    text: str
    provider: str = "fake"
    model: str = "judge-1"
    input_tokens: int = 0
    output_tokens: int = 0


class FakeModel:
    """Answers by line number; records every prompt."""

    def __init__(self, answers: dict[int, str]):
        self.answers = answers
        self.prompts: list[str] = []

    def __call__(self, *, system_prompt, user_prompt, timeout_seconds, temperature, max_output_tokens):
        self.prompts.append(user_prompt)
        line = int(user_prompt.split("Flagged lines: ")[1].split("-")[0])
        return FakeResponse(self.answers[line])


def _finding(rule_id: str, line: int, internal_type: str, fingerprint: str) -> dict:
    return {
        "rule_id": rule_id,
        "internal_type": internal_type,
        "cwe_id": "CWE-0",
        "title": f"{rule_id} title",
        "file_path": "app.py",
        "line_start": line,
        "line_end": line,
        "code_snippet": SOURCE.splitlines()[line - 1],
        "fingerprint": fingerprint,
    }


@pytest.fixture
def corpus(tmp_path):
    findings = [
        _finding("crypto.weak.hash", 3, "weak_cipher_algorithm", "f" * 64),          # unjudged
        _finding("cmd.injection.os_system", 5, "command_injection", "c" * 64),     # labelled: never asked
        _finding("sql.injection.raw_query", 7, "sql_injection", "a" * 64),         # hand-read, calibration sample
        _finding("code.injection.eval", 9, "code_injection", "e" * 64),            # hand-read, later pass
    ]
    results = tmp_path / "result.json"
    results.write_text(json.dumps({"repo": REPO, "ref": REF, "mode": "snapshot", "records": [{"findings": findings}]}))
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"labels": [{
        "id": "app-cmd", "repo": REPO, "ref": REF, "path": "app.py", "line_range": [5, 5],
        "cwe": "CWE-78", "rule_classes_expected": ["command_injection"],
    }]}))
    human = tmp_path / "adjudications.json"
    human.write_text(json.dumps({"version": 1, "adjudications": [
        {"fingerprint": "a" * 64, "verdict": "true", "note": "n", "rule_id": "sql.injection.raw_query",
         "where": f"{REPO} app.py:7", "sampled_as": "unlabelled"},
        {"fingerprint": "e" * 64, "verdict": "true", "note": "n", "rule_id": "code.injection.eval",
         "where": f"{REPO} app.py:9", "sampled_as": "new_rule_2026_09_24"},
    ]}, indent=2) + "\n")
    snapshots = tmp_path / "snapshots"
    tree = snapshots / REPO.replace("/", "__") / REF / "app-tree"
    tree.mkdir(parents=True)
    (tree / "app.py").write_text(SOURCE)
    return {
        "results": results, "labels": labels, "human": human,
        "model": tmp_path / "adjudications-model.json", "snapshots": snapshots,
    }


def _common(corpus) -> list[str]:
    return ["--labels", str(corpus["labels"]), "--human", str(corpus["human"]), "--model", str(corpus["model"])]


def _propose(corpus, model: FakeModel, *extra: str) -> int:
    argv = ["propose", str(corpus["results"]), "--snapshots", str(corpus["snapshots"]), *extra, *_common(corpus)]
    return ADJ.main(argv, caller=model)


def _model_entries(corpus) -> dict[str, dict]:
    return {entry["fingerprint"]: entry for entry in json.loads(corpus["model"].read_text())["adjudications"]}


def test_only_unjudged_findings_are_asked_and_the_human_file_is_untouched(corpus):
    before = corpus["human"].read_bytes()
    model = FakeModel({3: '{"verdict": "true", "quote": "hashlib.md5(user.name", "reason": "MD5 of a name as a token."}'})

    assert _propose(corpus, model) == 0

    assert corpus["human"].read_bytes() == before
    entries = _model_entries(corpus)
    assert list(entries) == ["f" * 64]
    entry = entries["f" * 64]
    assert entry["source"] == "model"
    assert entry["model"] == "fake/judge-1"
    assert entry["prompt_version"] == ADJ.PROMPT_VERSION
    assert entry["verdict"] == "true" and entry["quote_on_line"] is True
    assert entry["calibration"] is False and entry["context"] == "tree"
    assert ">     3 |     return hashlib.md5" in model.prompts[0]


def test_calibrate_also_asks_the_hand_read_sample_and_nothing_twice(corpus):
    model = FakeModel({
        3: '{"verdict": "false", "quote": "hashlib.md5", "reason": "r"}',
        7: '{"verdict": "true", "quote": "SELECT * FROM t", "reason": "r"}',
    })
    _propose(corpus, model, "--calibrate")
    entries = _model_entries(corpus)
    assert set(entries) == {"f" * 64, "a" * 64}
    assert entries["a" * 64]["calibration"] is True
    # The later hand-read pass (`e...`) is not in the calibration sample and is never asked.

    again = FakeModel({})
    _propose(corpus, again, "--calibrate")
    assert again.prompts == []


def test_calibration_only_asks_the_hand_read_sample_alone(corpus):
    model = FakeModel({7: '{"verdict": "true", "quote": "SELECT * FROM t", "reason": "r"}'})
    _propose(corpus, model, "--calibration-only")
    assert set(_model_entries(corpus)) == {"a" * 64}


def test_a_quote_that_is_not_on_the_line_is_recorded_as_such(corpus):
    model = FakeModel({3: '{"verdict": "true", "quote": "os.system(cmd)", "reason": "r"}'})
    _propose(corpus, model)
    assert _model_entries(corpus)["f" * 64]["quote_on_line"] is False


def test_an_answer_that_is_not_json_is_kept_as_unparsed(corpus):
    _propose(corpus, FakeModel({3: "I think this is fine."}))
    entry = _model_entries(corpus)["f" * 64]
    assert entry["verdict"] == "unparsed" and entry["quote_on_line"] is False


def test_no_configured_model_asks_nothing(corpus, monkeypatch, capsys):
    monkeypatch.setenv("LLM_TRIAGE_ENABLED", "false")
    argv = ["propose", str(corpus["results"]), "--snapshots", str(corpus["snapshots"]), *_common(corpus)]
    assert ADJ.main(argv) == 2
    assert not corpus["model"].exists()


@pytest.mark.parametrize(
    "pairs,kappa",
    [
        ([("true", "true"), ("false", "false")] * 5, 1.0),
        # Observed 0.5, expected 0.5: agreement no better than chance.
        ([("true", "true"), ("true", "false"), ("false", "true"), ("false", "false")], 0.0),
        # 20 true/true, 5 true/false, 10 false/true, 15 false/false: po 0.7, pe 0.5, kappa 0.4.
        ([("true", "true")] * 20 + [("true", "false")] * 5 + [("false", "true")] * 10 + [("false", "false")] * 15, 0.4),
    ],
)
def test_cohens_kappa(pairs, kappa):
    assert ADJ.cohen_kappa(pairs) == pytest.approx(kappa)


def test_report_counts_only_decisive_quoted_pairs_against_the_sample(corpus, capsys):
    human = [
        {"fingerprint": "1" * 64, "verdict": "true", "sampled_as": "unlabelled"},
        {"fingerprint": "2" * 64, "verdict": "false", "sampled_as": "class_mismatch"},
        {"fingerprint": "3" * 64, "verdict": "false", "sampled_as": "unlabelled"},
        {"fingerprint": "4" * 64, "verdict": "true", "sampled_as": "new_rule_2026_09_24"},
    ]
    model = [
        {"fingerprint": "1" * 64, "verdict": "true", "quote_on_line": True, "model": "fake/judge-1"},
        {"fingerprint": "2" * 64, "verdict": "false", "quote_on_line": True, "model": "fake/judge-1"},
        {"fingerprint": "3" * 64, "verdict": "true", "quote_on_line": False, "model": "fake/judge-1"},
        {"fingerprint": "4" * 64, "verdict": "false", "quote_on_line": True, "model": "fake/judge-1"},
    ]
    result = ADJ.agreement(human, model)
    assert result["human_calibration_verdicts"] == 3
    assert result["model_judged"] == 3
    assert result["decisive_pairs"] == 2 and result["agreed"] == 2
    assert result["kappa"] == pytest.approx(1.0)
    assert result["table"][("false", "quote not on line")] == 1
    text = ADJ.render_agreement(result)
    assert "| human \\ model | true | false | unsure | quote not on line | unparsed |" in text
    assert "| true | 1 | 0 | 0 | 0 | 0 |" in text


def test_accept_needs_a_reviewer(corpus):
    with pytest.raises(SystemExit):
        ADJ.main(["accept", "f" * 12, *_common(corpus)])


def test_accept_copies_a_read_verdict_and_names_the_reviewer(corpus):
    _propose(corpus, FakeModel({3: '{"verdict": "true", "quote": "hashlib.md5", "reason": "MD5 token."}'}))
    assert ADJ.main(["accept", "f" * 12, "--reviewer", "nebullii", *_common(corpus)]) == 0
    accepted = json.loads(corpus["human"].read_text())["adjudications"][-1]
    assert accepted == {
        "fingerprint": "f" * 64, "verdict": "true", "note": "MD5 token.", "rule_id": "crypto.weak.hash",
        "where": f"{REPO} app.py:3", "sampled_as": "model_proposed", "source": "model",
        "model": "fake/judge-1", "accepted_by": "nebullii",
    }
    with pytest.raises(SystemExit, match="already in"):
        ADJ.main(["accept", "f" * 12, "--reviewer", "nebullii", *_common(corpus)])


@pytest.mark.parametrize(
    "answer,calibrate,fingerprint,message",
    [
        ('{"verdict": "unsure", "quote": "hashlib.md5", "reason": "r"}', False, "f" * 12, "only true or false"),
        ('{"verdict": "true", "quote": "nowhere near", "reason": "r"}', False, "f" * 12, "not on the flagged line"),
        ('{"verdict": "true", "quote": "SELECT * FROM t", "reason": "r"}', True, "a" * 12, "calibration entry"),
    ],
)
def test_accept_refuses_what_a_person_should_not_sign(corpus, answer, calibrate, fingerprint, message):
    flags = ["--calibrate"] if calibrate else []
    _propose(corpus, FakeModel({3: answer, 7: answer}), *flags)
    before = corpus["human"].read_bytes()
    with pytest.raises(SystemExit, match=message):
        ADJ.main(["accept", fingerprint, "--reviewer", "nebullii", *_common(corpus)])
    assert corpus["human"].read_bytes() == before


def test_the_committed_human_file_survives_an_accept_round_trip_byte_for_byte():
    path = REPO_ROOT / "benchmarks" / "vulnerable-corpus" / "adjudications.json"
    text = path.read_text(encoding="utf-8")
    assert json.dumps(json.loads(text), indent=2) + "\n" == text
