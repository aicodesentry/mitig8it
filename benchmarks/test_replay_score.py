"""Provenance on an adjudicated verdict, and the order the reading list comes out in.

A model may suggest a verdict; only a human may license a rule to post. The two tests that
matter here are that an entry with no `source` is refused outright, and that an entry whose
source is anything but `hand` cannot reach the precision numerator or denominator. The rest
pin the ranking `--emit-queue` now applies, so the first thing a reader is handed is a
finding whose verdict could actually release or stop a rule.
"""
from __future__ import annotations

import json

import pytest

from scripts.replay import score


HAND_FINGERPRINT = "a" * 64
MODEL_FINGERPRINT = "b" * 64


def finding(fingerprint: str, *, rule_id: str = "opengrep.cwe-89.py-sql-format", line: int = 10,
            path: str = "app.py", repo: str = "example/one") -> dict:
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "internal_type": "sql_injection",
        "cwe_id": "CWE-89",
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "code_snippet": "query = 'select ' + name",
        "_repo": repo,
        "_ref": "c" * 40,
        "_source_file": "results.json",
    }


def write_adjudications(tmp_path, entries: list[dict]):
    path = tmp_path / "adjudications.json"
    path.write_text(json.dumps({"version": 1, "adjudications": entries}, indent=2), encoding="utf-8")
    return str(path)


def test_an_adjudication_with_no_source_is_refused(tmp_path) -> None:
    path = write_adjudications(tmp_path, [
        {"fingerprint": HAND_FINGERPRINT, "verdict": "true", "source": "hand"},
        {"fingerprint": MODEL_FINGERPRINT, "verdict": "true"},
    ])

    with pytest.raises(SystemExit) as refusal:
        score.load_adjudications(path)

    assert MODEL_FINGERPRINT in str(refusal.value)
    assert "source" in str(refusal.value)


def test_a_source_that_is_not_hand_does_not_move_precision(tmp_path) -> None:
    adjudications = score.load_adjudications(write_adjudications(tmp_path, [
        {"fingerprint": HAND_FINGERPRINT, "verdict": "false", "source": "hand"},
        {"fingerprint": MODEL_FINGERPRINT, "verdict": "true", "source": "model"},
    ]))

    scored, _ = score.join(
        [finding(HAND_FINGERPRINT), finding(MODEL_FINGERPRINT, line=20)],
        [],
        adjudications,
        set(),
    )

    by_fingerprint = {row["fingerprint"]: row for row in scored}
    assert by_fingerprint[HAND_FINGERPRINT]["verdict"] == "false"
    assert by_fingerprint[HAND_FINGERPRINT]["verdict_source"] == "hand-read"
    assert by_fingerprint[MODEL_FINGERPRINT]["verdict"] != "true"
    assert by_fingerprint[MODEL_FINGERPRINT]["verdict_source"] == "model-suggested"

    # One hand-read false and one model-suggested true: precision is 0/1, not 1/2.
    assert score._precision(scored) == (0, 1, 0.0)


def test_a_model_suggestion_cannot_be_promoted_by_a_stray_verdict_field() -> None:
    """The exclusion lives in the precision function, not only at load time.

    Provenance is checked twice on purpose. If some later caller hands `_precision` a row
    that carries a true verdict under a source other than a label or a hand reading, that
    row still must not count.
    """
    rows = [
        {"verdict": "true", "verdict_source": "label"},
        {"verdict": "true", "verdict_source": "model-suggested"},
        {"verdict": "false", "verdict_source": "model-suggested"},
    ]

    assert score._precision(rows) == (1, 0, 1.0)


def test_the_shipped_adjudications_are_all_hand_sourced() -> None:
    adjudications = score.load_adjudications(
        str(score.REPO_ROOT / "benchmarks" / "vulnerable-corpus" / "adjudications.json")
    )

    assert adjudications
    assert {str(entry.get("source")) for entry in adjudications.values()} == {"hand"}


# --- the reading list -------------------------------------------------------------------------


def unread_queue(tmp_path, scored, *, sample: int = 10, seed: int = 1) -> dict:
    out = tmp_path / "queue.json"
    score.emit_queue(scored, str(out), sample, seed)
    return json.loads(out.read_text(encoding="utf-8"))


def test_the_queue_reads_a_scarce_quarantined_rule_before_a_well_evidenced_one(tmp_path) -> None:
    quarantined = "opengrep.cwe-22.py-path-join-user"
    posting = "opengrep.cwe-89.py-sql-format"
    well_evidenced = "opengrep.cwe-79.js-html-string-interpolated"

    findings = [
        # Four hand verdicts on the well-evidenced rule, so it is already past the bar.
        *[finding("d" * 63 + str(index), rule_id=well_evidenced, line=100 + index)
          for index in range(4)],
        finding("e" * 63 + "0", rule_id=well_evidenced, line=200),
        finding("f" * 63 + "0", rule_id=posting, line=300),
        finding("0" * 63 + "1", rule_id=quarantined, line=400),
    ]
    adjudications = score.load_adjudications(write_adjudications(tmp_path, [
        {"fingerprint": "d" * 63 + str(index), "verdict": "true", "source": "hand"}
        for index in range(4)
    ]))

    scored, _ = score.join(findings, [], adjudications, {quarantined})
    document = unread_queue(tmp_path, scored)

    order = [row["rule_id"] for row in document["queue"]]
    assert order == [quarantined, posting, well_evidenced]
    assert document["rules"][quarantined]["adjudicated"] == 0
    assert document["rules"][well_evidenced]["adjudicated"] == 4
    assert document["queue"][0]["adjudicated_now"] == 0
    assert document["bar"]["adjudicated_findings"] == 3
    assert document["bar"]["precision"] == 0.8
    assert document["bar"]["recorded_in"]


def test_the_queue_keeps_every_class_mismatch_and_honours_the_sample_cap(tmp_path) -> None:
    label = {
        "id": "one-mismatch", "repo": "example/one", "ref": "c" * 40, "path": "app.py",
        "line_range": [10, 10], "cwe": "CWE-79", "rule_classes_expected": ["xss"],
        "source": "fixture", "evidence": "the line",
    }
    findings = [finding(HAND_FINGERPRINT, line=10)] + [
        finding(f"{index:064d}", line=500 + index) for index in range(6)
    ]

    scored, _ = score.join(findings, [label], adjudications={}, quarantined=set())
    document = unread_queue(tmp_path, scored, sample=2)

    assert document["class_mismatch_total"] == 1
    assert document["unlabelled_total"] == 6
    assert len(document["queue"]) == 3
    assert HAND_FINGERPRINT in {row["fingerprint"] for row in document["queue"]}


def test_a_model_suggestion_is_queued_for_a_human_rather_than_dropped(tmp_path) -> None:
    adjudications = score.load_adjudications(write_adjudications(tmp_path, [
        {"fingerprint": MODEL_FINGERPRINT, "verdict": "true", "source": "model",
         "note": "the model thinks this reaches a sink"},
    ]))

    scored, _ = score.join([finding(MODEL_FINGERPRINT)], [], adjudications, set())
    document = unread_queue(tmp_path, scored, sample=0)

    assert document["model_suggested_total"] == 1
    queued = [row for row in document["queue"] if row["fingerprint"] == MODEL_FINGERPRINT]
    assert len(queued) == 1
    assert queued[0]["suggested_verdict"] == "true"


def test_the_sample_is_still_reproducible_under_a_seed(tmp_path) -> None:
    findings = [finding(f"{index:064d}", line=600 + index) for index in range(20)]
    scored, _ = score.join(findings, [], adjudications={}, quarantined=set())

    first = unread_queue(tmp_path, scored, sample=5, seed=7)
    second = unread_queue(tmp_path, scored, sample=5, seed=7)
    other = unread_queue(tmp_path, scored, sample=5, seed=8)

    assert [row["fingerprint"] for row in first["queue"]] == [
        row["fingerprint"] for row in second["queue"]
    ]
    assert [row["fingerprint"] for row in first["queue"]] != [
        row["fingerprint"] for row in other["queue"]
    ]


def test_the_report_names_the_model_suggestions_it_did_not_count(tmp_path) -> None:
    adjudications = score.load_adjudications(write_adjudications(tmp_path, [
        {"fingerprint": HAND_FINGERPRINT, "verdict": "true", "source": "hand"},
        {"fingerprint": MODEL_FINGERPRINT, "verdict": "true", "source": "model"},
    ]))
    labels = [{
        "id": "unhit", "repo": "example/two", "ref": "c" * 40, "path": "other.py",
        "line_range": [1, 1], "cwe": "CWE-89", "rule_classes_expected": ["sql_injection"],
        "source": "fixture", "evidence": "the line",
    }]
    scored, label_state = score.join(
        [finding(HAND_FINGERPRINT), finding(MODEL_FINGERPRINT, line=20)],
        labels,
        adjudications,
        set(),
    )

    report = score.render(scored, label_state, labels)

    assert "1 model-suggested" in report
    assert "not counted" in report
