"""Tests for benchmarks/authz-handlers/run.py with a fake provider.

    ~/.pyenv/versions/3.11.6/bin/python -I -m unittest discover -s benchmarks/authz-handlers -p 'test_*.py'

Nothing here calls a model or reads a key. The source trees are small synthetic ones
written into a temporary directory in the scripts/replay/corpus.py layout.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("authz_run", HERE / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

REPO = "example/shop"
REF = "0" * 40

HANDLERS_JS = """\
const db = require('./db')

// filler 1
// filler 2

module.exports.getOrder = function (req, res) {
  // insecure: no checking that the order belongs to the caller
  const order = db.orders.find(req.params.id)
  challengeUtils.solveIf(challenges.orderChallenge, () => {
    return order.userId !== req.user.id
  })
  res.json(order)
}

module.exports.getOwnOrder = function (req, res) {
  const order = db.orders.find({ id: req.params.id, userId: req.user.id })
  res.json(order)
}
"""

ROUTES_JS = """\
const handlers = require('./handlers')
const { isLoggedIn } = require('./auth')
app.use('/orders', isLoggedIn)
app.use('/admin', isAdmin)
app.get('/orders/:id', handlers.getOrder)
app.get('/orders/:id/own', handlers.getOwnOrder)
"""

AUTH_JS = """\
const passport = require('passport')
const isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) return next()
  res.redirect('/login')
}
module.exports = { isLoggedIn }
"""

CASES = {
    "version": 1,
    "cases": [
        {"id": "b-own-order", "repo": REPO, "ref": REF, "path": "handlers.js", "handler": "getOwnOrder",
         "line_range": [15, 18], "verdict": "safe", "missing_control": "none", "source": "synthetic",
         "reason": "scoped by the session user", "registration": {"path": "routes.js", "pattern": "handlers.getOwnOrder"}},
        {"id": "a-order", "repo": REPO, "ref": REF, "path": "handlers.js", "handler": "getOrder",
         "line_range": [6, 13], "verdict": "vulnerable", "missing_control": "ownership_check", "source": "synthetic",
         "reason": "selected by req.params.id", "registration": {"path": "routes.js", "pattern": "handlers.getOrder)"}},
    ],
}


def write_tree(base: Path) -> Path:
    root = base / REPO.replace("/", "__") / REF / "shop-extracted"
    root.mkdir(parents=True)
    (root / "handlers.js").write_text(HANDLERS_JS)
    (root / "routes.js").write_text(ROUTES_JS)
    (root / "auth.js").write_text(AUTH_JS)
    return base


@dataclass
class FakeResponse:
    text: str
    input_tokens: int = 1000
    output_tokens: int = 100
    provider: str = "fake"
    model: str = "fake-model"


class FakeProvider:
    """Answers by case: the handler name in the prompt picks the canned reply."""

    def __init__(self, replies: dict[str, str], fail_on: set[str] | None = None):
        self.replies, self.fail_on, self.calls = replies, fail_on or set(), []

    def __call__(self, *, system_prompt, user_prompt, timeout_seconds, temperature, max_output_tokens):
        assert temperature == 0
        name = next(key for key in self.replies if f"handler `{key}`" in user_prompt)
        self.calls.append(name)
        if name in self.fail_on:
            raise TimeoutError("fake transport failure")
        return FakeResponse(self.replies[name])


def answer(verdict, control, evidence, reasoning="because"):
    return json.dumps({"verdict": verdict, "missing_control": control, "evidence": evidence, "reasoning": reasoning})


GOOD_REPLIES = {
    "getOrder": answer("vulnerable", "ownership_check", "const order = db.orders.find(req.params.id)"),
    "getOwnOrder": answer("safe", "none", "db.orders.find({ id: req.params.id, userId: req.user.id })"),
}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.trees = write_tree(self.tmp / "trees")
        self.cases_path = self.tmp / "cases.json"
        self.cases_path.write_text(json.dumps(CASES))
        self.tree = run.snapshot_root(self.trees, REPO, REF)
        self._provider = run.PROVIDER

    def tearDown(self):
        run.PROVIDER = self._provider
        self._tmp.cleanup()

    def args(self, **overrides):
        values = dict(cases=self.cases_path, case=None, trees=self.trees, output=self.tmp / "out" / "report.json",
                      cache=self.tmp / "cache", model="fake-model", input_price=1.0, output_price=1.0,
                      max_cost=1.0, max_output_tokens=600, timeout=5, dry_run=False, show_prompts=False, fresh=False)
        values.update(overrides)
        return argparse.Namespace(**values)


class ExtractionTests(Base):
    def case(self, case_id):
        return next(case for case in CASES["cases"] if case["id"] == case_id)

    def test_handler_block_is_the_line_range(self):
        extraction = run.extract_handler(self.tree, self.case("b-own-order"))
        self.assertTrue(extraction["handler"].startswith("module.exports.getOwnOrder"))
        self.assertTrue(extraction["handler"].rstrip().endswith("}"))
        self.assertNotIn("getOrder =", extraction["handler"])
        self.assertIn("module.exports.getOrder", extraction["context_before"])

    def test_context_is_capped_on_each_side(self):
        extraction = run.extract_handler(self.tree, self.case("b-own-order"), context_lines=2)
        self.assertLessEqual(len(extraction["context_before"].split("\n")), 2)
        self.assertNotIn("require('./db')", extraction["context_before"])

    def test_hints_and_challenge_calls_are_redacted(self):
        extraction = run.extract_handler(self.tree, self.case("a-order"))
        handler = extraction["handler"]
        self.assertNotIn("insecure", handler)
        self.assertNotIn("challengeUtils", handler)
        self.assertNotIn("order.userId !== req.user.id", handler)
        self.assertIn("const order = db.orders.find(req.params.id)", handler)
        self.assertIn("res.json(order)", handler)
        self.assertEqual(extraction["redactions"], 2)

    def test_registration_and_path_scoped_middleware(self):
        extraction = run.extract_handler(self.tree, self.case("a-order"))
        registration = extraction["registration"]
        self.assertEqual(registration["line"], 5)
        self.assertEqual(registration["text"], "app.get('/orders/:id', handlers.getOrder)")
        covering = [m["text"] for m in registration["path_middleware"]]
        self.assertEqual(covering, ["app.use('/orders', isLoggedIn)"])

    def test_auth_summary_resolves_middleware_and_counts_terms(self):
        extraction = run.extract_handler(self.tree, self.case("a-order"))
        summary = run.auth_summary(self.tree, extraction["registration"], "getOrder")
        self.assertEqual([m["name"] for m in summary["middleware"]], ["isLoggedIn"])
        self.assertEqual(summary["middleware"][0]["path"], "auth.js")
        self.assertEqual(summary["grep"]["passport"]["files"], 1)
        self.assertEqual(summary["grep"]["isAuthenticated"]["occurrences"], 1)
        self.assertEqual(summary["grep"]["login_required"]["occurrences"], 0)

    def test_missing_registration_is_reported_not_raised(self):
        case = {**self.case("a-order"), "registration": {"path": "routes.js", "pattern": "no such handler"}}
        self.assertIsNone(run.extract_handler(self.tree, case)["registration"])

    def test_out_of_range_lines_raise(self):
        case = {**self.case("a-order"), "line_range": [10, 999]}
        with self.assertRaises(ValueError):
            run.extract_handler(self.tree, case)

    def test_prompt_marks_the_quotable_block(self):
        case = self.case("a-order")
        extraction = run.extract_handler(self.tree, case)
        prompt = run.build_user_prompt(case, extraction, run.auth_summary(self.tree, extraction["registration"], "getOrder"))
        self.assertIn("## Handler (quote your evidence from this block only)", prompt)
        self.assertIn("`isLoggedIn` (auth.js:2)", prompt)


class ParseTests(unittest.TestCase):
    HANDLER = "function h (req, res) {\n  const order = db.orders.find(req.params.id)\n  res.json(order)\n}"

    def parse(self, text):
        return run.parse_response(text, self.HANDLER)

    def test_valid_answer(self):
        record, rejection = self.parse(answer("vulnerable", "ownership_check", "db.orders.find(req.params.id)"))
        self.assertIsNone(rejection)
        self.assertEqual(record["verdict"], "vulnerable")

    def test_fenced_answer_and_whitespace_normalised_quote(self):
        text = "```json\n" + answer("vulnerable", "ownership_check", "const   order =\n db.orders.find(req.params.id)") + "\n```"
        record, rejection = self.parse(text)
        self.assertIsNone(rejection)
        self.assertEqual(record["missing_control"], "ownership_check")

    def test_quote_not_in_handler_is_rejected(self):
        _, rejection = self.parse(answer("vulnerable", "ownership_check", "if (order.userId !== req.user.id)"))
        self.assertEqual(rejection, "evidence_not_in_handler")

    def test_quote_too_short_is_rejected(self):
        _, rejection = self.parse(answer("safe", "none", "}"))
        self.assertEqual(rejection, "evidence_too_short")

    def test_schema_violations(self):
        cases = {
            "not json": "not_json",
            "[1, 2]": "not_object",
            json.dumps({"verdict": "safe"}): "missing_fields:missing_control,evidence,reasoning",
            answer("maybe", "none", "db.orders.find(req.params.id)"): "bad_verdict",
            answer("vulnerable", "csrf", "db.orders.find(req.params.id)"): "bad_missing_control",
            answer("vulnerable", "none", "db.orders.find(req.params.id)"): "vulnerable_without_control",
            answer("safe", "role_check", "db.orders.find(req.params.id)"): "safe_with_control",
            answer("safe", "none", "   "): "empty_evidence",
        }
        for text, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(self.parse(text), (None, expected))

    def test_uncertain_is_accepted_with_any_control(self):
        record, rejection = self.parse(answer("uncertain", "role_check", "db.orders.find(req.params.id)"))
        self.assertIsNone(rejection)
        self.assertEqual(record["verdict"], "uncertain")


class ScoringTests(unittest.TestCase):
    def test_wilson_matches_reference_values(self):
        interval = run.wilson(8, 10)
        self.assertAlmostEqual(interval["low"], 0.4902, places=3)
        self.assertAlmostEqual(interval["high"], 0.9433, places=3)
        self.assertEqual(run.wilson(0, 5)["low"], 0.0)
        self.assertEqual(run.wilson(5, 5)["high"], 1.0)
        self.assertIsNone(run.wilson(0, 0))

    def test_uncertain_rejected_and_error_are_misses_not_false_positives(self):
        rows = [
            {"label": "vulnerable", "label_missing_control": "ownership_check", "observed": "vulnerable", "observed_missing_control": "ownership_check"},
            {"label": "vulnerable", "label_missing_control": "role_check", "observed": "vulnerable", "observed_missing_control": "ownership_check"},
            {"label": "vulnerable", "label_missing_control": "role_check", "observed": "uncertain"},
            {"label": "vulnerable", "label_missing_control": "role_check", "observed": "rejected"},
            {"label": "vulnerable", "label_missing_control": "role_check", "observed": "error"},
            {"label": "safe", "label_missing_control": "none", "observed": "vulnerable", "observed_missing_control": "role_check"},
            {"label": "safe", "label_missing_control": "none", "observed": "uncertain"},
            {"label": "safe", "label_missing_control": "none", "observed": "safe"},
        ]
        summary = run.score(rows)
        self.assertEqual(summary["confusion"], {"tp": 2, "fp": 1, "fn": 3, "tn": 2})
        self.assertEqual((summary["precision"]["successes"], summary["precision"]["total"]), (2, 3))
        self.assertEqual((summary["recall"]["successes"], summary["recall"]["total"]), (2, 5))
        self.assertEqual(summary["missing_control_agreement_on_true_positives"], {"agree": 1, "total": 2})
        self.assertEqual(summary["outcomes"]["uncertain"], 2)

    def test_precision_is_undefined_without_vulnerable_verdicts(self):
        rows = [{"label": "vulnerable", "label_missing_control": "role_check", "observed": "safe"}]
        self.assertIsNone(run.score(rows)["precision"])
        self.assertEqual(run.score(rows)["recall"]["point"], 0.0)


class CostGuardTests(unittest.TestCase):
    def test_reserve_refuses_past_budget_and_settle_replaces_estimate(self):
        guard = run.CostGuard(max_cost=0.01, input_price=1.0, output_price=1.0)
        reservation = guard.reserve(prompt_chars=3000, max_output_tokens=600)
        self.assertAlmostEqual(reservation, (1000 + 256 + 600) / 1e6)
        cost = guard.settle(reservation, input_tokens=900, output_tokens=50)
        self.assertAlmostEqual(guard.spent_or_reserved, cost)
        with self.assertRaises(run.BudgetExhausted):
            guard.reserve(prompt_chars=3_000_000, max_output_tokens=600)

    def test_settle_without_usage_keeps_the_reservation(self):
        guard = run.CostGuard(max_cost=1.0, input_price=1.0, output_price=1.0)
        reservation = guard.reserve(prompt_chars=300, max_output_tokens=10)
        self.assertIsNone(guard.settle(reservation, 0, 0))
        self.assertAlmostEqual(guard.spent_or_reserved, reservation)


class RunTests(Base):
    def test_end_to_end_scores_in_id_order(self):
        run.PROVIDER = FakeProvider(GOOD_REPLIES)
        report = run.run(self.args())
        self.assertEqual(report["status"], "complete")
        self.assertEqual([row["case_id"] for row in report["rows"]], ["a-order", "b-own-order"])
        self.assertEqual(report["summary"]["confusion"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        saved = json.loads(self.args().output.read_text())
        self.assertEqual(saved["summary"], report["summary"])

    def test_second_run_is_served_from_cache(self):
        run.PROVIDER = FakeProvider(GOOD_REPLIES)
        run.run(self.args())
        fake = FakeProvider(GOOD_REPLIES)
        run.PROVIDER = fake
        report = run.run(self.args(output=self.tmp / "second.json"))
        self.assertEqual(fake.calls, [])
        self.assertTrue(all(row.get("from_cache") for row in report["rows"]))

    def test_fresh_ignores_the_cache(self):
        run.PROVIDER = FakeProvider(GOOD_REPLIES)
        run.run(self.args())
        fake = FakeProvider(GOOD_REPLIES)
        run.PROVIDER = fake
        run.run(self.args(fresh=True))
        self.assertEqual(sorted(fake.calls), ["getOrder", "getOwnOrder"])

    def test_resume_keeps_answers_and_retries_errors(self):
        run.PROVIDER = FakeProvider(GOOD_REPLIES, fail_on={"getOwnOrder"})
        first = run.run(self.args())
        self.assertEqual({row["case_id"]: row["observed"] for row in first["rows"]},
                         {"a-order": "vulnerable", "b-own-order": "error"})
        self.assertEqual(first["rows"][1]["error"], "TimeoutError")
        fake = FakeProvider(GOOD_REPLIES)
        run.PROVIDER = fake
        second = run.run(self.args())
        self.assertEqual(fake.calls, ["getOwnOrder"])
        self.assertTrue(second["rows"][0]["resumed"])
        self.assertEqual(second["rows"][1]["observed"], "safe")

    def test_wrong_quote_is_rejected_and_counted_as_a_miss(self):
        replies = {**GOOD_REPLIES, "getOrder": answer("vulnerable", "ownership_check", "order.userId !== req.user.id")}
        run.PROVIDER = FakeProvider(replies)
        report = run.run(self.args())
        row = report["rows"][0]
        self.assertEqual((row["observed"], row["rejection"]), ("rejected", "evidence_not_in_handler"))
        self.assertEqual(report["summary"]["confusion"]["fn"], 1)

    def test_budget_stops_before_the_request(self):
        fake = FakeProvider(GOOD_REPLIES)
        run.PROVIDER = fake
        report = run.run(self.args(max_cost=0.000001))
        self.assertEqual(report["status"], "stopped:budget")
        self.assertEqual(fake.calls, [])
        self.assertTrue(all(row["observed"] == "error" for row in report["rows"]))

    def test_dry_run_calls_nothing(self):
        fake = FakeProvider(GOOD_REPLIES)
        run.PROVIDER = fake
        report = run.run(self.args(dry_run=True, model=None, show_prompts=True))
        self.assertEqual(report["status"], "dry_run")
        self.assertEqual(fake.calls, [])
        self.assertIn("db.orders.find", report["rows"][0]["user_prompt"])


class FetchTests(Base):
    def test_fetch_asks_for_each_pinned_pair_once(self):
        asked = []

        class FakeCache:
            def tree(self, repo, ref):
                asked.append((repo, ref))
                return Path("/elsewhere") / repo

        suite = run.load_cases(self.cases_path)
        paths = run.fetch_trees(suite, self.tmp / "fetched", cache_factory=lambda trees: FakeCache())
        self.assertEqual(asked, [(REPO, REF)])
        self.assertEqual(len(paths), 1)

    def test_fetch_refuses_a_directory_inside_the_repository(self):
        suite = run.load_cases(self.cases_path)
        with self.assertRaises(SystemExit):
            run.fetch_trees(suite, run.ROOT / "benchmarks" / "trees", cache_factory=lambda trees: None)


class CaseFileTests(unittest.TestCase):
    """The committed cases.json, checked without any source tree."""

    def setUp(self):
        self.suite = run.load_cases(HERE / "cases.json")

    def test_thirty_cases_balanced(self):
        cases = self.suite["cases"]
        self.assertEqual(len(cases), 30)
        verdicts = [case["verdict"] for case in cases]
        self.assertEqual(verdicts.count("vulnerable"), 15)
        self.assertEqual(verdicts.count("safe"), 15)

    def test_every_case_is_pinned_to_a_corpus_ref(self):
        labels = (HERE.parent / "vulnerable-corpus" / "labels.json").read_text()
        pinned = {(repo["repo"], repo["ref"]) for repo in self.suite["repositories"]}
        for case in self.suite["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIn((case["repo"], case["ref"]), pinned)
                self.assertIn(case["ref"], labels)
                self.assertTrue(case["reason"] and case["source"] and case["registration"])

    def test_load_cases_rejects_inconsistent_labels(self):
        bad = {"cases": [{"id": "x", "verdict": "vulnerable", "missing_control": "none"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as stream:
            json.dump(bad, stream)
        try:
            with self.assertRaises(ValueError):
                run.load_cases(Path(stream.name))
        finally:
            Path(stream.name).unlink()


if __name__ == "__main__":
    unittest.main()
