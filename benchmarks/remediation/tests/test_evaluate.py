import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from benchmarks.remediation.evaluate import (
    DEVELOPMENT_VERIFICATION_LEVEL,
    LIVE_PROVIDER_KIND,
    PRODUCTION_VERIFICATION_LEVEL,
    REMOTE_PROVIDER_KIND,
    SCRIPTED_PROVIDER_KIND,
    FixtureError,
    RemediationServiceClient,
    known_failure_for,
    load_known_failures,
    assert_no_repository_leakage,
    engine_adapter,
    engine_local_adapter,
    evaluate_fixture,
    expected_patches,
    live_provider_settings,
    load_fixtures,
    load_service_modules,
    matches_reference_patch,
    reference_adapter,
    remote_results_kind,
    summarize,
    validate_verification_checks,
)


ROOT = Path(__file__).resolve().parents[3]


class RemediationHarnessTests(unittest.TestCase):
    def test_fixture_corpus_has_isolated_repositories_and_supported_families(self):
        fixtures = load_fixtures()
        families = {fixture["family"] for _, fixture in fixtures if fixture["kind"] == "supported"}
        self.assertEqual(families, {"sql_parameterization", "command_arguments", "path_containment", "hardcoded_credential", "code_injection_eval"})
        self.assertEqual(len({fixture["repository_id"] for _, fixture in fixtures}), len(fixtures))

    def test_repository_leakage_is_rejected(self):
        fixtures = [
            (ROOT, {"id": "a", "repository_id": "same-repo", "split": "train"}),
            (ROOT, {"id": "b", "repository_id": "same-repo", "split": "holdout"}),
        ]
        with self.assertRaises(FixtureError):
            assert_no_repository_leakage(fixtures)

    def test_seed_runs_trusted_reference_behavior_checks(self):
        completed = subprocess.run(
            [sys.executable, "benchmarks/remediation/evaluate.py", "--suite", "seed"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        # 46 supported, 9 negative and 4 adversarial across 59 fixtures. Asserted rather
        # than derived so adding a fixture is a deliberate change here too; these counts had
        # fallen behind the fixture set more than once before.
        self.assertEqual(report["summary"]["eligible_supported_cases"], 46)
        self.assertEqual(report["summary"]["negative_adversarial_cases"], 13)
        self.assertEqual(report["summary"]["failures"], [])

    def test_reference_candidate_must_match_the_expected_patch_not_only_claim_ready(self):
        fixture_dir, fixture = next((directory, item) for directory, item in load_fixtures() if item["id"] == "sql-parameterized-001")
        result = reference_adapter(fixture_dir, fixture)
        self.assertTrue(matches_reference_patch(fixture_dir, fixture, result))
        result["candidates"][0]["replacement_content"] = "module.exports = {};"
        self.assertFalse(matches_reference_patch(fixture_dir, fixture, result))

    def test_release_gate_refuses_to_promote_the_small_seed(self):
        completed = subprocess.run(
            [sys.executable, "benchmarks/remediation/evaluate.py", "--suite", "release"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        report = json.loads(completed.stdout)
        self.assertFalse(report["release_gate"]["passed"])
        self.assertTrue(any(reason.startswith("minimum_cases_not_met") for reason in report["release_gate"]["reasons"]))
        self.assertIn("external_review_signatures_missing", report["release_gate"]["reasons"])

    def test_every_supported_family_is_covered_in_both_toolchains_or_recorded_as_an_abstention(self):
        fixtures = [fixture for _, fixture in load_fixtures()]
        supported = {(fixture["family"], fixture["source"].rsplit(".", 1)[-1]) for fixture in fixtures if fixture["kind"] == "supported"}
        # Both toolchains prove all five families, so every cell of the family table is a
        # supported fixture and no family is represented only by an abstention.
        for family in ("sql_parameterization", "command_arguments", "path_containment", "hardcoded_credential", "code_injection_eval"):
            self.assertIn((family, "py"), supported, family)
            self.assertIn((family, "js"), supported, family)
        # Each gate that refuses a shape still has a fixture standing for it.
        abstaining = {(fixture["family"], fixture["source"].rsplit(".", 1)[-1]) for fixture in fixtures if fixture["kind"] == "negative"}
        for family in ("sql_parameterization", "command_arguments", "code_injection_eval"):
            self.assertIn((family, "js"), abstaining, family)
        self.assertGreaterEqual(sum(1 for fixture in fixtures if fixture["kind"] == "negative"), 6)
        self.assertGreaterEqual(sum(1 for fixture in fixtures if fixture["kind"] == "adversarial"), 4)

    def test_a_recorded_known_failure_names_a_defect_and_never_becomes_a_pass(self):
        entries = load_known_failures()
        fixture_ids = {fixture["id"] for _, fixture in load_fixtures()}
        for entry in entries:
            self.assertIn(entry["fixture_id"], fixture_ids)
            # Every entry cites the defect's file and line, so it cannot silence a regression.
            self.assertRegex(entry["bug"], r"^[\w./-]+\.py:\d+$")
            self.assertNotIn("reference", entry["adapters"])
        self.assertIsNone(known_failure_for(entries, "sql-parameterized-001", "engine-local", "anything"))

    def test_empty_metrics_have_explicit_unknown_intervals(self):
        summary = summarize([])
        self.assertEqual(summary["precision_wilson_95"], [None, None])
        self.assertEqual(summary["coverage_wilson_95"], [None, None])


class EngineLocalPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = load_service_modules()
        cls.fixtures = {fixture["id"]: (directory, fixture) for directory, fixture in load_fixtures()}

    def _run(self, fixture_id):
        directory, fixture = self.fixtures[fixture_id]
        with tempfile.TemporaryDirectory(prefix="mitig8it-engine-local-test-") as state:
            return engine_local_adapter(directory, fixture, self.modules, Path(state), SCRIPTED_PROVIDER_KIND)

    def test_supported_fixture_reaches_a_development_unverified_candidate(self):
        directory, fixture = self.fixtures["sql-parameterized-001"]
        result = self._run("sql-parameterized-001")
        self.assertEqual(result["state"], "ready", result.get("reason"))
        self.assertEqual(result["verification_level"], "development_unverified")
        self.assertTrue(matches_reference_patch(directory, fixture, result))
        self.assertTrue(any("development local sandbox" in item for item in result["limitations"]))

    def test_supported_fixture_is_graded_as_a_passing_pipeline_case(self):
        directory, fixture = self.fixtures["sql-parameterized-001"]
        with tempfile.TemporaryDirectory(prefix="mitig8it-engine-local-test-") as state:
            local = {"modules": self.modules, "state_dir": Path(state), "provider_kind": SCRIPTED_PROVIDER_KIND}
            case = evaluate_fixture(directory, fixture, "engine-local", None, local)
        self.assertEqual(case.outcome, "passed", case.reason)
        self.assertEqual(case.verification_level, "development_unverified")

    def test_ambiguous_driver_fixture_abstains(self):
        result = self._run("ambiguous-sql-driver-001")
        self.assertEqual(result["state"], "unsupported")
        self.assertEqual(result["candidates"], [])
        self.assertNotEqual(result["verification_level"], "independent_sandbox")

    def test_python_fixtures_reach_development_unverified_candidates(self):
        for fixture_id in ("python-sql-sqlite-001", "python-hardcoded-secret-001", "python-eval-001"):
            directory, fixture = self.fixtures[fixture_id]
            result = self._run(fixture_id)
            self.assertEqual(result["state"], "ready", (fixture_id, result.get("reason")))
            self.assertEqual(result["verification_level"], "development_unverified")
            self.assertTrue(matches_reference_patch(directory, fixture, result), fixture_id)
        secret = self._run("python-hardcoded-secret-001")
        self.assertTrue(any("reads API_KEY from the environment" in item for item in secret["limitations"]), secret["limitations"])

    def test_python_ambiguous_query_fixture_is_skipped_as_ambiguous_query_api(self):
        result = self._run("python-ambiguous-sql-001")
        self.assertEqual(result["state"], "unsupported")
        self.assertEqual(result["reason"], "ambiguous_query_api")
        self.assertEqual(result["candidates"], [])

    def test_engine_live_requires_a_configured_provider(self):
        saved = {name: os.environ.pop(name, None) for name in ("REPAIR_LLM_BASE_URL", "REPAIR_LLM_API_KEY", "REPAIR_LLM_MODEL")}
        try:
            with self.assertRaises(FixtureError) as error:
                live_provider_settings()
            self.assertIn("REPAIR_LLM_API_KEY", str(error.exception))
        finally:
            for name, value in saved.items():
                if value is not None:
                    os.environ[name] = value

    def test_fixture_without_verification_checks_is_rejected(self):
        with self.assertRaises(FixtureError):
            validate_verification_checks({"id": "x", "kind": "supported"})

    def test_multi_file_fixture_produces_one_candidate_per_group_and_a_combined_batch(self):
        directory, fixture = self.fixtures["multi-file-batch-001"]
        result = self._run("multi-file-batch-001")
        self.assertEqual(result["state"], "ready", result.get("reason"))
        self.assertEqual(result["verification_level"], "development_unverified")
        # Two findings in two files: two groups, two candidates, one combined verified batch.
        self.assertEqual(
            sorted(candidate["path"] for candidate in result["candidates"]),
            sorted(expected_patches(directory, fixture)),
        )
        self.assertTrue(matches_reference_patch(directory, fixture, result))
        self.assertIsNotNone(result["evidence"]["manifest_digest"])

    def test_a_partial_multi_file_repair_is_not_graded_as_a_match(self):
        directory, fixture = self.fixtures["multi-file-batch-001"]
        expected = expected_patches(directory, fixture)
        partial = {"candidates": [{"path": "orders.js", "replacement_content": expected["orders.js"]}]}
        self.assertFalse(matches_reference_patch(directory, fixture, partial))


class FakeRemediationClient:
    """Stands in for the deployed service. No socket is opened."""

    def __init__(self, terminal, running_polls=1):
        self.terminal = terminal
        self.running_polls = running_polls
        self.submitted = None
        self.polls = 0

    def submit(self, payload):
        self.submitted = payload
        return {"schema_version": "v1", "execution_id": "sha256:" + "a" * 64, "state": "queued"}

    def poll(self, execution_id):
        self.polls += 1
        if self.polls <= self.running_polls:
            return {"schema_version": "v1", "execution_id": execution_id, "state": "running"}
        return self.terminal


class EngineHttpAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = load_service_modules()
        cls.fixtures = {fixture["id"]: (directory, fixture) for directory, fixture in load_fixtures()}

    def _terminal(self, fixture_dir, fixture, level=DEVELOPMENT_VERIFICATION_LEVEL):
        candidates = [
            {"patch": [{"path": path, "replacement_content": content}]}
            for path, content in sorted(expected_patches(fixture_dir, fixture).items())
        ]
        return {
            "schema_version": "v1",
            "execution_id": "sha256:" + "a" * 64,
            "state": "ready",
            "result": {
                "state": "ready",
                "candidates": candidates,
                "manifest_digest": "sha256:" + "b" * 64,
                "evidence": {"verification_level": level, "usage": {"input_tokens": 24, "output_tokens": 24}, "limitations": []},
            },
        }

    def test_the_adapter_builds_the_full_request_polls_and_grades_the_result(self):
        directory, fixture = self.fixtures["multi-file-batch-001"]
        client = FakeRemediationClient(self._terminal(directory, fixture))
        result = engine_adapter(
            client, directory, fixture, self.modules, allow_development_verification=True, sleep=lambda seconds: None
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["verification_level"], DEVELOPMENT_VERIFICATION_LEVEL)
        self.assertTrue(matches_reference_patch(directory, fixture, result))
        self.assertEqual(client.polls, 2)
        # The same complete intake contract the in-process adapter builds.
        self.assertEqual(client.submitted["schema_version"], "v1")
        self.assertFalse(client.submitted["tree_truncated"])
        self.assertEqual(len(client.submitted["findings"]), 2)
        self.assertTrue(client.submitted["head_tree_oid"])
        self.assertTrue(client.submitted["tree_entries"])
        self.assertTrue(client.submitted["policy"]["allow_development_verification"])

    def test_the_adapter_is_graded_like_the_local_adapters(self):
        directory, fixture = self.fixtures["sql-parameterized-001"]
        client = FakeRemediationClient(self._terminal(directory, fixture))
        engine = {
            "client": client,
            "modules": self.modules,
            "poll_timeout_seconds": 5,
            "allow_development_verification": True,
            "sandbox_image_digest": None,
        }
        case = evaluate_fixture(directory, fixture, "engine", engine)
        self.assertEqual(case.outcome, "passed", case.reason)
        self.assertEqual(case.verification_level, DEVELOPMENT_VERIFICATION_LEVEL)

    def test_a_never_terminal_execution_times_out_instead_of_hanging(self):
        directory, fixture = self.fixtures["sql-parameterized-001"]
        client = FakeRemediationClient(self._terminal(directory, fixture), running_polls=10_000)
        result = engine_adapter(
            client, directory, fixture, self.modules, poll_timeout_seconds=0, sleep=lambda seconds: None
        )
        self.assertEqual(result["state"], "inconclusive")
        self.assertEqual(result["reason"], "engine_poll_timeout")

    def test_a_failed_execution_is_never_read_as_a_repair(self):
        directory, fixture = self.fixtures["sql-parameterized-001"]
        client = FakeRemediationClient({"state": "failed", "reason": {"code": "worker_attempts_exhausted"}}, running_polls=0)
        result = engine_adapter(client, directory, fixture, self.modules, sleep=lambda seconds: None)
        self.assertEqual(result["state"], "inconclusive")
        self.assertEqual(result["reason"], "engine_execution_failed")

    def test_the_client_names_the_missing_url_and_secret(self):
        with self.assertRaises(FixtureError) as error:
            RemediationServiceClient("", "secret")
        self.assertIn("REMEDIATION_SERVICE_URL", str(error.exception))
        with self.assertRaises(FixtureError) as error:
            RemediationServiceClient("https://service.invalid", "")
        self.assertIn("REMEDIATION_SERVICE_INTERNAL_SECRET", str(error.exception))

    def test_results_kind_claims_repair_quality_only_for_a_declared_real_model(self):
        self.assertEqual(remote_results_kind([DEVELOPMENT_VERIFICATION_LEVEL], LIVE_PROVIDER_KIND), "pipeline_integrity")
        self.assertEqual(remote_results_kind([PRODUCTION_VERIFICATION_LEVEL], REMOTE_PROVIDER_KIND), "unverified_contract_smoke")
        self.assertEqual(remote_results_kind([PRODUCTION_VERIFICATION_LEVEL], LIVE_PROVIDER_KIND), "repair_quality")
        self.assertEqual(remote_results_kind(["none"], LIVE_PROVIDER_KIND), "pipeline_integrity")


if __name__ == "__main__":
    unittest.main()
