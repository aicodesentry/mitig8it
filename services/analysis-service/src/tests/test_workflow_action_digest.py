"""The action reference a workflow finding carries, and the digest lookup behind it.

The pinning repair needs one fact this service can get and the repair service cannot: the commit
an action's tag currently resolves to. The repair sandbox has no egress by design, so the lookup
happens here and the answer rides on the finding.

What is tested is mostly what happens when the lookup does not answer, because that is the common
case: the flag is off by default, so no request leaves this process unless someone turned it on,
and the reference still has to be carried.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import workflow_action_digest as wad
from opengrep_runner import run_opengrep

DIGEST = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture(autouse=True)
def clean_lookup(monkeypatch):
    monkeypatch.delenv("WORKFLOW_ACTION_DIGEST_LOOKUP", raising=False)
    monkeypatch.delenv("WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN", raising=False)
    wad.reset_cache()
    yield
    wad.reset_cache()


class TestParsingTheReference:
    @pytest.mark.parametrize(
        "line,repository,ref,subdirectory",
        [
            ("      - uses: codecov/codecov-action@v5", "codecov/codecov-action", "v5", ""),
            ("        uses: pypa/gh-action-pypi-publish@master", "pypa/gh-action-pypi-publish", "master", ""),
            ("      - uses: qltysh/qlty-action/coverage@v2 # a comment", "qltysh/qlty-action", "v2", "coverage"),
            ("      - uses: 'some-org/act@release/v1'", "some-org/act", "release/v1", ""),
            (f"      - uses: some-org/act@{DIGEST}", "some-org/act", DIGEST, ""),
        ],
    )
    def test_a_reference_is_parsed_into_its_parts(self, line, repository, ref, subdirectory):
        parsed = wad.parse_action_reference(line)
        assert parsed == {"repository": repository, "subdirectory": subdirectory, "ref": ref}

    @pytest.mark.parametrize(
        "line",
        [
            "      - uses: ./.github/actions/setup",
            "      - uses: docker://alpine:3.19",
            "      - uses: actions/checkout",
            "      - run: npm ci",
            "",
        ],
    )
    def test_anything_that_is_not_a_github_ref_is_not_parsed(self, line):
        assert wad.parse_action_reference(line) is None


class TestTheLookupIsOffByDefault:
    def test_no_request_is_made_unless_the_flag_is_set(self, monkeypatch):
        """A scanner that quietly makes an outbound call per finding is one nobody can reason
        about, and the Action's contract is that nothing leaves the runner at all."""
        def explode(url):  # pragma: no cover - the point is that it is never called
            raise AssertionError(f"a request was made with the flag unset: {url}")

        monkeypatch.setattr(wad, "_request", explode)
        assert wad.lookup_enabled() is False
        assert wad.resolve_action_digest("codecov/codecov-action", "v5") is None

    @pytest.mark.parametrize("value,expected", [("true", True), ("1", True), ("on", True), ("no", False), ("", False)])
    def test_the_flag_is_read_the_usual_way(self, monkeypatch, value, expected):
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", value)
        assert wad.lookup_enabled() is expected

    def test_a_reference_that_is_already_a_digest_needs_no_lookup(self, monkeypatch):
        """Answering with it rather than None keeps a caller from reading a pinned reference as a
        failed lookup."""
        monkeypatch.setattr(wad, "_request", lambda url: pytest.fail("no request should be made"))
        assert wad.resolve_action_digest("some-org/act", DIGEST.upper()) == DIGEST


class TestTheLookupWhenItIsOn:
    def test_a_resolved_sha_is_returned_lowercased(self, monkeypatch):
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        monkeypatch.setattr(wad, "_request", lambda url: {"sha": DIGEST.upper()})
        assert wad.resolve_action_digest("codecov/codecov-action", "v5") == DIGEST

    def test_the_answer_is_cached_per_repository_and_ref(self, monkeypatch):
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        calls: list[str] = []

        def record(url):
            calls.append(url)
            return {"sha": DIGEST}

        monkeypatch.setattr(wad, "_request", record)
        for _ in range(3):
            assert wad.resolve_action_digest("codecov/codecov-action", "v5") == DIGEST
        assert len(calls) == 1

    @pytest.mark.parametrize("payload", [None, {}, {"sha": ""}, {"sha": "not-a-sha"}, {"sha": "abc123"}])
    def test_anything_short_of_a_full_sha_is_no_digest_at_all(self, monkeypatch, payload):
        """Unreachable API, rate limit, deleted tag, malformed body: all the same answer. The
        repair side refuses a finding with no digest by name, so silence is the safe result and a
        guess is not."""
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        monkeypatch.setattr(wad, "_request", lambda url: payload)
        assert wad.resolve_action_digest("codecov/codecov-action", "v5") is None

    def test_the_ref_is_escaped_into_the_path(self, monkeypatch):
        """`release/v1` is a legal ref and a path separator. Left unescaped it would ask for a
        different endpoint entirely."""
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        seen: list[str] = []
        monkeypatch.setattr(wad, "_request", lambda url: seen.append(url) or {"sha": DIGEST})
        wad.resolve_action_digest("some-org/act", "release/v1")
        assert seen == ["https://api.github.com/repos/some-org/act/commits/release%2Fv1"]


class TestWhatTheFindingCarries:
    def test_the_reference_is_carried_even_with_no_digest(self):
        extra = wad.action_reference_evidence("      - uses: codecov/codecov-action@v5")
        assert extra == {
            "workflow_action_reference": "codecov/codecov-action",
            "workflow_action_ref": "v5",
        }

    def test_a_subdirectory_action_carries_its_subdirectory(self):
        extra = wad.action_reference_evidence("      - uses: qltysh/qlty-action/coverage@v2")
        assert extra["workflow_action_subdirectory"] == "coverage"

    def test_a_resolved_digest_is_added_when_one_was_found(self, monkeypatch):
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        monkeypatch.setattr(wad, "_request", lambda url: {"sha": DIGEST})
        extra = wad.action_reference_evidence("      - uses: codecov/codecov-action@v5")
        assert extra["resolved_action_digest"] == DIGEST


class TestTheRunnerAttachesIt:
    """End to end through the real scanner, because the wiring is what actually breaks."""

    WORKFLOW = (
        "name: coverage\n"
        "on: push\n"
        "jobs:\n"
        "  coverage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: codecov/codecov-action@v5\n"
    )

    def _findings(self):
        files = [{
            "path": ".github/workflows/coverage.yml",
            "content": self.WORKFLOW,
            "patch": "",
            "reviewable_line_spans": [],
        }]
        return [
            finding for finding in run_opengrep(files)
            if finding["rule_id"] == "opengrep.cwe-1357.gha-third-party-action-unpinned"
        ]

    def test_an_unpinned_finding_carries_the_reference(self):
        findings = self._findings()
        assert len(findings) == 1, "the first-party actions/checkout must not be reported"
        extra = findings[0]["evidence_details"]["extra"]
        assert extra["workflow_action_reference"] == "codecov/codecov-action"
        assert extra["workflow_action_ref"] == "v5"
        assert "resolved_action_digest" not in extra

    def test_the_digest_arrives_on_the_finding_when_the_lookup_answers(self, monkeypatch):
        monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "true")
        monkeypatch.setattr(wad, "_request", lambda url: {"sha": DIGEST})
        extra = self._findings()[0]["evidence_details"]["extra"]
        assert extra["resolved_action_digest"] == DIGEST

    def test_no_other_workflow_rule_carries_this_evidence(self):
        """Only the pinning repair depends on a looked-up fact. Everything the injection repair
        needs is on the line it matched."""
        source = (
            "name: t\n"
            "on:\n"
            "  pull_request_target:\n"
            "    types: [opened]\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  t:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ github.event.pull_request.title }}\n"
        )
        files = [{"path": ".github/workflows/t.yml", "content": source, "patch": "", "reviewable_line_spans": []}]
        for finding in run_opengrep(files):
            if finding["rule_id"] == "opengrep.cwe-1357.gha-third-party-action-unpinned":
                continue
            extra = (finding.get("evidence_details") or {}).get("extra") or {}
            assert "workflow_action_reference" not in extra, finding["rule_id"]


class TestTheHostedDeploymentCanActuallyTurnItOn:
    """The variable was read by this module and set by nothing, for as long as it existed.

    `resolve_action_digest` returns None while the flag is off, the finding then carries no
    `resolved_action_digest`, and the repair service refuses it as `action_digest_unresolved`. So a
    variable no deployment passes is the same thing as a repair family that can never ship a fix,
    and the rule those findings come from is the most precise one measured
    (1.00 over 46 findings, `docs/validation/workflow-tampering-2026-09.md`).

    These read the deploy workflow as text rather than asserting on a running service, which is the
    most this suite can do. It is still enough to fail if the line is dropped again.
    """

    WORKFLOW = Path(__file__).resolve().parents[4] / ".github/workflows/deploy-analysis-cloudrun.yml"

    def test_the_deploy_passes_the_variable_to_the_service(self):
        body = self.WORKFLOW.read_text(encoding="utf-8")
        assert "WORKFLOW_ACTION_DIGEST_LOOKUP=${WORKFLOW_ACTION_DIGEST_LOOKUP}" in body, (
            "deploy-analysis-cloudrun.yml no longer passes WORKFLOW_ACTION_DIGEST_LOOKUP to the "
            "service, so the hosted deployment cannot resolve an action digest and every workflow "
            "pinning repair is refused as action_digest_unresolved."
        )
        assert "vars.WORKFLOW_ACTION_DIGEST_LOOKUP" in body, "the value has to come from somewhere"

    def test_the_deploy_normalises_the_value_rather_than_interpolating_it(self):
        """A repository variable is operator input, and it lands in a comma-separated list."""
        body = self.WORKFLOW.read_text(encoding="utf-8")
        assert 'DIGEST_LOOKUP="true"' in body and 'DIGEST_LOOKUP=""' in body, (
            "the deploy should map the variable onto exactly true or empty, so a value containing a "
            "comma or a quote cannot break out of --update-env-vars"
        )
        # The raw variable must not reach the env list directly.
        assert "WORKFLOW_ACTION_DIGEST_LOOKUP=${{ vars." not in body

    def test_the_values_the_deploy_accepts_are_the_values_this_module_accepts(self, monkeypatch):
        """Two spellings of the same switch in two languages is how a flag silently does nothing."""
        for value in ("1", "true", "yes", "on", "TRUE", "On"):
            monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", value)
            assert wad.lookup_enabled() is True, value
        for value in ("", "0", "false", "no", "off", "maybe"):
            monkeypatch.setenv("WORKFLOW_ACTION_DIGEST_LOOKUP", value)
            assert wad.lookup_enabled() is False, value
