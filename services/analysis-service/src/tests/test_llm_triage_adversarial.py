"""Per-finding isolation, the exploit payload requirement and the patch critic.

Every test here drives `triage_findings` through a fake `call_llm`, the one seam the service
has to a provider, so what they prove is the handling around the model: how the batch is
split, which model each call names, what happens to a confirmation that carries no payload,
and what a critic's answer does to `fixed_code`. None of it says anything about what a real
model would answer.
"""

import json
import os
from unittest.mock import patch

import pytest

import llm_triage
from llm_client import LLMResponse
from llm_triage import (
    CRITIC_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    TriageBudget,
    _concrete_payload,
    _parse_critic_response,
    _require_concrete_payloads,
    _split_for_isolation,
    triage_findings,
)

GOOD_PAYLOAD = {
    "entrypoint": "app.py:10 GET /users?id=",
    "input": "1 OR 1=1",
    "expected_effect": "the WHERE clause is always true and every row is returned",
}
FIX = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'


def _finding(fingerprint="fp-1", severity="high", **overrides):
    base = {
        "rule_id": "sql.injection.raw_query",
        "title": "Potential SQL Injection",
        "category": "SQL injection",
        "cwe_id": "CWE-89",
        "severity": severity,
        "confidence": 0.7,
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 10,
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "evidence": "Matched deterministic rule",
        "fingerprint": fingerprint,
        "description": "SQL query built with f-string",
        "remediation": "Use parameterized queries",
        "remediation_patch": "",
        "exploit_scenario": "",
        "evidence_details": {},
    }
    base.update(overrides)
    return base


def _fixable(fingerprint="fp-1", severity="high", **overrides):
    """A finding the deterministic gate lets a fix through on."""
    return _finding(
        fingerprint,
        severity,
        evidence_details={
            "trace_steps": [
                {"kind": "source", "expr": "req.query.id", "line": 10},
                {"kind": "sink", "expr": "cursor.execute(query)", "line": 11},
            ],
            "auto_fix_eligible": True,
            "fix_scope": "line",
            "missing_control_type": "output_encoding",
        },
        **overrides,
    )


def _env(**overrides):
    values = {"OPENAI_API_KEY": "sk-test"}
    values.update(overrides)
    return patch.dict(os.environ, values, clear=True)


def _fingerprints_in(user_prompt):
    contexts = json.loads(user_prompt.split("## Findings to triage\n\n", 1)[1])
    return [context["fingerprint"] for context in contexts]


def _confirm(fingerprints, payload=GOOD_PAYLOAD, fixed_code=None, **extra):
    return json.dumps([
        {
            "fingerprint": fp,
            "reachability": "req.query.id is interpolated into the query string with no cast.",
            "exploit_payload": payload,
            "verdict": "true_positive",
            "reasoning": "The identifier reaches the query unparameterised.",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploit_scenario": None,
            "remediation": None,
            "fixed_code": fixed_code,
            **extra,
        }
        for fp in fingerprints
    ])


class FakeProvider:
    """Stands in for `llm_client.call_llm`. Triage calls are answered by `triage`, critic
    calls by `critic`; each may be a string or a callable of (user_prompt, fingerprints)."""

    def __init__(self, triage, critic="NONE", tokens=(100, 50)):
        self.triage = triage
        self.critic = critic
        self.tokens = tokens
        self.calls = []

    def __call__(self, **kwargs):
        kind = "critic" if kwargs["system_prompt"] == CRITIC_SYSTEM_PROMPT else "triage"
        prompt = kwargs["user_prompt"]
        fingerprints = _fingerprints_in(prompt) if kind == "triage" else []
        self.calls.append({"kind": kind, "model": kwargs.get("model"), "fingerprints": fingerprints, "prompt": prompt})
        answer = self.critic if kind == "critic" else self.triage
        text = answer(prompt, fingerprints) if callable(answer) else answer
        return LLMResponse(text=text, input_tokens=self.tokens[0], output_tokens=self.tokens[1],
                           provider="fake", model=kwargs.get("model") or "batch-model")

    def of_kind(self, kind):
        return [call for call in self.calls if call["kind"] == kind]


def _run(provider, findings, patches=None):
    with patch.object(llm_triage, "call_llm", provider):
        return triage_findings(findings, patches or {"app.py": "+query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"})


# ── isolation and tiering ─────────────────────────────────────────────────


class TestIsolation:
    def test_split_puts_high_and_critical_alone_and_keeps_order(self):
        findings = [_finding("c", "critical"), _finding("m", "medium"), _finding("h", "high"), _finding("l", "low")]
        isolated, batched = _split_for_isolation(findings, llm_triage.SEVERITY_RANK["high"])
        assert [f["fingerprint"] for f in isolated] == ["c", "h"]
        assert [f["fingerprint"] for f in batched] == ["m", "l"]

    def test_split_disabled_keeps_one_batch(self):
        findings = [_finding("c", "critical"), _finding("l", "low")]
        assert _split_for_isolation(findings, 0) == ([], findings)

    def test_high_and_critical_get_one_call_each_and_the_rest_share_one(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps))
        findings = [_finding("c", "critical"), _finding("m", "medium"), _finding("h", "high"), _finding("l", "low")]
        with _env():
            result = _run(provider, findings)
        triage_calls = provider.of_kind("triage")
        assert [call["fingerprints"] for call in triage_calls] == [["c"], ["h"], ["m", "l"]]
        assert len(result) == 4
        assert {f["llm_triage"]["verdict"] for f in result} == {"true_positive"}

    def test_isolation_threshold_is_configurable(self):
        findings = [_finding("c", "critical"), _finding("h", "high"), _finding("l", "low")]
        with _env(LLM_TRIAGE_ISOLATE_SEVERITY="critical"):
            provider = FakeProvider(lambda prompt, fps: _confirm(fps))
            _run(provider, findings)
        assert [call["fingerprints"] for call in provider.of_kind("triage")] == [["c"], ["h", "l"]]

        with _env(LLM_TRIAGE_ISOLATE_SEVERITY="none"):
            provider = FakeProvider(lambda prompt, fps: _confirm(fps))
            _run(provider, findings)
        assert [call["fingerprints"] for call in provider.of_kind("triage")] == [["c", "h", "l"]]

    def test_isolated_calls_name_the_high_model_and_the_batch_does_not(self):
        findings = [_finding("c", "critical"), _finding("l", "low")]
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX))
        with _env(LLM_TRIAGE_MODEL_HIGH="gpt-strong"):
            _run(provider, [_fixable("c", "critical"), findings[1]])
        by_fingerprints = {tuple(call["fingerprints"]): call["model"] for call in provider.of_kind("triage")}
        assert by_fingerprints == {("c",): "gpt-strong", ("l",): None}
        assert [call["model"] for call in provider.of_kind("critic")] == ["gpt-strong"]

    def test_without_a_high_model_every_call_uses_the_configured_one(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps))
        with _env():
            _run(provider, [_finding("c", "critical"), _finding("l", "low")])
        assert {call["model"] for call in provider.calls} == {None}

    def test_system_prompt_argues_reachability_before_the_verdict(self):
        order = [SYSTEM_PROMPT.index(marker) for marker in ("Reachability first", "Exploit construction second", "Verdict last")]
        assert order == sorted(order)
        assert '"exploit_payload"' in SYSTEM_PROMPT and '"reachability"' in SYSTEM_PROMPT
        assert SYSTEM_PROMPT.rstrip().endswith("Do not include any text outside the JSON array.")


# ── the payload requirement ──────────────────────────────────────────────


class TestPayloadRequirement:
    @pytest.mark.parametrize("payload", [
        None,
        "1 OR 1=1",
        {"entrypoint": "app.py:10", "input": "1 OR 1=1"},
        {"entrypoint": "n/a", "input": "1 OR 1=1", "expected_effect": "dump"},
        {"entrypoint": "<route>", "input": "<value>", "expected_effect": "<effect>"},
        {"entrypoint": "the handler", "input": "malicious input", "expected_effect": "injection happens"},
        {"entrypoint": "some other module", "input": "a string", "expected_effect": "rows come back"},
        # Off-file: the entrypoint is another file, even though the input names the identifier.
        {"entrypoint": "routes/admin.py:42 POST /reset", "input": "user_id=1 OR 1=1", "expected_effect": "all rows"},
        {"entrypoint": "lib/other_app.py:10", "input": "1 OR 1=1", "expected_effect": "all rows"},
    ])
    def test_missing_placeholder_and_unanchored_payloads_are_not_concrete(self, payload):
        assert _concrete_payload(payload, _finding()) is None

    def test_a_payload_naming_the_file_or_the_flagged_identifier_is_concrete(self):
        assert _concrete_payload(GOOD_PAYLOAD, _finding()) == GOOD_PAYLOAD
        by_identifier = {"entrypoint": "GET /users with user_id", "input": "1 OR 1=1", "expected_effect": "all rows"}
        assert _concrete_payload(by_identifier, _finding()) == by_identifier
        with_directory = {"entrypoint": "src/app.py:10 GET /users?id=", "input": "1 OR 1=1", "expected_effect": "all rows"}
        assert _concrete_payload(with_directory, _finding(file_path="src/app.py")) == with_directory
        also_names_the_file = {"entrypoint": "routes.py mounts app.py:10 at /users", "input": "1 OR 1=1", "expected_effect": "all rows"}
        assert _concrete_payload(also_names_the_file, _finding()) == also_names_the_file

    def test_high_confirmation_without_payload_becomes_uncertain_with_the_reason(self):
        verdicts = [{"fingerprint": "fp-1", "verdict": "true_positive", "exploit_payload": None}]
        [updated] = _require_concrete_payloads(verdicts, [_finding(severity="high")], enforce=True)
        assert updated["verdict"] == "uncertain"
        assert updated["downgrade"] == {"from": "true_positive", "to": "uncertain", "reason": "no_concrete_payload"}

    def test_a_medium_finding_raised_to_high_by_the_model_needs_a_payload_too(self):
        verdicts = [{"fingerprint": "fp-1", "verdict": "true_positive", "exploit_payload": None, "adjusted_severity": "critical"}]
        [updated] = _require_concrete_payloads(verdicts, [_finding(severity="medium")], enforce=True)
        assert updated["verdict"] == "uncertain"

    def test_medium_and_low_confirmations_keep_their_verdict_without_a_payload(self):
        verdicts = [{"fingerprint": "fp-1", "verdict": "true_positive", "exploit_payload": None}]
        [updated] = _require_concrete_payloads(verdicts, [_finding(severity="medium")], enforce=True)
        assert updated["verdict"] == "true_positive" and "downgrade" not in updated

    def test_false_positive_and_uncertain_are_untouched(self):
        verdicts = [
            {"fingerprint": "fp-1", "verdict": "false_positive", "exploit_payload": None},
            {"fingerprint": "fp-2", "verdict": "uncertain", "exploit_payload": None},
        ]
        updated = _require_concrete_payloads(verdicts, [_finding("fp-1", "critical"), _finding("fp-2", "critical")], enforce=True)
        assert [v["verdict"] for v in updated] == ["false_positive", "uncertain"]

    def test_critical_confirmation_without_payload_is_recorded_on_the_finding(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, payload=None, fixed_code=FIX, adjusted_confidence=0.95))
        with _env():
            [result] = _run(provider, [_fixable("fp-1", "critical")])
        assert result["llm_triage"]["verdict"] == "uncertain"
        assert result["llm_triage"]["downgrade"]["reason"] == "no_concrete_payload"
        assert result["llm_triage"]["exploit_payload"] is None
        # What crosses gRPC and lands in the findings table.
        assert result["evidence_details"]["extra"]["triage_downgrade_reason"] == "no_concrete_payload"
        assert result["evidence_details"]["extra"]["triage_downgraded_from"] == "true_positive"
        # Nothing the model attached to its confirmation survives the downgrade.
        assert result["confidence"] == 0.7
        assert "remediation_patch" not in result
        assert provider.of_kind("critic") == []

    def test_concrete_payload_keeps_the_confirmation_and_is_recorded(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps))
        with _env():
            [result] = _run(provider, [_finding("fp-1", "critical")])
        assert result["llm_triage"]["verdict"] == "true_positive"
        assert result["llm_triage"]["downgrade"] is None
        assert result["llm_triage"]["exploit_payload"] == GOOD_PAYLOAD
        assert "interpolated" in result["llm_triage"]["reachability"]
        assert "extra" not in result["evidence_details"]

    def test_requirement_off_confirms_without_a_payload(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, payload=None))
        with _env(LLM_TRIAGE_REQUIRE_PAYLOAD="false"):
            [result] = _run(provider, [_finding("fp-1", "critical")])
        assert result["llm_triage"]["verdict"] == "true_positive"
        assert result["llm_triage"]["downgrade"] is None


# ── the patch critic ─────────────────────────────────────────────────────


class TestPatchCritic:
    def test_counterexample_withholds_fixed_code_and_keeps_the_finding(self):
        critic_answer = json.dumps({
            "counterexample": {"input": "id[]=1", "path": "an array skips the cast and reaches cursor.execute"},
            "behavior_risk": "none",
        })
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic=critic_answer)
        with _env():
            [result] = _run(provider, [_fixable()])
        assert result["llm_triage"]["verdict"] == "true_positive"
        assert "remediation_patch" not in result
        critic = result["llm_triage"]["fix_critic"]
        assert critic["accepted"] is False and critic["reason"] == "counterexample"
        assert critic["counterexample"]["input"] == "id[]=1"
        extra = result["evidence_details"]["extra"]
        assert extra["fix_critic_accepted"] is False
        assert extra["fix_critic_reason"] == "counterexample"
        assert extra["fix_critic_counterexample"] == "id[]=1"

    def test_a_rejected_fix_is_withheld_from_an_untriaged_sibling_with_the_same_patch(self):
        # The sibling is not selected for triage (cap of one finding), so it would reach the
        # cross-tier fold still carrying the deterministic patch the critic just broke.
        critic_answer = json.dumps({"counterexample": {"input": "id[]=1", "path": "array"}, "behavior_risk": "none"})
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic=critic_answer)
        checked = _fixable("fp-1", "critical")
        sibling = _fixable("fp-2", "low", rule_id="opengrep.sql", remediation_patch=FIX)
        other_file = _fixable("fp-3", "low", file_path="other.py", remediation_patch=FIX)
        with _env(), patch.object(llm_triage, "LLM_TRIAGE_MAX_FINDINGS", 1):
            result = _run(provider, [checked, sibling, other_file])
        by_fp = {f["fingerprint"]: f for f in result}
        assert "remediation_patch" not in by_fp["fp-1"]
        assert "remediation_patch" not in by_fp["fp-2"]
        assert by_fp["fp-2"]["evidence_details"]["extra"]["fix_critic_reason"] == "same_fix_rejected"
        assert by_fp["fp-3"]["remediation_patch"] == FIX
        assert sibling["remediation_patch"] == FIX, "the caller's finding is not modified"

    def test_critic_sees_the_original_the_patch_and_the_payload(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX))
        with _env():
            _run(provider, [_fixable()])
        [critic_call] = provider.of_kind("critic")
        prompt = critic_call["prompt"]
        assert "## Original lines" in prompt and 'query = f"SELECT * FROM users WHERE id = {user_id}"' in prompt
        assert "## Proposed replacement" in prompt and FIX in prompt
        assert "## Exploit payload before the patch" in prompt and "1 OR 1=1" in prompt
        assert "sql.injection.raw_query" in prompt

    @pytest.mark.parametrize("answer", [
        "NONE",
        '"NONE"',
        json.dumps({"counterexample": None, "behavior_risk": "none"}),
        json.dumps({"counterexample": "n/a", "behavior_risk": None}),
        "```json\n{\"counterexample\": null, \"behavior_risk\": \"none\"}\n```",
    ])
    def test_no_counterexample_attaches_the_fix(self, answer):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic=answer)
        with _env():
            [result] = _run(provider, [_fixable()])
        assert result["remediation_patch"] == FIX
        assert result["llm_triage"]["fix_critic"]["accepted"] is True
        assert result["evidence_details"]["extra"]["fix_critic_accepted"] is True

    def test_behavior_risk_is_recorded_with_an_accepted_fix(self):
        answer = json.dumps({"counterexample": None, "behavior_risk": "Callers passing a non-numeric id now get a database error."})
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic=answer)
        with _env():
            [result] = _run(provider, [_fixable()])
        assert result["remediation_patch"] == FIX
        assert "non-numeric id" in result["evidence_details"]["extra"]["fix_critic_behavior_risk"]

    def test_unreadable_critic_answer_withholds_the_fix(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic="Looks fine to me.")
        with _env():
            [result] = _run(provider, [_fixable()])
        assert "remediation_patch" not in result
        assert result["llm_triage"]["fix_critic"]["reason"] == "critic_unparseable"

    def test_critic_failure_withholds_the_fix(self):
        def broken(prompt, fps):
            raise RuntimeError("provider 503")

        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic=broken)
        with _env():
            [result] = _run(provider, [_fixable()])
        assert "remediation_patch" not in result
        assert result["llm_triage"]["fix_critic"]["reason"] == "critic_failed"
        assert result["llm_triage"]["verdict"] == "true_positive"

    def test_critic_runs_on_the_deterministic_fallback_fix_too(self):
        counterexample = json.dumps({"counterexample": {"input": "1; DROP TABLE users", "path": "still concatenated"}, "behavior_risk": "none"})
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=None), critic=counterexample)
        finding = _fixable(file_path="app.js", code_snippet='db.query("SELECT * FROM users WHERE id = " + userId);')
        payload_for_js = dict(GOOD_PAYLOAD, entrypoint="app.js:10 GET /users?id=")
        provider.triage = lambda prompt, fps: _confirm(fps, payload=payload_for_js, fixed_code=None)
        with _env():
            [result] = _run(provider, [finding], {"app.js": '+db.query("SELECT * FROM users WHERE id = " + userId);\n'})
        assert "remediation_patch" not in result
        assert len(provider.of_kind("critic")) == 1

    def test_critic_is_not_called_when_nothing_would_be_attached(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX))
        with _env():
            [result] = _run(provider, [_finding()])  # not auto_fix_eligible
        assert provider.of_kind("critic") == []
        assert "remediation_patch" not in result
        assert "fix_critic" not in result["llm_triage"]

    def test_critic_off_attaches_the_fix_unchecked(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX), critic="should not be called")
        with _env(LLM_TRIAGE_CRITIC_ENABLED="false"):
            [result] = _run(provider, [_fixable()])
        assert result["remediation_patch"] == FIX
        assert provider.of_kind("critic") == []
        assert "fix_critic" not in result["llm_triage"]

    @pytest.mark.parametrize("raw, expected", [
        ("NONE", None),
        (json.dumps({"counterexample": {"input": "x' OR '1'='1", "reaches_sink_via": "quote unbalanced"}}), "x' OR '1'='1"),
        (json.dumps({"counterexample": "../../etc/passwd"}), "../../etc/passwd"),
        (json.dumps({"counterexample": {"input": "", "path": "none"}}), None),
    ])
    def test_parse_critic_response_shapes(self, raw, expected):
        parsed = _parse_critic_response(raw)
        assert (parsed["counterexample"] or {}).get("input") == expected

    @pytest.mark.parametrize("raw", ["not json", "[]", '"a bare opinion"', "42"])
    def test_parse_critic_response_rejects_junk(self, raw):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_critic_response(raw)


# ── flags off: the previous behaviour ────────────────────────────────────


class TestFlagsOff:
    def test_all_flags_off_is_one_batched_call_that_confirms_and_attaches_unchecked(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, payload=None, fixed_code=FIX), critic="should not be called")
        findings = [_fixable("c", "critical"), _fixable("h", "high"), _fixable("l", "low")]
        with _env(LLM_TRIAGE_REQUIRE_PAYLOAD="false", LLM_TRIAGE_CRITIC_ENABLED="false", LLM_TRIAGE_ISOLATE_SEVERITY="none"):
            result = _run(provider, findings)
        assert [call["fingerprints"] for call in provider.calls] == [["c", "h", "l"]]
        assert all(f["llm_triage"]["verdict"] == "true_positive" for f in result)
        assert all(f["remediation_patch"] == FIX for f in result)
        assert all(f["llm_triage"]["downgrade"] is None for f in result)
        assert all("extra" not in f["evidence_details"] for f in result)


# ── failures fail closed ─────────────────────────────────────────────────


class TestFailClosed:
    @pytest.mark.parametrize("isolate", ["high", "none"])
    def test_unparseable_answer_keeps_the_finding_as_uncertain_without_its_patch(self, isolate):
        provider = FakeProvider("I could not decide.")
        finding = _fixable(remediation_patch=FIX)
        with _env(LLM_TRIAGE_ISOLATE_SEVERITY=isolate):
            [result] = _run(provider, [finding])
        assert result["llm_triage"]["verdict"] == "uncertain"
        assert result["llm_triage"]["downgrade"] == {"to": "uncertain", "reason": "parse_error"}
        assert result["evidence_details"]["extra"]["triage_downgrade_reason"] == "parse_error"
        assert "triage_downgraded_from" not in result["evidence_details"]["extra"]
        assert result["confidence"] == 0.7
        assert "remediation_patch" not in result

    @pytest.mark.parametrize("answer", ['{"note": "no findings"}', '"true_positive"', "42"])
    def test_an_answer_that_is_not_a_verdict_list_fails_the_batch_closed(self, answer):
        findings = [_fixable("fp-1", "medium"), _fixable("fp-2", "low")]
        with _env(LLM_TRIAGE_ISOLATE_SEVERITY="none"), \
                patch.object(llm_triage, "call_llm", return_value=LLMResponse(answer, 1, 1, "fake", "fake")):
            result = triage_findings(findings, {"app.py": "+code"})
        assert [f["llm_triage"]["verdict"] for f in result] == ["uncertain", "uncertain"]
        assert all(f["llm_triage"]["downgrade"]["reason"] == "parse_error" for f in result)

    def test_a_single_verdict_object_or_a_wrapped_list_is_read(self):
        one = json.loads(_confirm(["fp-1"]))[0]
        assert [v["fingerprint"] for v in llm_triage._parse_triage_response(json.dumps(one), {"fp-1"})] == ["fp-1"]
        wrapped = json.dumps({"verdicts": [one]})
        assert [v["fingerprint"] for v in llm_triage._parse_triage_response(wrapped, {"fp-1"})] == ["fp-1"]

    def test_isolated_answer_about_another_finding_fails_closed(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(["somebody-else"]))
        with _env():
            [result] = _run(provider, [_finding()])
        assert result["llm_triage"]["downgrade"]["reason"] == "parse_error"

    def test_provider_error_on_one_call_leaves_only_that_finding_untriaged(self):
        def flaky(prompt, fps):
            if fps == ["c"]:
                raise RuntimeError("provider 503")
            return _confirm(fps)

        provider = FakeProvider(flaky)
        with _env():
            result = _run(provider, [_finding("c", "critical"), _finding("h", "high")])
        by_fp = {f["fingerprint"]: f for f in result}
        assert "llm_triage" not in by_fp["c"]
        assert by_fp["h"]["llm_triage"]["verdict"] == "true_positive"

    def test_an_unexpected_failure_still_returns_the_findings(self):
        findings = [_finding()]
        with _env(), patch.object(llm_triage, "_split_for_isolation", side_effect=RuntimeError("boom")):
            result = triage_findings(findings, {})
        assert result == findings


# ── budget ───────────────────────────────────────────────────────────────


class TestBudget:
    def test_budget_counts_calls_and_tokens(self):
        budget = TriageBudget(max_calls=2, max_tokens=1000)
        assert budget.allows_call()
        budget.record(300, 100)
        budget.record(300, 100)
        assert not budget.allows_call()
        assert "2/2 calls" in budget.summary() and "800/1000 tokens" in budget.summary()

        budget = TriageBudget(max_calls=10, max_tokens=500)
        budget.record(400, 100)
        assert not budget.allows_call()

    def test_call_cap_passes_the_remaining_findings_through_untriaged(self, capsys):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps))
        findings = [_finding("a", "critical"), _finding("b", "critical"), _finding("c", "high")]
        with _env(LLM_TRIAGE_MAX_CALLS="2"):
            result = _run(provider, findings)
        by_fp = {f["fingerprint"]: f for f in result}
        assert by_fp["a"]["llm_triage"]["verdict"] == "true_positive"
        assert by_fp["b"]["llm_triage"]["verdict"] == "true_positive"
        assert "llm_triage" not in by_fp["c"]
        assert len(provider.calls) == 2
        assert "1 calls refused covering 1 findings" in capsys.readouterr().out

    def test_token_cap_stops_further_calls(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps), tokens=(100, 50))
        with _env(LLM_TRIAGE_MAX_TOKENS="120"):
            result = _run(provider, [_finding("a", "critical"), _finding("b", "critical")])
        assert len(provider.calls) == 1
        assert sum("llm_triage" in f for f in result) == 1

    def test_critic_refused_by_the_cap_withholds_the_fix(self):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX))
        with _env(LLM_TRIAGE_MAX_CALLS="1"):
            [result] = _run(provider, [_fixable()])
        assert result["llm_triage"]["verdict"] == "true_positive"
        assert "remediation_patch" not in result
        assert result["llm_triage"]["fix_critic"]["reason"] == "budget_exhausted"
        assert provider.of_kind("critic") == []

    def test_budget_is_logged_per_run(self, capsys):
        provider = FakeProvider(lambda prompt, fps: _confirm(fps, fixed_code=FIX))
        with _env():
            _run(provider, [_fixable("a", "critical"), _finding("b", "low")])
        out = capsys.readouterr().out
        assert "1 isolated + 1 batched" in out
        assert "budget 3/24 calls, 450/300000 tokens" in out
