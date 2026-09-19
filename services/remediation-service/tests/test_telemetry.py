from __future__ import annotations

import pytest

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from src import telemetry

CANARY_BEARER = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
CANARY_OPENAI = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
CANARY_GITHUB = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
CANARY_GITHUB_SERVER = "ghs_abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.fixture
def exporter(monkeypatch):
    """Installs a real SDK tracer with an in-memory exporter, as if an endpoint were set."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.invalid:4318")
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(memory))
    telemetry.reset_for_tests()
    monkeypatch.setattr(telemetry, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(telemetry, "_configured", True)
    yield memory
    telemetry.reset_for_tests()


def test_tracing_is_inert_without_an_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    telemetry.reset_for_tests()
    assert telemetry.is_enabled() is False
    assert telemetry.configure() is False
    assert telemetry.current_traceparent() is None
    with telemetry.stage_span("agent_attempt", **{"mitig8it.job_id": "job-1"}) as span:
        assert span.is_recording() is False
        span.set_attribute("mitig8it.job_id", "job-1")
    with telemetry.linked_span("remediation.repair", "00-" + "a" * 32 + "-" + "b" * 16 + "-01") as span:
        assert span.is_recording() is False
    telemetry.reset_for_tests()


def test_only_allowlisted_attributes_are_exported(exporter):
    with telemetry.stage_span(
        "agent_attempt",
        **{
            "mitig8it.job_id": "job-1",
            "mitig8it.attempt": 2,
            "mitig8it.cost_usd": 0.004,
            "mitig8it.patch": "const query = 'SELECT 1';",
            "http.url": "https://api.github.com/repos/acme/widget",
            "source": "function loadUser() {}",
        },
    ):
        pass
    attributes = dict(exporter.get_finished_spans()[0].attributes)
    assert attributes == {
        "mitig8it.stage": "agent_attempt",
        "mitig8it.job_id": "job-1",
        "mitig8it.attempt": 2,
        "mitig8it.cost_usd": 0.004,
    }


def test_an_unknown_stage_is_a_programming_error(exporter):
    with pytest.raises(ValueError):
        with telemetry.stage_span("exfiltrate"):
            pass


@pytest.mark.parametrize("canary", [CANARY_BEARER, CANARY_OPENAI, CANARY_GITHUB, CANARY_GITHUB_SERVER])
def test_the_redaction_guard_rejects_secret_canaries(canary):
    assert telemetry.attribute_rejection("mitig8it.outcome", canary) == "secret_like_value"
    assert telemetry.safe_attributes({"mitig8it.outcome": canary}) == {}


def test_the_redaction_guard_rejects_oversized_values():
    assert telemetry.attribute_rejection("mitig8it.outcome", "x" * 257) == "value_too_long"
    assert telemetry.attribute_rejection("mitig8it.outcome", "x" * 256) is None


def test_a_secret_canary_never_reaches_an_exported_span(exporter):
    with telemetry.stage_span("verification", **{"mitig8it.outcome": CANARY_GITHUB, "mitig8it.job_id": "job-1"}):
        pass
    span = exporter.get_finished_spans()[0]
    assert CANARY_GITHUB not in str(dict(span.attributes))
    assert "mitig8it.outcome" not in span.attributes


def test_a_resumed_stage_links_to_the_persisted_trace_context_instead_of_reparenting(exporter):
    tracer = telemetry._tracer
    with tracer.start_as_current_span("intake"):
        traceparent = telemetry.current_traceparent()
    assert traceparent is not None
    intake = exporter.get_finished_spans()[0]

    with telemetry.linked_span("remediation.repair", traceparent, **{"mitig8it.job_id": "job-1"}):
        pass
    resumed = exporter.get_finished_spans()[1]
    assert resumed.parent is None
    assert len(resumed.links) == 1
    assert resumed.links[0].context.span_id == intake.context.span_id
    assert resumed.links[0].context.trace_id == intake.context.trace_id


def test_an_unparsable_persisted_trace_context_yields_an_unlinked_span(exporter):
    with telemetry.linked_span("remediation.repair", "not-a-traceparent"):
        pass
    resumed = exporter.get_finished_spans()[0]
    assert resumed.parent is None
    assert not resumed.links


def test_an_incoming_request_continues_the_callers_trace(exporter):
    tracer = telemetry._tracer
    with tracer.start_as_current_span("caller"):
        traceparent = telemetry.current_traceparent()
    caller = exporter.get_finished_spans()[0]
    with telemetry.request_span("remediation.intake", traceparent, **{"mitig8it.job_id": "job-1"}):
        pass
    intake = exporter.get_finished_spans()[1]
    assert intake.parent.span_id == caller.context.span_id
    assert intake.context.trace_id == caller.context.trace_id


def test_record_outcome_never_raises_on_a_broken_span():
    class Exploding:
        def set_attribute(self, key, value):
            raise RuntimeError("exporter is down")

    telemetry.record_outcome(Exploding(), "ready")


def test_request_attributes_expose_only_versions_and_identity(request_payload):
    from src.models import RepairRequest

    attributes = telemetry.request_attributes(RepairRequest.model_validate(request_payload))
    assert attributes == {
        "mitig8it.job_id": "job-1",
        "mitig8it.model_version": "repair-model-1",
        "mitig8it.prompt_version": "v1",
        "mitig8it.policy_version": "policy-1",
    }
    assert set(attributes).issubset(telemetry.ALLOWED_ATTRIBUTES)


def test_configure_downgrades_to_no_op_when_the_exporter_cannot_be_built(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.invalid:4318")
    telemetry.reset_for_tests()
    import opentelemetry.sdk.trace as sdk_trace

    def explode(*args, **kwargs):
        raise RuntimeError("no exporter")

    monkeypatch.setattr(sdk_trace, "TracerProvider", explode)
    assert telemetry.configure() is False
    with telemetry.stage_span("batch") as span:
        assert span.is_recording() is False
    telemetry.reset_for_tests()
