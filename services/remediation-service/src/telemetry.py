"""OpenTelemetry tracing for the repair workflow, with an allowlist and a redaction guard.

Section 10 of the implementation plan requires W3C trace context across the workflow, span
links for resumed asynchronous stages, and allowlisted attributes with redaction applied
before export. It also requires that a telemetry exporter failure never crashes the workflow.

Three rules hold here and are enforced in code, not by convention:

1. Tracing is configured only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Unset means every
   helper in this module is an inert no-op, so a development or test run exports nothing.
2. Only allowlisted attribute names are exported. An unknown name is dropped, never renamed
   or truncated into something exportable.
3. Source, prompts, completions, patches, tool output, and secrets never reach a span. The
   redaction guard rejects any value longer than 256 characters and any value matching a
   secret-like pattern, which is a backstop under the allowlist, not a substitute for it.
"""
from __future__ import annotations

import logging
import os
import re
from contextlib import contextmanager
from typing import Any, Iterator

logger = logging.getLogger("mitig8it.remediation.telemetry")

TRACER_NAME = "mitig8it.remediation"
ENDPOINT_VARIABLE = "OTEL_EXPORTER_OTLP_ENDPOINT"
MAX_ATTRIBUTE_CHARS = 256

STAGES = ("snapshot_bind", "retrieval", "template_verification", "agent_attempt", "agent_retry", "verification", "batch")

# The complete set of attributes this service is allowed to export. Everything else is
# dropped, including anything a future caller adds without extending this list.
ALLOWED_ATTRIBUTES = frozenset(
    {
        "mitig8it.job_id",
        "mitig8it.stage",
        "mitig8it.attempt",
        "mitig8it.model_version",
        "mitig8it.prompt_version",
        "mitig8it.policy_version",
        "mitig8it.outcome",
        "mitig8it.error_category",
        "mitig8it.input_tokens",
        "mitig8it.output_tokens",
        "mitig8it.cost_usd",
    }
)

SECRET_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}"),
)

try:  # pragma: no cover - exercised by whichever dependency set is installed.
    from opentelemetry import trace as _trace
    from opentelemetry.trace import Link, Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - the service degrades to no-op tracing.
    _trace = None
    Link = Status = StatusCode = None
    TraceContextTextMapPropagator = None
    _OTEL_AVAILABLE = False

_tracer: Any | None = None
_configured = False


class _NoOpSpan:
    """Accepts the same calls as a real span and records nothing."""

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def set_attributes(self, attributes: dict[str, Any]) -> None:
        return None

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        return None

    def is_recording(self) -> bool:
        return False


def attribute_rejection(name: str, value: Any) -> str | None:
    """Returns why this attribute must not be exported, or None when it may be.

    This is the redaction guard. It is deliberately independent of the allowlist so it can be
    tested directly with a secret canary.
    """
    if name not in ALLOWED_ATTRIBUTES:
        return "not_allowlisted"
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return None
    if not isinstance(value, str):
        return "unsupported_attribute_type"
    if len(value) > MAX_ATTRIBUTE_CHARS:
        return "value_too_long"
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        return "secret_like_value"
    return None


def safe_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Returns only the attributes that are allowlisted and pass the redaction guard."""
    kept: dict[str, Any] = {}
    for name, value in attributes.items():
        if value is None:
            continue
        reason = attribute_rejection(name, value)
        if reason is None:
            kept[name] = value
        else:
            # The rejected value is never logged; only its name and the reason.
            logger.debug("remediation telemetry attribute dropped", extra={"attribute": name, "reason": reason})
    return kept


def is_enabled() -> bool:
    return bool(os.getenv(ENDPOINT_VARIABLE, "").strip()) and _OTEL_AVAILABLE


def configure() -> bool:
    """Configures the tracer provider once. Returns True when a real tracer is active.

    Any failure to build an exporter is logged and downgraded to no-op tracing, because a
    telemetry misconfiguration must not stop repairs.
    """
    global _tracer, _configured
    if _configured:
        return _tracer is not None
    _configured = True
    if not is_enabled():
        return False
    try:  # pragma: no cover - requires the SDK and an endpoint.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": os.getenv("OTEL_SERVICE_NAME", "remediation-service"),
                "service.version": os.getenv("REMEDIATION_SERVICE_VERSION", "unknown"),
            }
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        _trace.set_tracer_provider(provider)
        _tracer = _trace.get_tracer(TRACER_NAME)
        return True
    except Exception:  # noqa: BLE001 - telemetry setup never fails the workflow.
        logger.warning("remediation telemetry could not be configured; continuing without traces")
        _tracer = None
        return False


def reset_for_tests() -> None:
    """Clears the cached provider selection. Test-only."""
    global _tracer, _configured
    _tracer = None
    _configured = False


def _tracer_or_none() -> Any | None:
    configure()
    return _tracer


def current_traceparent() -> str | None:
    """The W3C `traceparent` of the active span, or None when tracing is inert."""
    if _tracer_or_none() is None:
        return None
    try:
        carrier: dict[str, str] = {}
        TraceContextTextMapPropagator().inject(carrier)
        return carrier.get("traceparent")
    except Exception:  # noqa: BLE001
        return None


def _span_context(traceparent: str | None) -> Any | None:
    if not traceparent or not _OTEL_AVAILABLE:
        return None
    try:
        context = TraceContextTextMapPropagator().extract({"traceparent": traceparent})
        span_context = _trace.get_current_span(context).get_span_context()
        return span_context if span_context.is_valid else None
    except Exception:  # noqa: BLE001 - an unparsable header is simply not propagated.
        return None


@contextmanager
def request_span(name: str, traceparent: str | None = None, **attributes: Any) -> Iterator[Any]:
    """A span continuing an incoming W3C trace context, for a synchronous HTTP request."""
    tracer = _tracer_or_none()
    if tracer is None:
        yield _NoOpSpan()
        return
    context = None
    if traceparent:
        try:
            context = TraceContextTextMapPropagator().extract({"traceparent": traceparent})
        except Exception:  # noqa: BLE001
            context = None
    with tracer.start_as_current_span(name, context=context, attributes=safe_attributes(attributes)) as span:
        yield span


@contextmanager
def linked_span(name: str, traceparent: str | None = None, **attributes: Any) -> Iterator[Any]:
    """A span for a resumed asynchronous stage.

    The persisted trace context becomes a span *link*, not a parent, because the worker runs
    long after the intake request finished. That is what the plan's trace contract asks for.
    """
    tracer = _tracer_or_none()
    if tracer is None:
        yield _NoOpSpan()
        return
    span_context = _span_context(traceparent)
    links = [Link(span_context)] if span_context is not None else None
    with tracer.start_as_current_span(name, links=links, attributes=safe_attributes(attributes)) as span:
        yield span


@contextmanager
def stage_span(stage: str, **attributes: Any) -> Iterator[Any]:
    """A span for one repair stage. `stage` must be one of `STAGES`."""
    if stage not in STAGES:
        raise ValueError(f"unknown repair stage: {stage}")
    tracer = _tracer_or_none()
    if tracer is None:
        yield _NoOpSpan()
        return
    payload = {"mitig8it.stage": stage, **attributes}
    with tracer.start_as_current_span(f"remediation.{stage}", attributes=safe_attributes(payload)) as span:
        yield span


def record_outcome(span: Any, outcome: str | None = None, error_category: str | None = None, **attributes: Any) -> None:
    """Records the outcome and any allowlisted counters on a span. Never raises."""
    try:
        payload = safe_attributes({"mitig8it.outcome": outcome, "mitig8it.error_category": error_category, **attributes})
        for name, value in payload.items():
            span.set_attribute(name, value)
        if error_category and Status is not None and hasattr(span, "set_status"):
            span.set_status(Status(StatusCode.ERROR))
    except Exception:  # noqa: BLE001 - telemetry never fails the workflow.
        logger.debug("remediation telemetry outcome could not be recorded")


def request_attributes(request: Any) -> dict[str, Any]:
    """The allowlisted identity attributes for one repair request."""
    versions = getattr(request, "versions", {}) or {}
    return {
        "mitig8it.job_id": getattr(request, "job_id", None),
        "mitig8it.model_version": versions.get("repair_model"),
        "mitig8it.prompt_version": versions.get("prompt"),
        "mitig8it.policy_version": getattr(getattr(request, "policy", None), "policy_version", None),
    }
