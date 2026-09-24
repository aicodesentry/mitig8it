"""Correlation identifiers that travel with the work instead of with the signature.

Same contract as the Node services: one identifier set per unit of work, carried in
contextvars so no call site has to thread it through, and written into every log line
as a single JSON object with a Cloud Logging ``severity``.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional, Tuple

# Field name to the header (and gRPC metadata key) it travels on. gRPC metadata keys
# must be lowercase ASCII, which these already are, so one table serves both.
FIELD_HEADERS: Dict[str, str] = {
    "delivery_id": "x-github-delivery",
    "analysis_run_id": "x-analysis-run-id",
    "job_id": "x-job-id",
    "correlation_id": "x-correlation-id",
}

FIELDS: Tuple[str, ...] = tuple(FIELD_HEADERS)

_context: contextvars.ContextVar[Dict[str, str]] = contextvars.ContextVar(
    "mitig8it_request_context", default={}
)

_MAX_VALUE_LENGTH = 200


def sanitize(value: Any) -> Optional[str]:
    """Identifiers arrive from GitHub and from peer services.

    A newline in one would forge a second log line out of a single record, and an
    unbounded one would bloat every record that follows it.
    """
    if value is None:
        return None
    text = str(value).replace("\r", "").replace("\n", "").replace("\x00", "").strip()
    if not text:
        return None
    return text[:_MAX_VALUE_LENGTH]


def _clean(fields: Mapping[str, Any]) -> Dict[str, str]:
    cleaned: Dict[str, str] = {}
    for field in FIELDS:
        value = sanitize(fields.get(field))
        if value:
            cleaned[field] = value
    return cleaned


def current() -> Dict[str, str]:
    return dict(_context.get())


@contextmanager
def use(fields: Mapping[str, Any]) -> Iterator[Dict[str, str]]:
    """Adds identifiers to whatever is already in scope for the duration of the block."""
    merged = {**current(), **_clean(fields)}
    token = _context.set(merged)
    try:
        yield merged
    finally:
        _context.reset(token)


def assign(fields: Mapping[str, Any]) -> Dict[str, str]:
    """For an identifier only learned partway through the work."""
    merged = {**current(), **_clean(fields)}
    _context.set(merged)
    return merged


def from_headers(headers: Mapping[str, Any]) -> Dict[str, str]:
    fields = {}
    for field, header in FIELD_HEADERS.items():
        fields[field] = headers.get(header) or headers.get(header.upper())
    return _clean(fields)


def from_grpc_metadata(metadata: Optional[Iterable[Tuple[str, Any]]]) -> Dict[str, str]:
    if not metadata:
        return {}
    pairs = {str(key).lower(): value for key, value in metadata}
    return from_headers(pairs)


def to_headers(**extra: Any) -> Dict[str, str]:
    """Outbound headers. Only fields that are actually known are sent, so an empty
    header never claims a correlation that does not exist."""
    fields = {**current(), **_clean(extra)}
    return {FIELD_HEADERS[field]: value for field, value in fields.items() if value}


def to_grpc_metadata(**extra: Any) -> Tuple[Tuple[str, str], ...]:
    return tuple(to_headers(**extra).items())


_SEVERITY = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}

_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", (), None)))


class JsonContextFormatter(logging.Formatter):
    """One JSON object per line, with the correlation fields already in it.

    Cloud Logging reads ``severity`` and ``message`` off such a line and promotes them
    onto the entry, so the same format is both machine-parsable locally and native in
    production.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "severity": _SEVERITY.get(record.levelno, "DEFAULT"),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
            "logger": record.name,
        }
        payload.update(current())
        # Anything passed through `extra=` wins over the ambient context: a call site
        # logging about another run's id must be able to say so.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            # The classification, never the stack: a traceback can carry source.
            payload["error_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "unknown"
        return json.dumps(payload, default=str)


def configure_logging(level: str | int | None = None) -> None:
    """Installs the JSON formatter on the root logger, once."""
    root = logging.getLogger()
    resolved = level or "INFO"
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonContextFormatter())
    root.handlers = [handler]
    root.setLevel(resolved)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
