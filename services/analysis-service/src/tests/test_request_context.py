import json
import logging

import pytest

import request_context


@pytest.fixture(autouse=True)
def _reset_context():
    yield


def test_identifiers_reach_a_nested_call_without_being_passed_to_it():
    def inner():
        return request_context.current()

    with request_context.use({"delivery_id": "delivery-1", "analysis_run_id": "run-1"}):
        assert inner() == {"delivery_id": "delivery-1", "analysis_run_id": "run-1"}

    assert request_context.current() == {}


def test_grpc_metadata_from_the_api_becomes_the_context_for_the_call():
    # Exactly the metadata the API's gRPC client sends.
    metadata = (
        ("x-github-delivery", "delivery-2"),
        ("x-analysis-run-id", "run-2"),
        ("x-serverless-authorization", "Bearer token"),
    )

    fields = request_context.from_grpc_metadata(metadata)

    assert fields == {"delivery_id": "delivery-2", "analysis_run_id": "run-2"}


def test_http_headers_round_trip_through_outbound_headers():
    inbound = {
        "x-github-delivery": "delivery-3",
        "x-analysis-run-id": "run-3",
        "x-job-id": "job-3",
        "x-correlation-id": "corr-3",
    }
    with request_context.use(request_context.from_headers(inbound)):
        assert request_context.to_headers() == inbound


def test_an_unknown_identifier_is_never_carried():
    assert request_context.from_headers({"x-secret": "value"}) == {}


def test_a_newline_in_an_identifier_cannot_forge_a_second_log_line():
    fields = request_context.from_headers({"x-github-delivery": 'abc\n{"severity":"ERROR"}'})
    assert fields["delivery_id"] == 'abc{"severity":"ERROR"}'


def test_an_oversized_identifier_is_bounded():
    fields = request_context.from_headers({"x-correlation-id": "x" * 5000})
    assert len(fields["correlation_id"]) == 200


def test_every_log_line_is_one_json_object_with_severity_and_the_context(capsys):
    request_context.configure_logging("INFO")
    logger = request_context.get_logger("mitig8it.analysis.test")

    with request_context.use({"delivery_id": "delivery-4", "analysis_run_id": "run-4"}):
        logger.warning("tier2 skipped a file", extra={"path": "src/app.py"})

    line = capsys.readouterr().out.strip()
    assert "\n" not in line
    entry = json.loads(line)
    assert entry["severity"] == "WARNING"
    assert entry["message"] == "tier2 skipped a file"
    assert entry["delivery_id"] == "delivery-4"
    assert entry["analysis_run_id"] == "run-4"
    assert entry["path"] == "src/app.py"


def test_an_explicit_field_wins_over_the_ambient_context(capsys):
    request_context.configure_logging("INFO")
    logger = request_context.get_logger("mitig8it.analysis.test")

    with request_context.use({"analysis_run_id": "run-5"}):
        logger.info("about another run", extra={"analysis_run_id": "run-6"})

    assert json.loads(capsys.readouterr().out.strip())["analysis_run_id"] == "run-6"


def test_an_exception_is_classified_rather_than_logged_with_its_stack(capsys):
    request_context.configure_logging("INFO")
    logger = request_context.get_logger("mitig8it.analysis.test")

    try:
        raise ValueError("secret in the message")
    except ValueError:
        logger.error("tier failed", exc_info=True)

    entry = json.loads(capsys.readouterr().out.strip())
    assert entry["error_type"] == "ValueError"
    assert "Traceback" not in json.dumps(entry)


def test_logging_is_restored_to_a_plain_handler_for_other_suites():
    logging.getLogger().handlers = []
