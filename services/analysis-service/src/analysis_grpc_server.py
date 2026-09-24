import os
import sys
from concurrent import futures
from pathlib import Path
from typing import Any, Dict

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from google.protobuf.json_format import MessageToDict, ParseDict

import request_context
from main import (
    AnalyzePRRequest,
    TriageRequest,
    analyze_pull_request_payload,
    analyze_tier1_payload,
    analyze_tier2_payload,
    triage_findings_payload,
)

GENERATED_DIR = Path(__file__).resolve().parent / "grpc" / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

import analysis_pb2  # noqa: E402
import analysis_pb2_grpc  # noqa: E402
import common_pb2  # noqa: E402


def _message_to_dict(message) -> Dict[str, Any]:
    return MessageToDict(
        message,
        preserving_proto_field_name=True,
        use_integers_for_enums=True,
    )


def _drop_none(value):
    if isinstance(value, dict):
        return {key: _drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value if item is not None]
    return value


def _analysis_request_from_proto(request) -> AnalyzePRRequest:
    payload = _message_to_dict(request)
    # Proto3 omits default scalars from JSON; zero identifies a playground scan.
    payload["pull_request_number"] = request.pull_request_number
    return AnalyzePRRequest(**payload)


def _triage_request_from_proto(request) -> TriageRequest:
    payload = _message_to_dict(request)
    payload["pull_request_number"] = request.pull_request_number
    repo_profile = payload.get("repo_profile") or {}
    if isinstance(repo_profile, dict) and "data" in repo_profile:
        payload["repo_profile"] = repo_profile.get("data") or {}
    return TriageRequest(**payload)


def _parse_analysis_response(payload: Dict[str, Any]):
    response = analysis_pb2.AnalyzePullRequestResponse()
    ParseDict(_drop_none(payload), response, ignore_unknown_fields=True)
    return response


def _parse_triage_response(payload: Dict[str, Any]):
    response = analysis_pb2.TriageFindingsResponse()
    ParseDict(_drop_none(payload), response, ignore_unknown_fields=True)
    return response


def _abort_invalid_request(context, error: Exception) -> None:
    context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(error))


def _abort_internal(context, error: Exception) -> None:
    context.abort(grpc.StatusCode.INTERNAL, str(error))


class AnalysisGrpcService(analysis_pb2_grpc.AnalysisServiceServicer):
    def AnalyzePullRequest(self, request, context):
        try:
            payload = analyze_pull_request_payload(_analysis_request_from_proto(request))
            return _parse_analysis_response(payload)
        except ValueError as error:
            _abort_invalid_request(context, error)
        except Exception as error:
            _abort_internal(context, error)

    def AnalyzeTier1(self, request, context):
        try:
            payload = analyze_tier1_payload(_analysis_request_from_proto(request))
            return _parse_analysis_response(payload)
        except ValueError as error:
            _abort_invalid_request(context, error)
        except Exception as error:
            _abort_internal(context, error)

    def AnalyzeTier2(self, request, context):
        try:
            payload = analyze_tier2_payload(_analysis_request_from_proto(request))
            return _parse_analysis_response(payload)
        except ValueError as error:
            _abort_invalid_request(context, error)
        except Exception as error:
            _abort_internal(context, error)

    def TriageFindings(self, request, context):
        try:
            payload = triage_findings_payload(_triage_request_from_proto(request))
            return _parse_triage_response(payload)
        except ValueError as error:
            _abort_invalid_request(context, error)
        except Exception as error:
            _abort_internal(context, error)

    def HealthCheck(self, request, context):
        return common_pb2.HealthCheckResponse(
            status="ok",
            service="analysis-service",
            version="1.0.0",
        )


class CorrelationInterceptor(grpc.ServerInterceptor):
    """Adopts the caller's identifiers from the call metadata before the handler runs.

    One interceptor rather than a line in every method: a handler that forgot the line
    would be the one whose logs an operator cannot find.
    """

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None or not handler.unary_unary:
            return handler

        fields = request_context.from_grpc_metadata(handler_call_details.invocation_metadata)

        def wrapped(request, context):
            with request_context.use(fields):
                return handler.unary_unary(request, context)

        return grpc.unary_unary_rpc_method_handler(
            wrapped,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


def create_server() -> grpc.Server:
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=int(os.getenv("GRPC_WORKERS", "10"))),
        interceptors=(CorrelationInterceptor(),),
    )
    analysis_pb2_grpc.add_AnalysisServiceServicer_to_server(AnalysisGrpcService(), server)
    health_servicer = health.HealthServicer()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    health_servicer.set("mitig8it.analysis.v1.AnalysisService", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    return server


def serve() -> None:
    port = int(os.getenv("ANALYSIS_GRPC_PORT") or os.getenv("PORT", "50052"))
    server = create_server()
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    request_context.get_logger("mitig8it.analysis.grpc").info(
        "Analysis gRPC service listening", extra={"port": port}
    )
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
