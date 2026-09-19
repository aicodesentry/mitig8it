from analysis_grpc_server import (
    _analysis_request_from_proto,
    _triage_request_from_proto,
    analysis_pb2,
)


def test_synthetic_zero_pr_number_survives_analysis_wire_roundtrip():
    request = analysis_pb2.AnalyzePullRequestRequest(
        repository_full_name="playground/code", pull_request_number=0, commit_sha="a" * 40
    )
    decoded = analysis_pb2.AnalyzePullRequestRequest.FromString(request.SerializeToString())
    assert _analysis_request_from_proto(decoded).pull_request_number == 0


def test_synthetic_zero_pr_number_survives_triage_wire_roundtrip():
    request = analysis_pb2.TriageFindingsRequest(
        repository_full_name="playground/code", pull_request_number=0, commit_sha="a" * 40
    )
    decoded = analysis_pb2.TriageFindingsRequest.FromString(request.SerializeToString())
    assert _triage_request_from_proto(decoded).pull_request_number == 0
