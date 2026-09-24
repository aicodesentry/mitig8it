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


def test_analysis_limitations_survive_the_response_wire_roundtrip():
    """A limitation is useless if it stops at the service boundary."""
    from analysis_grpc_server import _parse_analysis_response

    payload = {
        "repository_full_name": "owner/repo",
        "pull_request_number": 135,
        "commit_sha": "a" * 40,
        "files_analyzed": 12,
        "tier": 2,
        "findings": [],
        "analysis_limitations": [
            {
                "path": "svc/cwe-vul.py",
                "kind": "partial_parse",
                "type": "Lexical error",
                "message": "unrecognized symbol in string",
                "line": 127,
            },
            {
                "path": "svc/huge.ts",
                "kind": "not_analyzed",
                "type": "Timeout",
                "message": "timed out",
                "line": None,
            },
        ],
    }

    decoded = analysis_pb2.AnalyzePullRequestResponse.FromString(
        _parse_analysis_response(payload).SerializeToString()
    )

    assert [limitation.path for limitation in decoded.analysis_limitations] == [
        "svc/cwe-vul.py",
        "svc/huge.ts",
    ]
    assert decoded.analysis_limitations[0].kind == "partial_parse"
    assert decoded.analysis_limitations[0].type == "Lexical error"
    assert decoded.analysis_limitations[0].line == 127
    assert decoded.analysis_limitations[1].type == "Timeout"
    assert decoded.analysis_limitations[1].line == 0


def test_a_response_without_limitations_stays_empty():
    from analysis_grpc_server import _parse_analysis_response

    response = _parse_analysis_response({
        "repository_full_name": "owner/repo",
        "pull_request_number": 1,
        "commit_sha": "a" * 40,
        "findings": [],
    })
    assert list(response.analysis_limitations) == []
