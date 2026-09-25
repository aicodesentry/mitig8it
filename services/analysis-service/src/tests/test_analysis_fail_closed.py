from unittest.mock import patch
import pytest
from main import AnalyzePRRequest, analyze_tier2_payload
from opengrep_runner import run_opengrep


def test_tier2_does_not_turn_detector_failure_into_clean_scan():
    request = AnalyzePRRequest(repository_full_name='owner/repo', pull_request_number=1, commit_sha='a', files=[{'path':'app.py', 'patch':'+eval(user_input)'}])
    with patch('main.run_opengrep_with_limitations', side_effect=RuntimeError('detector unavailable')):
        with pytest.raises(RuntimeError):
            analyze_tier2_payload(request)


def test_missing_detector_is_a_failed_scan():
    with patch('opengrep_runner.subprocess.run', side_effect=FileNotFoundError()):
        with pytest.raises(RuntimeError):
            run_opengrep([{'path':'app.py','patch':'+eval(user_input)'}])


@pytest.mark.parametrize('output', ['{}', '{"results": [], "errors": [{"type":"Timeout"}]}'])
def test_incomplete_detector_output_cannot_be_clean(output):
    from subprocess import CompletedProcess
    with patch('opengrep_runner.subprocess.run', return_value=CompletedProcess([], 0, stdout=output, stderr='')):
        with pytest.raises(RuntimeError):
            run_opengrep([{'path':'app.py','patch':'+eval(user_input)'}])
