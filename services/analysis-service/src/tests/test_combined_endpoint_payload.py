"""`/analyze/pr` must hand tier 2 the same file payload `/analyze/pr/tier2` gets.

The combined endpoint used to forward only `{path, patch}`, so it scanned a
reconstruction of the diff while the split endpoint scanned the head content of the
same file. The two therefore reported different findings, and different line numbers,
for the same pull request.
"""

from unittest.mock import patch as mock_patch

import main
from main import AnalyzePRRequest, ChangedFile


def _request() -> AnalyzePRRequest:
    return AnalyzePRRequest(
        repository_full_name="acme/app",
        pull_request_number=7,
        commit_sha="a" * 40,
        files=[
            ChangedFile(
                path="svc/handler.py",
                patch="@@ -1,1 +1,2 @@\n+import os\n",
                content="import os\nos.system(name)\n",
                reviewable_line_spans=[{"start": 1, "end": 2}],
            )
        ],
    )


class TestCombinedEndpointForwardsContent:
    def test_content_and_spans_reach_the_scanner(self):
        seen = {}

        def fake_run_opengrep(files):
            seen["files"] = files
            return []

        with mock_patch.object(main, "run_opengrep", fake_run_opengrep):
            main.analyze_pull_request_payload(_request())

        assert seen["files"] == [{
            "path": "svc/handler.py",
            "patch": "@@ -1,1 +1,2 @@\n+import os\n",
            "content": "import os\nos.system(name)\n",
            "reviewable_line_spans": [{"start": 1, "end": 2}],
        }]

    def test_the_two_endpoints_agree_on_the_scanner_payload(self):
        combined = {}
        split = {}

        def record(store):
            def fake_run_opengrep(files):
                store["files"] = files
                return []
            return fake_run_opengrep

        with mock_patch.object(main, "run_opengrep", record(combined)):
            main.analyze_pull_request_payload(_request())
        with mock_patch.object(main, "run_opengrep", record(split)):
            main.analyze_tier2_payload(_request())

        assert combined["files"] == split["files"]
