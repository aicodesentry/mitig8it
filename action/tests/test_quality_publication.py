import json
import shutil
import subprocess
from pathlib import Path

import pytest

from orchestrator import run


def test_action_cannot_publish_fixes_with_current_release_evidence():
    assert not run.fix_publication_ready()


def test_action_fails_closed_for_missing_or_malformed_packaged_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("MITIG8IT_GITHUB_SERVICE_ROOT", str(tmp_path))
    assert not run.fix_publication_ready()
    (tmp_path / "src").mkdir()
    (tmp_path / "src/quality-release.json").write_text("null")
    assert not run.fix_publication_ready()


def test_local_action_cannot_reuse_an_independent_production_receipt(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[2]
    release = json.loads((root / "tests/fixtures/verified-quality-release.json").read_text())
    target = tmp_path / "src"
    target.mkdir()
    (target / "quality-release.json").write_text(json.dumps(release))
    monkeypatch.setenv("MITIG8IT_GITHUB_SERVICE_ROOT", str(tmp_path))
    assert not run.fix_publication_ready()


def test_review_explains_withheld_fixes_without_claiming_generation():
    if not shutil.which("node"):
        pytest.skip("node is required for publisher rendering")
    publisher = Path(__file__).resolve().parents[1] / "publisher/publish.js"
    script = (
        f"const publisher=require({json.dumps(str(publisher))});"
        "console.log(publisher.buildReviewBody({counts:{high:1},fixes:0,modelConfigured:true,"
        "fixesWithheldReason:'independent_release_evidence_missing'}));"
    )
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "Fix suggestions are withheld" in result.stdout
    assert "Fixes were generated" not in result.stdout
