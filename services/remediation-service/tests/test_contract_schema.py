from pathlib import Path

from scripts.export_repair_request_schema import TARGET, render


def test_committed_repair_request_schema_matches_model():
    assert TARGET.exists(), "run scripts/export_repair_request_schema.py"
    assert Path(TARGET).read_text(encoding="utf-8") == render(), "schema drifted; rerun scripts/export_repair_request_schema.py"
