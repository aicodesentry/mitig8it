"""Write the JSON schema of the RepairRequest contract so other services can validate
the payloads they build against it. Run from the service directory:

    python scripts/export_repair_request_schema.py

The committed copy is checked against the model by tests/test_contract_schema.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models import RepairRequest  # noqa: E402

TARGET = ROOT / "contracts" / "repair-request.schema.json"


def render() -> str:
    return json.dumps(RepairRequest.model_json_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    TARGET.write_text(render(), encoding="utf-8")
    print(f"wrote {TARGET}")
