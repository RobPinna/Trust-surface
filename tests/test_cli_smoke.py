from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from operational_leverage_framework.cli.main import main

LOCAL_TMP_ROOT = Path(__file__).resolve().parent / ".tmp_local"


def _make_local_tmp(prefix: str) -> Path:
    LOCAL_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = LOCAL_TMP_ROOT / f"{prefix}_{uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_trust_surface_cli_smoke() -> None:
    tmp = _make_local_tmp("trust_surface")
    input_path = tmp / "input.json"
    output_path = tmp / "result.json"

    input_payload = [
        {
            "url": "https://example.org/contact",
            "snippet": "Contact us at support@example.org",
            "signal_type": "CONTACT_CHANNEL",
            "is_boilerplate": False,
            "weight": 0.65,
            "quality_tier": "MED",
        },
        {
            "url": "https://example.org/billing",
            "snippet": "Billing update request process.",
            "signal_type": "PROCESS_CUE",
            "is_boilerplate": False,
            "weight": 0.8,
            "quality_tier": "HIGH",
        },
    ]
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    code = main([str(input_path), "--out", str(output_path), "--risk-type", "impersonation"])

    assert code == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(result.get("confidence"), int)
    assert isinstance(result.get("meta"), dict)


def test_app_health_smoke() -> None:
    tmp = _make_local_tmp("health")
    for module_name in list(sys.modules):
        if module_name == "app" or module_name.startswith("app."):
            sys.modules.pop(module_name, None)
    os.environ["RUNTIME_DIR"] = str(tmp.resolve())
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"

    from app.main import create_app

    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
