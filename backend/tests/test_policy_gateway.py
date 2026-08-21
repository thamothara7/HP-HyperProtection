from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_controlled_app_exposes_decoy_only_when_policy_gate_passes() -> None:
    response = client.get("/corp/admin/credentials", headers={"X-InsiderGuard-Session": "SES-A817"})
    assert response.status_code == 200
    assert response.json()["route"] == "DECOY"
    assert response.json()["payload"]["synthetic"] is True


def test_legitimate_override_never_receives_decoy() -> None:
    response = client.get("/corp/admin/credentials", headers={"X-InsiderGuard-Session": "SES-B208"})
    assert response.status_code == 200
    assert response.json()["route"] == "REAL"
