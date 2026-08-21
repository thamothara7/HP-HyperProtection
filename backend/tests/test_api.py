from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_overview_returns_session_scoped_attention() -> None:
    response = client.get("/api/v1/overview")
    assert response.status_code == 200
    session = response.json()["attention_sessions"][0]
    assert session["id"] == "SES-A817"
    assert session["identity_id"] == "USR-A12"
    assert session["is_contained"] is True


def test_containment_does_not_change_identity_scope() -> None:
    response = client.post("/api/v1/sessions/SES-C441/contain")
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "REVOKE_APPLICATION_SESSION"
    assert body["session"]["id"] == "SES-C441"
