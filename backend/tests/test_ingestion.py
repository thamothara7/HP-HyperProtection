from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_normalized_event_is_persisted_in_its_own_session_context() -> None:
    payload = {"event_id": "real-test-event-001", "timestamp": datetime.now(UTC).isoformat(), "identity_id": "USR-REAL-TEST", "session_id": "SES-REAL-TEST", "device_id": "WIN-REAL-TEST", "event_type": "AUTH_SUCCESS", "event_category": "authentication", "source": "WIN-REAL-TEST", "target": "CORP-SRV", "action": "login", "result": "success", "metadata": {"source_kind": "windows"}}
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["id"] == "SES-REAL-TEST"
    assert body["identity_id"] == "USR-REAL-TEST"
    assert body["device_id"] == "WIN-REAL-TEST"
