from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app


def test_ingestion_publishes_event_and_risk_updates() -> None:
    with TestClient(app) as client, client.websocket_connect("/ws/events") as event_socket, client.websocket_connect("/ws/risk") as risk_socket:
        response = client.post("/api/v1/events", json={"event_id": "ws-real-event-001", "timestamp": datetime.now(UTC).isoformat(), "identity_id": "USR-WS-TEST", "session_id": "SES-WS-TEST", "device_id": "WIN-WS-TEST", "event_type": "AUTH_SUCCESS", "event_category": "authentication", "source": "WIN-WS-TEST", "action": "login", "result": "success"})
        assert response.status_code == 201
        assert event_socket.receive_json()["event_id"] == "ws-real-event-001"
        assert risk_socket.receive_json()["session_id"] == "SES-WS-TEST"
