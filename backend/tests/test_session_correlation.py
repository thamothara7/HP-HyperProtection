from datetime import UTC, datetime, timedelta

import pytest

from app.normalization.event import EventCategory, EventType, NormalizedEvent
from app.sessions.correlator import SessionCorrelator


def event(event_id: str, *, session_id: str | None, device_id: str = "MGR-PC", event_type: EventType = EventType.AUTH_SUCCESS) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 22, 9, 0, tzinfo=UTC) + timedelta(minutes=int(event_id[-1])),
        identity_id="USR-A12",
        session_id=session_id,
        device_id=device_id,
        event_type=event_type,
        event_category=EventCategory.AUTHENTICATION,
        source=device_id,
        action="login",
        result="success",
    )


def test_concurrent_contexts_for_one_identity_remain_separate() -> None:
    correlator = SessionCorrelator()
    manager = correlator.ingest(event("evt-1", session_id="SES-A18", device_id="MGR-PC"))
    employee = correlator.ingest(event("evt-2", session_id="SES-A92", device_id="EMP-PC"))
    assert manager.identity_id == employee.identity_id
    assert manager.device_id != employee.device_id
    assert manager.session_id != employee.session_id


def test_fallback_context_key_includes_device() -> None:
    correlator = SessionCorrelator()
    first = correlator.ingest(event("evt-3", session_id=None, device_id="MGR-PC"))
    second = correlator.ingest(event("evt-4", session_id=None, device_id="EMP-PC"))
    assert first.session_id != second.session_id


def test_mismatched_context_is_not_silently_merged() -> None:
    correlator = SessionCorrelator()
    correlator.ingest(event("evt-5", session_id="SES-A18", device_id="MGR-PC"))
    with pytest.raises(ValueError):
        correlator.ingest(event("evt-6", session_id="SES-A18", device_id="EMP-PC"))
