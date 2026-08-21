"""Explicitly labelled demo-event generator that uses the production ingestion path."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.ingestion import ingest_event
from app.normalization.event import EventCategory, EventType, NormalizedEvent


def run_scenario(db: Session, scenario_id: str) -> list[str]:
    """Generate safe simulation metadata only; it never reads endpoint/user content."""
    run_id = uuid4().hex[:10].upper()
    now = datetime.now(UTC)
    identity_id = f"USR-DEMO-{scenario_id[:8].upper()}"
    device_id = "MGR-PC-DEMO" if scenario_id in {"normal-manager", "deadline-day"} else "EMP-PC-DEMO"
    session_id = f"SIM-{run_id}"
    definition = _scenario_definition(scenario_id)
    session_ids: list[str] = []
    for index, (event_type, target, sensitivity, minute_offset) in enumerate(definition):
        event = NormalizedEvent(
            event_id=f"SIM-EVT-{run_id}-{index}",
            timestamp=now + timedelta(minutes=minute_offset),
            identity_id=identity_id,
            session_id=session_id,
            device_id=device_id,
            event_type=event_type,
            event_category=_category_for(event_type),
            source=device_id,
            target=target,
            resource_type="INTERNAL_APP",
            resource_sensitivity=sensitivity,
            action=event_type.value.lower(),
            result="failed" if event_type is EventType.AUTH_FAILURE else "success",
            metadata={"simulation": True, "scenario_id": scenario_id, "demo_run_id": run_id},
        )
        session = ingest_event(db, event)
        if session.id not in session_ids:
            session_ids.append(session.id)
    return session_ids


def _scenario_definition(scenario_id: str) -> list[tuple[EventType, str, int, int]]:
    if scenario_id == "normal-manager":
        return [(EventType.AUTH_SUCCESS, "FIN-PORTAL", 1, 0), (EventType.RESOURCE_ACCESS, "REPORTS", 2, 1)]
    if scenario_id == "deadline-day":
        return [(EventType.AUTH_SUCCESS, "PROJECT-REPO", 1, 0)] + [(EventType.RESOURCE_ACCESS, "PROJECT-REPO", 3, index) for index in range(1, 8)]
    if scenario_id == "stolen-credentials":
        return [(EventType.AUTH_SUCCESS, "CORP-PORTAL", 1, 0)] + [(EventType.DISCOVERY, f"SRV-{index:02d}", 1, index) for index in range(1, 7)] + [(EventType.AUTH_FAILURE, f"SRV-{index:02d}", 1, index + 6) for index in range(6)] + [(EventType.REMOTE_ACCESS, "ADMIN-SRV", 3, 13), (EventType.PRIVILEGED_ACTIVITY, "ADMIN-SRV", 3, 14), (EventType.EXPLICIT_CREDENTIALS, "CRED-VAULT", 4, 15)]
    if scenario_id == "session-hijack":
        return [(EventType.AUTH_SUCCESS, "FIN-PORTAL", 1, -20), (EventType.RESOURCE_ACCESS, "REPORTS", 2, -19)] + [(EventType.DISCOVERY, f"SRV-{index:02d}", 1, index) for index in range(1, 6)] + [(EventType.PRIVILEGED_ACTIVITY, "ADMIN-SRV", 4, 6)]
    if scenario_id == "low-and-slow":
        return [(EventType.AUTH_SUCCESS, "CORP-PORTAL", 1, -480), (EventType.DISCOVERY, "SRV-01", 1, -360), (EventType.REMOTE_ACCESS, "SRV-02", 2, -240), (EventType.PRIVILEGED_ACTIVITY, "ADMIN-SRV", 3, -120), (EventType.RESOURCE_ACCESS, "CRED-VAULT", 4, 0)]
    raise ValueError("Unknown simulation scenario")


def _category_for(event_type: EventType) -> EventCategory:
    if event_type in {EventType.AUTH_SUCCESS, EventType.AUTH_FAILURE, EventType.EXPLICIT_CREDENTIALS}:
        return EventCategory.AUTHENTICATION
    if event_type in {EventType.PRIVILEGED_ACTIVITY}:
        return EventCategory.PRIVILEGE
    if event_type in {EventType.DISCOVERY, EventType.REMOTE_ACCESS}:
        return EventCategory.DISCOVERY
    return EventCategory.RESOURCE_ACCESS
