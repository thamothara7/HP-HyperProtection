"""Correlate telemetry into identity × session × device contexts."""

from dataclasses import dataclass, field
from datetime import datetime

from app.normalization.event import EventType, NormalizedEvent


@dataclass(slots=True)
class CorrelatedSession:
    session_id: str
    identity_id: str
    device_id: str
    started_at: datetime
    last_seen: datetime
    events: list[NormalizedEvent] = field(default_factory=list)
    closed_at: datetime | None = None


class SessionCorrelator:
    """Small in-memory correlator used before a durable session repository exists.

    A supplied logon identifier is preferred. When a source lacks it, the
    identity/device context remains isolated rather than being merged with a
    different device for the same identity.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, CorrelatedSession] = {}

    def ingest(self, event: NormalizedEvent) -> CorrelatedSession:
        session_id = event.session_id or f"CTX-{event.identity_id}-{event.device_id}"
        session = self._sessions.get(session_id)
        if session is None:
            session = CorrelatedSession(
                session_id=session_id,
                identity_id=event.identity_id,
                device_id=event.device_id,
                started_at=event.timestamp,
                last_seen=event.timestamp,
            )
            self._sessions[session_id] = session
        if session.identity_id != event.identity_id or session.device_id != event.device_id:
            raise ValueError("A session cannot span identity or device contexts")
        session.events.append(event)
        session.last_seen = max(session.last_seen, event.timestamp)
        if event.event_type is EventType.LOGOFF:
            session.closed_at = event.timestamp
        return session

    def get(self, session_id: str) -> CorrelatedSession | None:
        return self._sessions.get(session_id)
