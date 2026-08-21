"""Durable normalized-event ingestion and session-scoped evaluation."""
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import EventRecord, RiskSnapshotRecord, SessionRecord
from app.db.repository import ensure_identity_and_device
from app.detection.intent import classify_intent
from app.detection.rules import evaluate_rules
from app.detection.sequence import SequenceMemory
from app.features.extractor import extract_features
from app.normalization.event import EventType, NormalizedEvent
from app.risk.engine import compose_risk
from app.schemas import SessionStatus

_sequence_memory = SequenceMemory()


def ingest_event(db: Session, event: NormalizedEvent) -> SessionRecord:
    """Persist original normalized security metadata and update only its context."""
    if db.get(EventRecord, event.event_id) is not None:
        session_id = event.session_id or f"CTX-{event.identity_id}-{event.device_id}"
        existing = db.get(SessionRecord, session_id)
        if existing is None:
            raise ValueError("Duplicate event references no session")
        return existing
    ensure_identity_and_device(db, event.identity_id, event.device_id)
    session_id = event.session_id or f"CTX-{event.identity_id}-{event.device_id}"
    session = db.get(SessionRecord, session_id)
    if session is None:
        session = SessionRecord(id=session_id, identity_id=event.identity_id, device_id=event.device_id, started_at=event.timestamp, last_seen=event.timestamp, features={}, evidence=[])
        db.add(session)
        db.flush()
    if session.identity_id != event.identity_id or session.device_id != event.device_id:
        raise ValueError("Session identity/device context mismatch")
    db.add(EventRecord(id=event.event_id, timestamp=event.timestamp, identity_id=event.identity_id, session_id=session_id, device_id=event.device_id, event_type=event.event_type.value, event_category=event.event_category.value, source=event.source, target=event.target, resource_type=event.resource_type, resource_sensitivity=event.resource_sensitivity, action=event.action, result=event.result, metadata_json=event.metadata))
    session.last_seen = max(session.last_seen, event.timestamp)
    if event.event_type is EventType.LOGOFF:
        session.closed_at = event.timestamp
    _evaluate(db, session)
    db.commit()
    db.refresh(session)
    return session


def _evaluate(db: Session, session: SessionRecord) -> None:
    records = db.scalars(select(EventRecord).where(EventRecord.session_id == session.id).order_by(EventRecord.timestamp)).all()
    normalized = [NormalizedEvent(event_id=item.id, timestamp=item.timestamp, identity_id=item.identity_id, session_id=item.session_id, device_id=item.device_id, event_type=EventType(item.event_type), event_category=item.event_category, source=item.source, target=item.target, resource_type=item.resource_type, resource_sensitivity=item.resource_sensitivity, action=item.action, result=item.result, metadata=item.metadata_json) for item in records]
    features = extract_features(normalized)
    concurrent = db.scalar(select(func.count()).select_from(SessionRecord).where(SessionRecord.identity_id == session.identity_id, SessionRecord.closed_at.is_(None))) or 0
    hits = evaluate_rules(features, concurrent_sessions=concurrent, new_device=False)
    sequence = _sequence_memory.ingest(session.id, normalized[-1].event_type.value) if normalized else 0.0
    intent = classify_intent(features, sequence)
    risk = compose_risk(anomaly=0, personal_deviation=0, peer_deviation=0, sequence=sequence, drift=0, rule_hits=[(hit.score, hit.evidence) for hit in hits], resource_sensitivity=min(100, features.sensitive_resource_reads * 5))
    session.risk_score, session.sequence_score = risk.score, round(sequence)
    session.intent, session.intent_confidence, session.evidence = intent.intent, intent.confidence, risk.explanation + intent.evidence
    session.status = SessionStatus.HIGH.value if session.risk_score >= 51 else SessionStatus.ELEVATED.value if session.risk_score >= 31 else SessionStatus.NORMAL.value
    session.features = {"failed_logins": features.failed_logins, "unique_target_count": features.unique_target_count, "sensitive_resource_reads": features.sensitive_resource_reads}
    db.add(RiskSnapshotRecord(session_id=session.id, risk_score=session.risk_score, components=risk.components, explanation=session.evidence))
