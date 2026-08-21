"""Durable normalized-event ingestion and session-scoped evaluation."""
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.baseline.persistence import (
    load_peer_profile,
    load_personal_baseline,
    save_peer_profile,
    save_personal_baseline,
    trusted_vectors,
)
from app.db.models import EventRecord, IntentDetectionRecord, RiskSnapshotRecord, SessionRecord
from app.db.repository import ensure_identity_and_device
from app.detection.intent import classify_intent
from app.detection.rules import evaluate_rules
from app.detection.sequence import SequenceMemory
from app.features.extractor import extract_features
from app.features.rolling import feature_snapshot, rolling_features
from app.ml.isolation_forest import SessionAnomalyModel
from app.normalization.event import EventCategory, EventType, NormalizedEvent
from app.risk.engine import compose_risk
from app.schemas import SessionStatus
from app.sessions.drift import within_session_drift


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
    # The session factory deliberately disables autoflush. Evaluation must include this event.
    db.flush()
    session.last_seen = max(session.last_seen, event.timestamp)
    if event.event_type is EventType.LOGOFF:
        session.closed_at = event.timestamp
    _evaluate(db, session)
    db.commit()
    db.refresh(session)
    return session


def _evaluate(db: Session, session: SessionRecord) -> None:
    records = db.scalars(select(EventRecord).where(EventRecord.session_id == session.id).order_by(EventRecord.timestamp)).all()
    normalized = [NormalizedEvent(event_id=item.id, timestamp=item.timestamp, identity_id=item.identity_id, session_id=item.session_id, device_id=item.device_id, event_type=EventType(item.event_type), event_category=EventCategory(item.event_category), source=item.source, target=item.target, resource_type=item.resource_type, resource_sensitivity=item.resource_sensitivity, action=item.action, result=item.result, metadata=item.metadata_json) for item in records]
    if not normalized:
        return
    personal, personal_record = load_personal_baseline(db, session.identity_id)
    peer, peer_record = load_peer_profile(db, session.identity_id)
    windows = rolling_features(normalized, known_targets=personal.known_targets)
    features = windows["5m"]
    personal_deviation = personal.deviation(
        device_id=session.device_id,
        target_count=features.unique_target_count,
        sensitive_reads=features.sensitive_resource_reads,
        after_hours=features.after_hours_score,
    )
    peer_deviation = peer.deviation(features)

    model = SessionAnomalyModel()
    vectors = trusted_vectors(personal_record)
    anomaly = 0.0
    if len(vectors) >= 10:
        model.fit(vectors)
        anomaly = model.score(features.vector())

    # Rebuild bounded sequence memory from persisted events: quiet gaps and restarts cannot
    # erase a low-and-slow progression.
    sequence_memory = SequenceMemory()
    sequence = 0.0
    for event in normalized:
        sequence = sequence_memory.ingest(session.id, event.event_type.value)

    current_start = normalized[-1].timestamp - timedelta(minutes=5)
    earlier_events = [event for event in normalized[:-1] if event.timestamp < current_start]
    drift = 0.0
    if earlier_events:
        earlier = extract_features(earlier_events, window_end=earlier_events[-1].timestamp)
        drift = within_session_drift(earlier, features)
    concurrent = db.scalar(select(func.count()).select_from(SessionRecord).where(SessionRecord.identity_id == session.identity_id, SessionRecord.closed_at.is_(None))) or 0
    hits = evaluate_rules(features, concurrent_sessions=concurrent, new_device=bool(personal.known_devices and session.device_id not in personal.known_devices))
    intent = classify_intent(features, sequence)
    risk = compose_risk(anomaly=anomaly, personal_deviation=personal_deviation, peer_deviation=peer_deviation, sequence=sequence, drift=drift, rule_hits=[(hit.score, hit.evidence) for hit in hits], resource_sensitivity=min(100, features.sensitive_resource_reads * 5))
    session.risk_score, session.anomaly_score, session.sequence_score = risk.score, round(anomaly), round(sequence)
    session.intent, session.intent_confidence, session.evidence = intent.intent, intent.confidence, risk.explanation + intent.evidence
    if not session.is_contained:
        session.status = SessionStatus.HIGH.value if session.risk_score >= 51 else SessionStatus.ELEVATED.value if session.risk_score >= 31 else SessionStatus.NORMAL.value
    session.features = {
        "failed_logins": features.failed_logins,
        "unique_target_count": features.unique_target_count,
        "sensitive_resource_reads": features.sensitive_resource_reads,
        "after_hours_score": features.after_hours_score,
        "personal_deviation": round(personal_deviation),
        "peer_deviation": round(peer_deviation),
        "within_session_drift": round(drift),
        "rolling_windows": {name: feature_snapshot(value) for name, value in windows.items()},
        "baseline_comparison": [
            ["Target systems", str(round(sum(personal.target_counts) / len(personal.target_counts))) if personal.target_counts else "Learning", str(features.unique_target_count)],
            ["Sensitive reads", str(round(sum(personal.sensitive_reads) / len(personal.sensitive_reads))) if personal.sensitive_reads else "Learning", str(features.sensitive_resource_reads)],
        ],
    }
    db.add(RiskSnapshotRecord(session_id=session.id, risk_score=session.risk_score, components=risk.components, explanation=session.evidence))
    db.add(IntentDetectionRecord(session_id=session.id, intent=intent.intent, confidence=intent.confidence, evidence=intent.evidence))

    # Learn only after final risk composition. This prevents the evaluated event from
    # establishing a trusted device or reshaping a profile while it is suspicious.
    personal.update(
        device_id=session.device_id,
        target_count=features.unique_target_count,
        sensitive_reads=features.sensitive_resource_reads,
        after_hours=features.after_hours_score,
        risk_score=risk.score,
        targets={event.target for event in normalized if event.target},
    )
    peer.update(features, risk.score)
    save_personal_baseline(db, identity_id=session.identity_id, baseline=personal, record=personal_record, features=features, risk_score=risk.score)
    save_peer_profile(db, peer, peer_record)
