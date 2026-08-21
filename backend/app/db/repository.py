from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import DeviceRecord, EventRecord, IdentityRecord, ResponseActionRecord, SessionRecord
from app.schemas import Intent, SessionDetail, SessionStatus, SessionSummary, TimelineEvent


def session_summary(record: SessionRecord) -> SessionSummary:
    return SessionSummary(id=record.id, identity_id=record.identity_id, device_id=record.device_id, risk_score=record.risk_score, intent=Intent(record.intent), intent_confidence=record.intent_confidence, status=SessionStatus(record.status), started_at=record.started_at, is_contained=record.is_contained, approved_override=record.approved_override)


def session_detail(db: Session, session_id: str) -> SessionDetail | None:
    record = db.get(SessionRecord, session_id)
    if record is None:
        return None
    events = db.scalars(select(EventRecord).where(EventRecord.session_id == session_id).order_by(EventRecord.timestamp)).all()
    timeline = [TimelineEvent(timestamp=event.timestamp, event_type=event.event_type, title=event.action.replace("_", " ").title(), detail=str(event.metadata_json.get("detail", event.action)), risk_change=event.metadata_json.get("risk_change")) for event in events]
    features = record.features or {}
    comparison = [tuple(row) for row in features.get("baseline_comparison", [])]
    return SessionDetail(**session_summary(record).model_dump(), anomaly_score=record.anomaly_score, sequence_score=record.sequence_score, device_deviation=features.get("device_deviation", "Unknown"), new_hosts=int(features.get("new_hosts", 0)), remote_access_ratio=float(features.get("remote_access_ratio", 0)), privilege_attempts=int(features.get("privilege_attempts", 0)), reason_codes=record.evidence or [], timeline=timeline, baseline_comparison=comparison)


def list_session_details(db: Session) -> list[SessionDetail]:
    ids = db.scalars(select(SessionRecord.id).order_by(SessionRecord.risk_score.desc())).all()
    return [detail for session_id in ids if (detail := session_detail(db, session_id)) is not None]


def contain(db: Session, session_id: str) -> SessionSummary | None:
    record = db.get(SessionRecord, session_id)
    if record is None:
        return None
    record.is_contained = True
    record.status = SessionStatus.CONTAINED.value
    db.add(ResponseActionRecord(session_id=session_id, action="REVOKE_APPLICATION_SESSION", reason="Analyst containment action; identity remains active in other contexts."))
    db.commit()
    db.refresh(record)
    return session_summary(record)


def ensure_identity_and_device(db: Session, identity_id: str, device_id: str) -> None:
    if db.get(IdentityRecord, identity_id) is None:
        db.add(IdentityRecord(id=identity_id, department="Demo", role="Employee"))
    if db.get(DeviceRecord, device_id) is None:
        db.add(DeviceRecord(id=device_id, first_seen=datetime.now(UTC), last_seen=datetime.now(UTC)))
    # Make pending rows observable to subsequent identities/sessions in a batch.
    db.flush()
