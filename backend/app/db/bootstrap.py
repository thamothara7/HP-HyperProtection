"""Create local development schema and safe synthetic seed data.

Production deployments use Alembic migrations; this keeps the prototype runnable
without silently treating fixture data as operational telemetry.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EventRecord, SessionRecord
from app.db.repository import ensure_identity_and_device
from app.db.session import Base, engine
from app.simulation.store import seed_sessions


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)


def seed_demo_if_empty(db: Session) -> None:
    if db.scalar(select(SessionRecord.id).limit(1)) is not None:
        return
    for detail in seed_sessions().values():
        ensure_identity_and_device(db, detail.identity_id, detail.device_id)
        db.add(SessionRecord(
            id=detail.id, identity_id=detail.identity_id, device_id=detail.device_id,
            started_at=detail.started_at, last_seen=detail.timeline[-1].timestamp if detail.timeline else detail.started_at,
            risk_score=detail.risk_score, anomaly_score=detail.anomaly_score, sequence_score=detail.sequence_score,
            intent=detail.intent.value, intent_confidence=detail.intent_confidence, status=detail.status.value,
            is_contained=detail.is_contained, approved_override=detail.approved_override,
            evidence=detail.reason_codes,
            features={"device_deviation": detail.device_deviation, "new_hosts": detail.new_hosts, "remote_access_ratio": detail.remote_access_ratio, "privilege_attempts": detail.privilege_attempts, "baseline_comparison": [list(row) for row in detail.baseline_comparison]},
        ))
    db.flush()
    for detail in seed_sessions().values():
        for index, item in enumerate(detail.timeline):
            db.add(EventRecord(id=f"EVT-{detail.id}-{index}", timestamp=item.timestamp, identity_id=detail.identity_id, session_id=detail.id, device_id=detail.device_id, event_type=item.event_type, event_category="simulation", source=detail.device_id, action=item.title, result="success", metadata_json={"detail": item.detail, "risk_change": item.risk_change}))
    db.commit()
