from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from app.baseline.persistence import load_personal_baseline, save_personal_baseline
from app.db.bootstrap import create_schema
from app.db.models import BaselineProfileRecord, IdentityRecord
from app.db.session import SessionLocal
from app.features.extractor import SessionFeatures
from app.ingestion import ingest_event
from app.normalization.event import EventCategory, EventType, NormalizedEvent


def _features(targets: int, reads: int) -> SessionFeatures:
    return SessionFeatures(0, 1, targets, 0, 0, 0, reads, 0.0, 0, ("AUTH_SUCCESS",))


def test_persisted_personal_baseline_never_learns_high_risk_device() -> None:
    create_schema()
    identity_id = "USR-PERSISTENCE-TEST"
    with SessionLocal() as db:
        db.query(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == identity_id).delete()
        db.query(IdentityRecord).where(IdentityRecord.id == identity_id).delete()
        db.add(IdentityRecord(id=identity_id, department="Test", role="Analyst"))
        db.commit()

        baseline, record = load_personal_baseline(db, identity_id)
        normal = _features(2, 3)
        baseline.update(device_id="MGR-PC", target_count=2, sensitive_reads=3, after_hours=0, risk_score=8)
        record = save_personal_baseline(db, identity_id=identity_id, baseline=baseline, record=record, features=normal, risk_score=8)
        db.commit()

        baseline, record = load_personal_baseline(db, identity_id)
        suspicious = _features(42, 180)
        baseline.update(device_id="EMP-PC", target_count=42, sensitive_reads=180, after_hours=1, risk_score=88)
        save_personal_baseline(db, identity_id=identity_id, baseline=baseline, record=record, features=suspicious, risk_score=88)
        db.commit()

        persisted, stored = load_personal_baseline(db, identity_id)
        assert "MGR-PC" in persisted.known_devices
        assert "EMP-PC" not in persisted.known_devices
        assert stored is not None
        assert stored.trusted_observations == 1
        assert len(stored.profile["trusted_vectors"]) == 1

        db.query(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == identity_id).delete()
        db.query(IdentityRecord).where(IdentityRecord.id == identity_id).delete()
        db.commit()


def test_ingestion_evaluates_current_event_before_persisting_trust() -> None:
    create_schema()
    suffix = uuid4().hex
    event = NormalizedEvent(
        event_id=f"evt-baseline-ingestion-{suffix}",
        timestamp=datetime(2026, 8, 22, 9, tzinfo=UTC),
        identity_id=f"USR-INGEST-BASELINE-{suffix}",
        session_id=f"SES-INGEST-BASELINE-{suffix}",
        device_id=f"MGR-PC-{suffix}",
        event_type=EventType.AUTH_SUCCESS,
        event_category=EventCategory.AUTHENTICATION,
        source="MGR-PC-TEST",
        target="CORP-SRV",
        action="login",
        result="success",
    )
    with SessionLocal() as db:
        db.query(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == event.identity_id).delete()
        db.query(IdentityRecord).where(IdentityRecord.id == event.identity_id).delete()
        db.commit()
        session = ingest_event(db, event)
        profile = db.scalar(select(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == event.identity_id))
        assert session.features["unique_target_count"] == 1
        assert profile is not None
        assert profile.trusted_observations == 1
