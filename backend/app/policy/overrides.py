"""Lifecycle-aware legitimate-operation overrides."""

from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import ApprovalRecord, SessionRecord


def has_active_override(db: Session, identity_id: str, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    approvals = db.scalars(
        select(ApprovalRecord).where(
            ApprovalRecord.identity_id == identity_id,
            ApprovalRecord.active.is_(True),
            or_(ApprovalRecord.expires_at.is_(None), ApprovalRecord.expires_at > now),
        )
    ).all()
    return bool(approvals)


def refresh_identity_override(db: Session, identity_id: str) -> bool:
    """Synchronize active application contexts after creation, expiry, or revocation."""
    effective = has_active_override(db, identity_id)
    for session in db.scalars(select(SessionRecord).where(SessionRecord.identity_id == identity_id, SessionRecord.closed_at.is_(None))).all():
        session.approved_override = effective
    return effective
