"""Persist and act on decoy evidence without widening containment to an identity."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import DecoyInteractionRecord, IncidentRecord, ResponseActionRecord, SessionRecord
from app.policy.engine import deception_allowed
from app.schemas import SessionStatus


def record_decoy_access(db: Session, *, session: SessionRecord, resource: str) -> None:
    """A decoy open corroborates suspicion but never contains by itself."""
    db.add(DecoyInteractionRecord(session_id=session.id, resource=resource, action="ACCESSED", confidence_delta=6, metadata_json={"synthetic": True}))
    session.risk_score = min(100, session.risk_score + 6)
    session.evidence = [*(session.evidence or []), f"Synthetic decoy resource accessed: {resource}."]
    db.commit()


def record_honey_credential_attempt(db: Session, *, session: SessionRecord, credential_id: str) -> SessionRecord:
    """Contain only after the strict gate is already satisfied and a honey ID is used."""
    decision = deception_allowed(
        risk_score=session.risk_score,
        intent=session.intent,
        intent_confidence=session.intent_confidence,
        strong_legitimate_override=session.approved_override,
    )
    if not decision.allow_decoy:
        raise PermissionError("The session is not eligible for honey-credential handling.")
    db.add(DecoyInteractionRecord(session_id=session.id, resource="/admin/credentials/attempt", action="HONEY_CREDENTIAL_ATTEMPTED", confidence_delta=20, metadata_json={"synthetic": True, "credential_id": credential_id}))
    session.risk_score = min(100, max(97, session.risk_score + 20))
    session.intent = "CREDENTIAL_HUNTING"
    session.intent_confidence = max(session.intent_confidence, 0.97)
    session.evidence = [*(session.evidence or []), "Synthetic honey credential identifier was attempted after the deception gate was satisfied."]
    session.is_contained = True
    session.status = SessionStatus.CONTAINED.value
    db.add(ResponseActionRecord(session_id=session.id, action="REVOKE_APPLICATION_SESSION", reason="Strong decoy evidence: synthetic honey credential attempted after strict deception eligibility."))
    existing_incident = db.scalar(select(IncidentRecord).where(IncidentRecord.session_id == session.id, IncidentRecord.status == "OPEN"))
    if existing_incident is None:
        db.add(IncidentRecord(id=f"INC-{uuid4().hex[:8].upper()}", session_id=session.id, title="Honey credential attempted in deception-eligible session", severity="CRITICAL", status="OPEN", summary="A synthetic credential identifier was attempted after high session risk and hostile intent satisfied the controlled deception gate."))
    db.commit()
    db.refresh(session)
    return session


def session_can_receive_decoy(session: SessionRecord) -> tuple[bool, str]:
    if session.is_contained:
        return False, "This application session is already contained."
    decision = deception_allowed(risk_score=session.risk_score, intent=session.intent, intent_confidence=session.intent_confidence, strong_legitimate_override=session.approved_override)
    return decision.allow_decoy, decision.reason
