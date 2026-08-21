from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class IdentityRecord(Base):
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    department: Mapped[str | None] = mapped_column(String(120))
    role: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeviceRecord(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    trust_level: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[int] = mapped_column(Integer, default=0)
    sequence_score: Mapped[int] = mapped_column(Integer, default=0)
    intent: Mapped[str] = mapped_column(String(40), default="NONE")
    intent_confidence: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(40), default="NORMAL")
    is_contained: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_override: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)


class EventRecord(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    event_category: Mapped[str] = mapped_column(String(60))
    source: Mapped[str] = mapped_column(String(120))
    target: Mapped[str | None] = mapped_column(String(200))
    resource_type: Mapped[str | None] = mapped_column(String(80))
    resource_sensitivity: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(120))
    result: Mapped[str] = mapped_column(String(40))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class BaselineProfileRecord(Base):
    __tablename__ = "baseline_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), unique=True, index=True)
    profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    trusted_observations: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class PeerBaselineRecord(Base):
    __tablename__ = "peer_baselines"
    id: Mapped[int] = mapped_column(primary_key=True)
    department: Mapped[str] = mapped_column(String(120), index=True)
    role: Mapped[str] = mapped_column(String(120), index=True)
    profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RiskSnapshotRecord(Base):
    __tablename__ = "risk_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    risk_score: Mapped[int] = mapped_column(Integer)
    components: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    explanation: Mapped[list[str]] = mapped_column(JSON, default=list)


class IntentDetectionRecord(Base):
    __tablename__ = "intent_detections"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    intent: Mapped[str] = mapped_column(String(40))
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentRecord(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DecoyInteractionRecord(Base):
    __tablename__ = "decoy_interactions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    resource: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(80))
    confidence_delta: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class ResponseActionRecord(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    action: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApprovalRecord(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    approval_type: Mapped[str] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
