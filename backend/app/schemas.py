"""Boundary schemas for the initial API vertical slice.

These remain deliberately independent of database and telemetry-source types.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class SessionStatus(StrEnum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    DECEPTION_ELIGIBLE = "DECEPTION_ELIGIBLE"
    DECEPTION = "DECEPTION"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"


class Intent(StrEnum):
    NONE = "NONE"
    RECON = "RECON"
    CREDENTIAL_HUNTING = "CREDENTIAL_HUNTING"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_COLLECTION = "DATA_COLLECTION"
    EXFIL_ATTEMPT = "EXFIL_ATTEMPT"


class SessionSummary(BaseModel):
    id: str
    identity_id: str
    device_id: str
    risk_score: int = Field(ge=0, le=100)
    intent: Intent
    intent_confidence: float = Field(ge=0, le=1)
    status: SessionStatus
    started_at: datetime
    is_contained: bool = False
    approved_override: bool = False


class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    title: str
    detail: str
    risk_change: int | None = None


class OverviewResponse(BaseModel):
    active_sessions: int
    elevated_sessions: int
    critical_sessions: int
    risk_activity: list[int]
    attention_sessions: list[SessionSummary]
    generated_at: datetime


class SessionDetail(SessionSummary):
    anomaly_score: int
    sequence_score: int
    device_deviation: str
    new_hosts: int
    remote_access_ratio: float
    privilege_attempts: int
    reason_codes: list[str]
    timeline: list[TimelineEvent]
    baseline_comparison: list[tuple[str, str, str]]


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    expected_outcome: str


class ContainmentResponse(BaseModel):
    session: SessionSummary
    action: str
    message: str
