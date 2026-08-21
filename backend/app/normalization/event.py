"""Normalized security events.

Windows Event Log parsing will be an adapter that produces this model; downstream
analytics must never depend on Windows XML layout or EventRecord objects.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EventType(StrEnum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    LOGOFF = "LOGOFF"
    EXPLICIT_CREDENTIALS = "EXPLICIT_CREDENTIALS"
    PRIVILEGED_ACTIVITY = "PRIVILEGED_ACTIVITY"
    PROCESS_CREATED = "PROCESS_CREATED"
    SHARE_ACCESS = "SHARE_ACCESS"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    DISCOVERY = "DISCOVERY"
    REMOTE_ACCESS = "REMOTE_ACCESS"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    RESOURCE_ACCESS = "resource_access"
    PRIVILEGE = "privilege"
    DISCOVERY = "discovery"
    PROCESS = "process"


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    identity_id: str
    device_id: str
    event_type: EventType
    event_category: EventCategory
    source: str
    target: str | None = None
    session_id: str | None = None
    resource_type: str | None = None
    resource_sensitivity: int = Field(default=0, ge=0, le=5)
    action: str
    result: str
    metadata: dict[str, Any] = Field(default_factory=dict)
