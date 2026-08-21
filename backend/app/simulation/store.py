"""In-memory demo state for the first end-to-end slice.

Replacing this with SQLAlchemy repositories later must not change the API shape.
"""

from datetime import UTC, datetime, timedelta

from app.schemas import Intent, Scenario, SessionDetail, SessionStatus, TimelineEvent

NOW = datetime(2026, 8, 22, 2, 44, tzinfo=UTC)


def _event(minutes: int, event_type: str, title: str, detail: str, change: int | None = None) -> TimelineEvent:
    return TimelineEvent(timestamp=NOW + timedelta(minutes=minutes), event_type=event_type, title=title, detail=detail, risk_change=change)


SCENARIOS = [
    Scenario(id="normal-manager", name="Normal manager", description="Expected finance and reporting work from MGR-PC.", expected_outcome="Low risk; no alert or deception."),
    Scenario(id="deadline-day", name="Deadline-day legitimate work", description="Late bulk work with an approved project operation.", expected_outcome="Risk rises, but the verified override blocks deception."),
    Scenario(id="stolen-credentials", name="Stolen credentials", description="Alice's valid credentials are used from EMP-PC for credential hunting.", expected_outcome="Intent-gated decoy evidence leads to session-only containment."),
    Scenario(id="session-hijack", name="Session hijack", description="A previously normal session rapidly changes its access pattern.", expected_outcome="Within-session drift is highlighted for investigation."),
    Scenario(id="low-and-slow", name="Low-and-slow", description="Reconnaissance and export stages are spaced apart.", expected_outcome="Sequence memory preserves risk despite quiet intervals."),
]


def seed_sessions() -> dict[str, SessionDetail]:
    suspicious = SessionDetail(
        id="SES-A817", identity_id="USR-A12", device_id="EMP-PC-22", risk_score=97,
        intent=Intent.CREDENTIAL_HUNTING, intent_confidence=0.94, status=SessionStatus.CONTAINED,
        started_at=NOW - timedelta(minutes=13), is_contained=True, anomaly_score=91, sequence_score=94,
        device_deviation="High", new_hosts=9, remote_access_ratio=8.2, privilege_attempts=4,
        reason_codes=["New device context", "Concurrent manager session", "9 previously unseen hosts", "Credential-resource sequence", "Honey credential attempted"],
        timeline=[
            _event(-13, "AUTH_SUCCESS", "Successful login", "Valid manager credentials accepted from EMP-PC-22.", 0),
            _event(-11, "DISCOVERY", "Server enumeration", "Nine previously unseen hosts contacted in five minutes.", 16),
            _event(-8, "REMOTE_ACCESS", "Remote-access attempts", "Authentication attempts to privileged endpoints increased 8.2× baseline.", 19),
            _event(-6, "ADMIN_RESOURCE", "Admin discovery", "Admin and credential routes inspected.", 21),
            _event(-3, "DECEPTION", "Deception eligible", "High risk + credential-hunting intent; no legitimate override.", 12),
            _event(-2, "DECOY", "Honey credential attempted", "Synthetic service credential was submitted to a decoy endpoint.", 29),
            _event(0, "CONTAINMENT", "Application session contained", "Only SES-A817 was revoked; Alice's MGR-PC session remains active.", 0),
        ],
        baseline_comparison=[("Target systems", "3", "14"), ("Failed logins", "0", "8"), ("Admin resources", "1", "6"), ("Sensitive reads", "12", "173"), ("Devices", "1", "2")],
    )
    normal = SessionDetail(
        id="SES-A102", identity_id="USR-A12", device_id="MGR-PC", risk_score=8,
        intent=Intent.NONE, intent_confidence=0.04, status=SessionStatus.NORMAL, started_at=NOW - timedelta(hours=2),
        anomaly_score=6, sequence_score=4, device_deviation="None", new_hosts=0, remote_access_ratio=0.7, privilege_attempts=0,
        reason_codes=["Known manager device", "Expected finance/reporting workflow"], timeline=[_event(-120, "AUTH_SUCCESS", "Successful login", "Login from known manager device.")],
        baseline_comparison=[("Target systems", "3", "3"), ("Failed logins", "0", "0"), ("Admin resources", "1", "0"), ("Sensitive reads", "12", "8"), ("Devices", "1", "1")],
    )
    approved = SessionDetail(
        id="SES-B208", identity_id="USR-B91", device_id="PC-08", risk_score=76,
        intent=Intent.EXFIL_ATTEMPT, intent_confidence=0.49, status=SessionStatus.HIGH, started_at=NOW - timedelta(minutes=31), approved_override=True,
        anomaly_score=77, sequence_score=44, device_deviation="Medium", new_hosts=2, remote_access_ratio=4.1, privilege_attempts=0,
        reason_codes=["Late bulk operation", "Approved bulk operation override", "New project repository"], timeline=[_event(-31, "AUTH_SUCCESS", "Successful login", "Known workstation login."), _event(-2, "RESOURCE_ACCESS", "Approved export", "Project closeout export under approved operation.")],
        baseline_comparison=[("Target systems", "5", "7"), ("Failed logins", "0", "0"), ("Admin resources", "0", "0"), ("Sensitive reads", "10", "108"), ("Devices", "1", "1")],
    )
    elevated = SessionDetail(
        id="SES-C441", identity_id="USR-C18", device_id="PC-14", risk_score=63,
        intent=Intent.RECON, intent_confidence=0.72, status=SessionStatus.HIGH, started_at=NOW - timedelta(minutes=18),
        anomaly_score=68, sequence_score=62, device_deviation="Medium", new_hosts=5, remote_access_ratio=2.8, privilege_attempts=1,
        reason_codes=["Unseen server access", "Host discovery progression"], timeline=[_event(-18, "AUTH_SUCCESS", "Successful login", "Login from PC-14."), _event(-8, "DISCOVERY", "Host discovery", "Five unseen targets contacted.")],
        baseline_comparison=[("Target systems", "4", "9"), ("Failed logins", "0", "2"), ("Admin resources", "0", "1"), ("Sensitive reads", "8", "16"), ("Devices", "1", "1")],
    )
    return {item.id: item for item in (suspicious, normal, approved, elevated)}


sessions = seed_sessions()


def reset() -> None:
    global sessions
    sessions = seed_sessions()
