from datetime import UTC, datetime, timedelta

from app.baseline.personal import PersonalBaseline
from app.baseline.poisoning_guard import learning_weight
from app.detection.intent import classify_intent
from app.detection.rules import evaluate_rules
from app.detection.sequence import SequenceMemory
from app.features.extractor import extract_features
from app.features.rolling import rolling_features
from app.normalization.event import EventCategory, EventType, NormalizedEvent
from app.policy.engine import deception_allowed
from app.sessions.drift import within_session_drift


def event(offset: int, event_type: EventType, target: str = "CORP-SRV", sensitivity: int = 0) -> NormalizedEvent:
    return NormalizedEvent(event_id=f"evt-{offset}-{event_type}", timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=offset), identity_id="USR-A", session_id="SES-A", device_id="EMP-PC", event_type=event_type, event_category=EventCategory.AUTHENTICATION, source="EMP-PC", target=target, action=event_type.value.lower(), result="success", resource_sensitivity=sensitivity)


def test_high_risk_without_attack_intent_never_gets_deception() -> None:
    decision = deception_allowed(risk_score=92, intent="NONE", intent_confidence=0.0, strong_legitimate_override=False)
    assert not decision.allow_decoy


def test_approved_deadline_operation_blocks_deception() -> None:
    decision = deception_allowed(risk_score=88, intent="EXFIL_ATTEMPT", intent_confidence=.91, strong_legitimate_override=True)
    assert not decision.allow_decoy


def test_suspicious_sequence_retains_progression() -> None:
    memory = SequenceMemory()
    for event_type in ("AUTH_SUCCESS", "DISCOVERY", "REMOTE_ACCESS", "PRIVILEGED_ACTIVITY", "RESOURCE_ACCESS"):
        score = memory.ingest("SES-A", event_type)
    assert score == 100


def test_poisoning_guard_freezes_high_risk_learning() -> None:
    baseline = PersonalBaseline()
    baseline.update(device_id="MGR-PC", target_count=2, sensitive_reads=4, after_hours=0, risk_score=8)
    baseline.update(device_id="EMP-PC", target_count=44, sensitive_reads=200, after_hours=1, risk_score=80)
    assert "MGR-PC" in baseline.known_devices
    assert "EMP-PC" not in baseline.known_devices
    assert learning_weight(80) == 0


def test_rules_intent_and_drift_are_explainable() -> None:
    earlier = extract_features([event(0, EventType.AUTH_SUCCESS)])
    current_events = [event(5 + index, EventType.AUTH_FAILURE, f"SRV-{index}") for index in range(6)] + [event(12, EventType.EXPLICIT_CREDENTIALS), event(13, EventType.PRIVILEGED_ACTIVITY)]
    current = extract_features(current_events, window=timedelta(minutes=15))
    rules = evaluate_rules(current, concurrent_sessions=2, new_device=True)
    intent = classify_intent(current, sequence_score=80)
    assert any(hit.code == "AUTH_FAILURE_BURST" for hit in rules)
    assert intent.intent == "CREDENTIAL_HUNTING"
    assert within_session_drift(earlier, current) > 0


def test_rolling_windows_keep_longer_context_and_known_target_deviation() -> None:
    events = [event(0, EventType.AUTH_SUCCESS, "FIN-01"), event(61, EventType.AUTH_SUCCESS, "FIN-01")]
    windows = rolling_features(events, known_targets={"FIN-01"})
    assert windows["5m"].successful_logins == 1
    assert windows["1h"].successful_logins == 1
    assert windows["24h"].successful_logins == 2
    assert windows["5m"].new_server_count == 0
