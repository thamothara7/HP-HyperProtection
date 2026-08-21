from dataclasses import dataclass

from app.features.extractor import SessionFeatures


@dataclass(frozen=True)
class RuleHit:
    code: str
    score: int
    evidence: str


def evaluate_rules(features: SessionFeatures, *, concurrent_sessions: int, new_device: bool) -> list[RuleHit]:
    hits: list[RuleHit] = []
    if features.failed_logins >= 5:
        hits.append(RuleHit("AUTH_FAILURE_BURST", 22, f"Session recorded {features.failed_logins} failed logins in the active window."))
    if new_device:
        hits.append(RuleHit("NEW_DEVICE_CONTEXT", 18, "Session originated from a device absent from the trusted identity baseline."))
    if features.unique_target_count >= 5:
        hits.append(RuleHit("TARGET_ENUMERATION", 21, f"Session contacted {features.unique_target_count} distinct targets in the active window."))
    if features.privileged_events >= 2:
        hits.append(RuleHit("PRIVILEGED_RESOURCE_ANOMALY", 20, f"Session initiated {features.privileged_events} privileged activities."))
    if concurrent_sessions >= 2:
        hits.append(RuleHit("CONCURRENT_SESSION_ANOMALY", 12, f"Identity has {concurrent_sessions} concurrent device contexts."))
    if features.sensitive_resource_reads >= 20:
        hits.append(RuleHit("SENSITIVE_ACCESS_SPIKE", 20, f"Session accessed {features.sensitive_resource_reads} sensitive resources."))
    return hits
