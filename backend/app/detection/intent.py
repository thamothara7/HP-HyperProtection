from dataclasses import dataclass

from app.features.extractor import SessionFeatures


@dataclass(frozen=True)
class IntentAssessment:
    intent: str
    confidence: float
    evidence: list[str]


def classify_intent(features: SessionFeatures, sequence_score: float) -> IntentAssessment:
    evidence: list[str] = []
    if features.explicit_credential_events > 0 and (features.privileged_events > 0 or sequence_score >= 60):
        evidence.append("Explicit credentials were used after privileged or discovery activity.")
        return IntentAssessment("CREDENTIAL_HUNTING", min(.95, .55 + .08 * features.explicit_credential_events + sequence_score / 300), evidence)
    if features.unique_target_count >= 5 and (features.failed_logins >= 3 or sequence_score >= 40):
        evidence.append("Multi-target exploration is paired with remote-access or failed authentication activity.")
        return IntentAssessment("LATERAL_MOVEMENT", min(.9, .45 + features.unique_target_count / 20 + sequence_score / 400), evidence)
    if features.unique_target_count >= 4:
        evidence.append("Session is exploring an unusual number of targets.")
        return IntentAssessment("RECON", min(.75, .35 + features.unique_target_count / 20), evidence)
    if features.sensitive_resource_reads >= 20:
        evidence.append("Sensitive access volume materially exceeds the active-window threshold.")
        return IntentAssessment("DATA_COLLECTION", min(.8, .4 + features.sensitive_resource_reads / 100), evidence)
    return IntentAssessment("NONE", 0.0, [])
