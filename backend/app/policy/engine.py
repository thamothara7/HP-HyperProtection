from dataclasses import dataclass

from app.config import settings


DECEPTION_INTENTS = {"RECON", "CREDENTIAL_HUNTING", "LATERAL_MOVEMENT", "EXFIL_ATTEMPT"}


@dataclass(frozen=True)
class PolicyDecision:
    allow_decoy: bool
    reason: str


def deception_allowed(*, risk_score: int, intent: str, intent_confidence: float, strong_legitimate_override: bool) -> PolicyDecision:
    if strong_legitimate_override:
        return PolicyDecision(False, "A verified legitimate override is active.")
    if risk_score < settings.high_risk_threshold:
        return PolicyDecision(False, "Risk has not reached the deception threshold.")
    if intent not in DECEPTION_INTENTS:
        return PolicyDecision(False, "No deception-eligible intent is present.")
    if intent_confidence < settings.intent_confidence_threshold:
        return PolicyDecision(False, "Intent confidence is below the policy threshold.")
    return PolicyDecision(True, "Risk, intent, confidence, and override checks permit controlled deception.")
