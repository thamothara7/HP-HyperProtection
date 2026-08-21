from dataclasses import dataclass


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    components: dict[str, int]
    explanation: list[str]


def compose_risk(*, anomaly: float, personal_deviation: float, peer_deviation: float, sequence: float, drift: float, rule_hits: list[tuple[int, str]], resource_sensitivity: float) -> RiskAssessment:
    rule_score = min(100.0, sum(score for score, _ in rule_hits))
    components = {
        "behavior_anomaly": round(anomaly), "personal_deviation": round(personal_deviation), "peer_deviation": round(peer_deviation),
        "sequence_risk": round(sequence), "within_session_drift": round(drift), "rule_evidence": round(rule_score), "resource_sensitivity": round(resource_sensitivity),
    }
    weighted = anomaly * .18 + personal_deviation * .16 + peer_deviation * .10 + sequence * .16 + drift * .12 + rule_score * .18 + resource_sensitivity * .10
    explanation = [evidence for _, evidence in rule_hits]
    if sequence >= 60:
        explanation.append("Security-event sequence matches a multi-stage suspicious progression.")
    if drift >= 50:
        explanation.append("Current behavior materially drifted from earlier activity in the same session.")
    return RiskAssessment(score=max(0, min(100, round(weighted))), components=components, explanation=explanation)
