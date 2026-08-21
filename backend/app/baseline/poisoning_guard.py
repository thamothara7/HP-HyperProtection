from enum import StrEnum


class LearningMode(StrEnum):
    NORMAL = "NORMAL"
    REDUCED = "REDUCED"
    FROZEN = "FROZEN"


def learning_weight(risk_score: int) -> float:
    """Suspicious behavior must never silently become trusted normal."""
    if risk_score < 30:
        return 1.0
    if risk_score <= 50:
        return 0.1
    return 0.0


def learning_mode(risk_score: int) -> LearningMode:
    return LearningMode.NORMAL if risk_score < 30 else LearningMode.REDUCED if risk_score <= 50 else LearningMode.FROZEN
