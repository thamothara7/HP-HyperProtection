import numpy as np
from sklearn.ensemble import IsolationForest


class SessionAnomalyModel:
    def __init__(self) -> None:
        self._model = IsolationForest(contamination=0.08, n_estimators=100, random_state=42)
        self._fitted = False

    def fit(self, trusted_vectors: list[list[float]]) -> None:
        if len(trusted_vectors) < 10:
            raise ValueError("At least ten trusted observations are required for Isolation Forest training.")
        self._model.fit(np.asarray(trusted_vectors, dtype=float))
        self._fitted = True

    def score(self, vector: list[float]) -> float:
        if not self._fitted:
            return 0.0
        # score_samples is higher for normal behavior. Convert to 0–100 unusualness.
        raw = float(-self._model.score_samples(np.asarray([vector], dtype=float))[0])
        return max(0.0, min(100.0, (raw - .35) / .35 * 100.0))
