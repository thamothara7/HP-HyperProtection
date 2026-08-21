from collections import defaultdict

from app.baseline.robust_stats import robust_z_score


class PeerBaseline:
    def __init__(self) -> None:
        self._features: dict[tuple[str, str, str], list[float]] = defaultdict(list)

    def update(self, department: str, role: str, feature: str, value: float) -> None:
        values = self._features[(department, role, feature)]
        values.append(value)
        del values[:-500]

    def deviation(self, department: str, role: str, feature: str, value: float) -> float:
        return min(100.0, robust_z_score(value, self._features[(department, role, feature)]) * 20.0)
