from dataclasses import dataclass, field

from app.baseline.poisoning_guard import learning_weight
from app.baseline.robust_stats import robust_z_score


@dataclass
class PersonalBaseline:
    """Compact trusted baseline. Lists are capped to resist both noise and poisoning."""

    known_devices: set[str] = field(default_factory=set)
    target_counts: list[float] = field(default_factory=list)
    sensitive_reads: list[float] = field(default_factory=list)
    after_hours: list[float] = field(default_factory=list)
    max_observations: int = 180

    def update(self, *, device_id: str, target_count: float, sensitive_reads: float, after_hours: float, risk_score: int) -> None:
        if learning_weight(risk_score) == 0:
            return
        if learning_weight(risk_score) == 1:
            self.known_devices.add(device_id)
        for values, value in ((self.target_counts, target_count), (self.sensitive_reads, sensitive_reads), (self.after_hours, after_hours)):
            if learning_weight(risk_score) == 1 or not values:
                values.append(value)
            else:
                # Reduced-risk observations have minimal influence and never establish device trust.
                values.append(sum(values[-min(10, len(values)):]) / min(10, len(values)))
            del values[:-self.max_observations]

    def deviation(self, *, device_id: str, target_count: float, sensitive_reads: float, after_hours: float) -> float:
        scores = [robust_z_score(target_count, self.target_counts), robust_z_score(sensitive_reads, self.sensitive_reads), robust_z_score(after_hours, self.after_hours)]
        if self.known_devices and device_id not in self.known_devices:
            scores.append(3.5)
        return min(100.0, max(scores) * 20.0)
