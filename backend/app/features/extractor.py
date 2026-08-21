from dataclasses import dataclass
from datetime import datetime, timedelta

from app.normalization.event import EventType, NormalizedEvent


@dataclass(frozen=True)
class SessionFeatures:
    failed_logins: int
    successful_logins: int
    unique_target_count: int
    explicit_credential_events: int
    privileged_events: int
    share_access_count: int
    sensitive_resource_reads: int
    after_hours_score: float
    new_server_count: int
    sequence_events: tuple[str, ...]

    def vector(self) -> list[float]:
        return [float(self.failed_logins), float(self.successful_logins), float(self.unique_target_count), float(self.explicit_credential_events), float(self.privileged_events), float(self.share_access_count), float(self.sensitive_resource_reads), self.after_hours_score, float(self.new_server_count)]


def extract_features(events: list[NormalizedEvent], *, window_end: datetime | None = None, window: timedelta = timedelta(minutes=5), known_targets: set[str] | None = None) -> SessionFeatures:
    if not events:
        return SessionFeatures(0, 0, 0, 0, 0, 0, 0, 0.0, 0, ())
    end = window_end or max(event.timestamp for event in events)
    selected = [event for event in events if end - window <= event.timestamp <= end]
    targets = {event.target for event in selected if event.target}
    known = known_targets or set()
    after_hours = sum(1 for event in selected if event.timestamp.hour < 8 or event.timestamp.hour >= 19) / max(1, len(selected))
    return SessionFeatures(
        failed_logins=sum(event.event_type is EventType.AUTH_FAILURE for event in selected),
        successful_logins=sum(event.event_type is EventType.AUTH_SUCCESS for event in selected),
        unique_target_count=len(targets),
        explicit_credential_events=sum(event.event_type is EventType.EXPLICIT_CREDENTIALS for event in selected),
        privileged_events=sum(event.event_type is EventType.PRIVILEGED_ACTIVITY for event in selected),
        share_access_count=sum(event.event_type is EventType.SHARE_ACCESS for event in selected),
        sensitive_resource_reads=sum(event.resource_sensitivity >= 3 for event in selected),
        after_hours_score=after_hours,
        new_server_count=len(targets - known),
        sequence_events=tuple(event.event_type.value for event in selected),
    )
