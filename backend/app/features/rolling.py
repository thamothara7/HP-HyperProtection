"""Named rolling security-feature windows for session evaluation and APIs."""

from datetime import timedelta

from app.features.extractor import SessionFeatures, extract_features
from app.normalization.event import NormalizedEvent

ROLLING_WINDOWS: dict[str, timedelta] = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def rolling_features(
    events: list[NormalizedEvent], *, known_targets: set[str] | None = None
) -> dict[str, SessionFeatures]:
    """Return consistent feature vectors over the V1 investigation windows."""
    if not events:
        return {name: extract_features([], window=window) for name, window in ROLLING_WINDOWS.items()}
    end = max(event.timestamp for event in events)
    return {
        name: extract_features(events, window_end=end, window=window, known_targets=known_targets)
        for name, window in ROLLING_WINDOWS.items()
    }


def feature_snapshot(features: SessionFeatures) -> dict[str, float | int]:
    """JSON-safe feature values, deliberately excluding raw resource contents."""
    return {
        "failed_logins": features.failed_logins,
        "successful_logins": features.successful_logins,
        "unique_target_count": features.unique_target_count,
        "explicit_credential_events": features.explicit_credential_events,
        "privileged_events": features.privileged_events,
        "share_access_count": features.share_access_count,
        "sensitive_resource_reads": features.sensitive_resource_reads,
        "after_hours_score": round(features.after_hours_score, 3),
        "new_server_count": features.new_server_count,
    }
