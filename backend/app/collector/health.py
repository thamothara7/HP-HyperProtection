"""Ephemeral collector liveness state for the SOC console."""

from datetime import UTC, datetime

_collectors: dict[str, dict[str, object]] = {}


def heartbeat(collector_id: str, *, source: str, submitted: int = 0, skipped: int = 0) -> dict[str, object]:
    record = {"collector_id": collector_id, "source": source, "submitted": submitted, "skipped": skipped, "last_seen": datetime.now(UTC)}
    _collectors[collector_id] = record
    return record


def all_collectors() -> list[dict[str, object]]:
    return list(_collectors.values())
