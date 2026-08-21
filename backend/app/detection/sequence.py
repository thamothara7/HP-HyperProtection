from collections import defaultdict


SUSPICIOUS_PATH = ("AUTH_SUCCESS", "DISCOVERY", "REMOTE_ACCESS", "PRIVILEGED_ACTIVITY", "RESOURCE_ACCESS")


class SequenceMemory:
    """Bounded per-session sequence memory so quiet gaps do not erase progression."""

    def __init__(self, max_events: int = 64) -> None:
        self._events: dict[str, list[str]] = defaultdict(list)
        self._max_events = max_events

    def ingest(self, session_id: str, event_type: str) -> float:
        events = self._events[session_id]
        events.append(event_type)
        del events[:-self._max_events]
        return self.score(session_id)

    def score(self, session_id: str) -> float:
        events = self._events[session_id]
        position = 0
        for event in events:
            if position < len(SUSPICIOUS_PATH) and event == SUSPICIOUS_PATH[position]:
                position += 1
        return round(100 * position / len(SUSPICIOUS_PATH), 2)
