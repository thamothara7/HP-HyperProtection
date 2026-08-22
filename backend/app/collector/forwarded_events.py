from collections.abc import Iterator

from app.collector.windows_events import read_windows_events
from app.normalization.event import NormalizedEvent
from app.privacy.pseudonymizer import Pseudonymizer


def read_forwarded_events(*, server: str = "localhost", max_events: int = 100, pseudonymizer: Pseudonymizer) -> Iterator[NormalizedEvent]:
    """Read WEF-delivered Security metadata from a configured Windows Event Collector."""
    yield from read_windows_events(channel="ForwardedEvents", server=server, max_events=max_events, pseudonymizer=pseudonymizer)
