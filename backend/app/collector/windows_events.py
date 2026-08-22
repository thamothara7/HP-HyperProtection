from collections.abc import Iterator

from app.collector.parser import parse_windows_event_xml
from app.normalization.event import NormalizedEvent
from app.privacy.pseudonymizer import Pseudonymizer


def read_windows_events(*, channel: str, server: str = "localhost", max_events: int = 100, pseudonymizer: Pseudonymizer) -> Iterator[NormalizedEvent]:
    """Read a local Windows event channel through pywin32 when running on Windows.

    This module is deliberately import-safe on non-Windows development hosts.
    Configure WEF/WEC before using ForwardedEvents in a production environment.
    """
    try:
        import win32evtlog  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required and this reader must run on Windows.") from error
    handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, "*")
    try:
        for event in win32evtlog.EvtNext(handle, max_events):
            parsed = parse_windows_event_xml(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml), source=server, pseudonymizer=pseudonymizer)
            if parsed:
                yield parsed
    finally:
        win32evtlog.EvtClose(handle)


def read_security_events(*, server: str = "localhost", max_events: int = 100, pseudonymizer: Pseudonymizer) -> Iterator[NormalizedEvent]:
    """Read the local Security channel; a convenience wrapper for the local collector."""
    yield from read_windows_events(channel="Security", server=server, max_events=max_events, pseudonymizer=pseudonymizer)
