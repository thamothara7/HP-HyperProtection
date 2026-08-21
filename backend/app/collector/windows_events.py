from collections.abc import Iterator

from app.collector.parser import parse_windows_event_xml
from app.normalization.event import NormalizedEvent
from app.privacy.pseudonymizer import Pseudonymizer


def read_security_events(*, server: str = "localhost", max_events: int = 100, pseudonymizer: Pseudonymizer) -> Iterator[NormalizedEvent]:
    """Read local Windows Security logs through pywin32 when running on Windows.

    This module is deliberately import-safe on non-Windows development hosts.
    Configure WEF/WEC before using ForwardedEvents in a production environment.
    """
    try:
        import win32evtlog  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required and this reader must run on Windows.") from error
    handle = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryReverseDirection, "*")
    try:
        for event in win32evtlog.EvtNext(handle, max_events):
            parsed = parse_windows_event_xml(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml), source=server, pseudonymizer=pseudonymizer)
            if parsed:
                yield parsed
    finally:
        win32evtlog.EvtClose(handle)
