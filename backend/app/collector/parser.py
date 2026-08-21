"""Parse Windows Security Event XML into a safe normalized event boundary."""
from datetime import UTC, datetime
from xml.etree import ElementTree

from app.normalization.event import EventCategory, EventType, NormalizedEvent
from app.privacy.pseudonymizer import Pseudonymizer

WINDOWS_EVENT_MAP: dict[int, tuple[EventType, EventCategory, str]] = {
    4624: (EventType.AUTH_SUCCESS, EventCategory.AUTHENTICATION, "login"),
    4625: (EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, "login"),
    4634: (EventType.LOGOFF, EventCategory.AUTHENTICATION, "logoff"),
    4648: (EventType.EXPLICIT_CREDENTIALS, EventCategory.AUTHENTICATION, "explicit_credentials"),
    4672: (EventType.PRIVILEGED_ACTIVITY, EventCategory.PRIVILEGE, "special_privileges"),
    4688: (EventType.PROCESS_CREATED, EventCategory.PROCESS, "process_created"),
    5140: (EventType.SHARE_ACCESS, EventCategory.RESOURCE_ACCESS, "share_access"),
    5145: (EventType.SHARE_ACCESS, EventCategory.RESOURCE_ACCESS, "detailed_share_access"),
}


def parse_windows_event_xml(xml: str, *, source: str, pseudonymizer: Pseudonymizer) -> NormalizedEvent | None:
    """Accept Security or ForwardedEvents XML and discard raw identity details.

    `SubjectUserSid` is transformed before persistence. Account names and raw XML
    are intentionally not included in metadata.
    """
    root = ElementTree.fromstring(xml)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", namespace)
    if system is None:
        return None
    event_id_element = system.find("e:EventID", namespace)
    time_element = system.find("e:TimeCreated", namespace)
    if event_id_element is None or time_element is None:
        return None
    event_id = int(event_id_element.text or "0")
    mapping = WINDOWS_EVENT_MAP.get(event_id)
    if mapping is None:
        return None
    data = {item.attrib.get("Name", ""): item.text or "" for item in root.findall(".//e:EventData/e:Data", namespace)}
    sid = data.get("TargetUserSid") or data.get("SubjectUserSid")
    if not sid or sid in {"S-1-0-0", "-"}:
        return None
    timestamp = datetime.fromisoformat(time_element.attrib["SystemTime"].replace("Z", "+00:00")).astimezone(UTC)
    event_type, category, action = mapping
    logon_id = data.get("TargetLogonId") or data.get("SubjectLogonId")
    target = data.get("WorkstationName") or data.get("IpAddress") or data.get("ShareName") or None
    return NormalizedEvent(
        event_id=f"win-{source}-{event_id}-{timestamp.timestamp():.6f}", timestamp=timestamp,
        identity_id=pseudonymizer.identity_id(sid), device_id=source, source=source,
        session_id=f"WIN-{logon_id}" if logon_id and logon_id != "0x0" else None,
        event_type=event_type, event_category=category, target=target,
        resource_type="NETWORK_SHARE" if event_id in {5140, 5145} else None,
        resource_sensitivity=0, action=action, result="failure" if event_id == 4625 else "success",
    )
