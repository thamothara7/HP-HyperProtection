from app.collector.parser import parse_windows_event_xml
from app.privacy.pseudonymizer import Pseudonymizer


def test_security_xml_is_pseudonymized_and_uses_stable_event_record_id() -> None:
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>4624</EventID><EventRecordID>942</EventRecordID><Computer>MGR-PC</Computer><TimeCreated SystemTime="2026-08-22T09:00:00.000Z" /></System>
      <EventData><Data Name="TargetUserSid">S-1-5-21-1000</Data><Data Name="TargetLogonId">0x123</Data><Data Name="WorkstationName">MGR-PC</Data></EventData>
    </Event>"""
    event = parse_windows_event_xml(xml, source="SEC-SRV", pseudonymizer=Pseudonymizer("test-secret"))
    assert event is not None
    assert event.event_id == "win-MGR-PC-942"
    assert event.identity_id.startswith("USR-")
    assert "S-1-5-21-1000" not in event.model_dump_json()
    assert event.device_id == "MGR-PC"
    assert event.session_id == "WIN-0x123"


def test_unsupported_windows_event_is_dropped() -> None:
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>9999</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-08-22T09:00:00.000Z" /></System>
    </Event>"""
    assert parse_windows_event_xml(xml, source="MGR-PC", pseudonymizer=Pseudonymizer("test-secret")) is None
