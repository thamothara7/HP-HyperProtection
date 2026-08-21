from app.collector.windows_events import read_security_events


def read_forwarded_events(**kwargs):
    """WEF/WEC reader. Run on the Windows Event Collector, not endpoint hosts."""
    # The reader implementation is shared; it will gain a channel parameter in
    # the next collector increment alongside WEC subscription documentation.
    raise NotImplementedError("ForwardedEvents ingestion requires configured WEF/WEC subscriptions.")
