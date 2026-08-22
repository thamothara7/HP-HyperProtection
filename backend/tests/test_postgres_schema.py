from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.db.models import EventRecord, PeerBaselineRecord


def test_postgresql_schema_uses_jsonb_and_unique_peer_groups() -> None:
    event_sql = str(CreateTable(EventRecord.__table__).compile(dialect=postgresql.dialect()))
    peer_sql = str(CreateTable(PeerBaselineRecord.__table__).compile(dialect=postgresql.dialect()))
    assert "JSONB" in event_sql
    assert "uq_peer_baselines_department_role" in peer_sql
