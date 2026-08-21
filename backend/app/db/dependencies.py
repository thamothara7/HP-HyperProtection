"""FastAPI dependencies for a ready development database session."""

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.db.bootstrap import create_schema, seed_demo_if_empty
from app.db.session import SessionLocal


def get_ready_db() -> Generator[Session, None, None]:
    """Create the local schema when needed; production uses Alembic before startup."""
    create_schema()
    db = SessionLocal()
    try:
        seed_demo_if_empty(db)
        yield db
    finally:
        db.close()
