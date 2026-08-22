"""FastAPI dependencies for a ready development database session."""

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.db.bootstrap import create_schema, seed_demo_if_empty
from app.db.session import SessionLocal
from app.config import settings


def get_ready_db() -> Generator[Session, None, None]:
    """Create the local schema when needed; production uses Alembic before startup."""
    if settings.auto_create_schema:
        create_schema()
    db = SessionLocal()
    try:
        if settings.seed_demo_data:
            seed_demo_if_empty(db)
        yield db
    finally:
        db.close()
