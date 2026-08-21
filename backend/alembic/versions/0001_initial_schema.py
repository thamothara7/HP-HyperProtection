"""Initial InsiderGuard storage tables.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-22
"""
from alembic import op
from app.db.session import Base
import app.db.models  # noqa: F401

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())

def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
