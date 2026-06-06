"""SQLAlchemy engine, session factory, and database initialization."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

_DB_PATH = Path(__file__).resolve().parent.parent / "iterative_research.db"
_DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    _DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def _migrate_add_columns() -> None:
    """Add new columns to existing tables when they are missing (lightweight migration)."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "results" not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns("results")}
    new_cols = {
        "semgrep_high": "INTEGER DEFAULT 0",
        "semgrep_medium": "INTEGER DEFAULT 0",
        "semgrep_low": "INTEGER DEFAULT 0",
        "semgrep_error": "INTEGER DEFAULT 0",
        "semgrep_warning": "INTEGER DEFAULT 0",
        "semgrep_info": "INTEGER DEFAULT 0",
    }
    with engine.begin() as conn:
        for col_name, col_def in new_cols.items():
            if col_name not in existing:
                conn.execute(text(f"ALTER TABLE results ADD COLUMN {col_name} {col_def}"))


def init_db() -> None:
    """Create all tables if they don't exist, then run lightweight migrations."""
    from . import models  # noqa: F401 — registers models with Base.metadata
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
