"""
Database setup for the forensic MVP.

Per spec section 7: "If there is no database, use SQLite for the MVP."
This project has no pre-existing backend/database, so we use SQLite via
SQLAlchemy. The DB file lives next to the backend so it's easy to find,
inspect (e.g. with `sqlite3 forensics.db`), or wipe between demos.
"""

import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("FORENSICS_DB_PATH", os.path.join(BACKEND_DIR, "forensics.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for SQLite + FastAPI
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Create tables and apply the small local SQLite compatibility migration.

    ``create_all`` does not add columns to a pre-existing SQLite table.  The
    explicit migration keeps databases created before OS filtering usable and
    backfills a value only where the recorded source establishes one.
    """
    from app import models  # noqa: F401  (ensure models are registered)
    Base.metadata.create_all(bind=engine)

    columns = {column["name"] for column in inspect(engine).get_columns("events")}
    if "operating_system" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE events ADD COLUMN operating_system VARCHAR"))

    # Columns added through ALTER TABLE are not picked up by SQLAlchemy's
    # create_all index creation, so ensure scoped lookups remain indexed for
    # both new and legacy databases.
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_events_operating_system ON events (operating_system)"))

    _backfill_operating_system()


def _backfill_operating_system():
    """Classify legacy rows without touching raw evidence or existing scores."""
    from app.filtering import infer_operating_system
    from app.models import Event

    db = SessionLocal()
    try:
        rows = db.query(Event).filter(Event.operating_system.is_(None)).all()
        for row in rows:
            inferred = infer_operating_system(
                log_source=row.log_source,
                provider=row.provider,
                data_origin=row.data_origin,
                raw_data=row.raw_data,
            )
            if inferred:
                row.operating_system = inferred
        db.commit()
    finally:
        db.close()


def get_db():
    """FastAPI dependency: yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
