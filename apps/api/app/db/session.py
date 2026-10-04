"""Database session management."""

from typing import Generator
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine_options = {
    "pool_pre_ping": True,
    "echo": False,
    "connect_args": {"check_same_thread": False} if is_sqlite else {},
}
if not is_sqlite:
    engine_options.update(
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,
    )

engine = create_engine(settings.DATABASE_URL, **engine_options)


def ensure_local_schema() -> None:
    """Apply tiny forward-compatible fixes for the standalone SQLite tool."""
    if not is_sqlite:
        return
    inspector = inspect(engine)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("investigations")}
    if "score_version" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE investigations "
                    "ADD COLUMN score_version VARCHAR(32) NOT NULL DEFAULT '2026.10'"
                )
            )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a SQLAlchemy database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
