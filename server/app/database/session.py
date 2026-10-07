from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from server.app.core.config import settings
from server.app.database.base import Base

# Import all models so metadata knows about them before create_all
import server.app.models  # noqa: F401

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
    echo=settings.FORENSIGHT_DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database tables and storage directories."""
    # Ensure storage paths exist
    _ = settings.resolved_evidence_dir
    _ = settings.resolved_reports_dir

    # Create tables
    Base.metadata.create_all(bind=engine)


def check_db_connection() -> bool:
    """Quick sanity check to verify database connectivity."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
