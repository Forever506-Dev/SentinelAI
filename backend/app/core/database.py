"""
Database Configuration

Async SQLAlchemy engine and session factory for PostgreSQL.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# --- Async Engine ---
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

# --- Session Factory ---
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# --- Base Model ---
class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


# --- Dependency ---
async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency that provides a database session per request."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
