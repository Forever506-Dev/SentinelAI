"""
API Dependencies

Shared FastAPI dependencies injected into route handlers.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user, get_current_agent


async def get_redis() -> Redis:  # type: ignore[misc]
    """Provide a Redis connection."""
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


# Re-export common dependencies for convenience
__all__ = [
    "get_db",
    "get_redis",
    "get_current_user",
    "get_current_agent",
    "Depends",
    "AsyncSession",
    "Redis",
]
