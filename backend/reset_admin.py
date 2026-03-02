"""Quick script to reset the admin user's password to the configured default."""
import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import engine
from app.core.security import hash_password
from app.core.config import settings


async def reset_admin():
    async with AsyncSession(engine) as db:
        result = await db.execute(
            text("SELECT id, username, email FROM users WHERE username = 'admin'")
        )
        row = result.first()
        if row:
            new_hash = hash_password(settings.ADMIN_DEFAULT_PASSWORD)
            await db.execute(
                text("UPDATE users SET hashed_password = :pw, role = 'admin' WHERE username = 'admin'"),
                {"pw": new_hash},
            )
            await db.commit()
            print(f"Admin password reset to: {settings.ADMIN_DEFAULT_PASSWORD}")
            print(f"Admin email: {row.email}")
        else:
            print("No admin user found - will be created on startup")
    await engine.dispose()


asyncio.run(reset_admin())
