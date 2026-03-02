"""
Cleanup Duplicate Agents

One-time migration script that finds duplicate agents (same hostname + os_type),
keeps the most recently active one, and decommissions the rest.
"""

import asyncio
import sys
import os

# Add parent to path so we can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.agent import Agent


async def cleanup():
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Find duplicate hostname+os_type groups
        dup_query = (
            select(Agent.hostname, Agent.os_type, func.count().label("cnt"))
            .where(Agent.status != "decommissioned")
            .group_by(Agent.hostname, Agent.os_type)
            .having(func.count() > 1)
        )
        dup_result = await db.execute(dup_query)
        duplicates = dup_result.all()

        if not duplicates:
            print("✓ No duplicate agents found.")
            return

        total_removed = 0
        for hostname, os_type, count in duplicates:
            print(f"\n  Hostname: {hostname} ({os_type}) — {count} copies")

            # Get all copies ordered by last_heartbeat desc
            copies_result = await db.execute(
                select(Agent)
                .where(Agent.hostname == hostname)
                .where(Agent.os_type == os_type)
                .where(Agent.status != "decommissioned")
                .order_by(Agent.last_heartbeat.desc().nullslast())
            )
            copies = copies_result.scalars().all()

            # Keep the first (most recent heartbeat), decommission the rest
            keeper = copies[0]
            print(f"    ✓ Keeping   {keeper.id} (heartbeat: {keeper.last_heartbeat})")

            for stale in copies[1:]:
                stale.status = "decommissioned"
                print(f"    ✗ Removing  {stale.id} (heartbeat: {stale.last_heartbeat})")
                total_removed += 1

        await db.commit()
        print(f"\n✓ Decommissioned {total_removed} duplicate agent(s).")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(cleanup())
