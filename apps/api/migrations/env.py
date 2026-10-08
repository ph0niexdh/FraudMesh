"""Alembic environment (async, URL from FM_DATABASE_URL)."""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from fraudmesh.config import get_settings
from fraudmesh.db.models import Base

target_metadata = Base.metadata


def _run(connection):
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def _main():
    url = context.config.attributes.get("url") or get_settings().database_url
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        await conn.run_sync(_run)
        await conn.commit()
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=get_settings().database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_main())
