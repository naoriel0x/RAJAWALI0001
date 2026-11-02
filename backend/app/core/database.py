import logging
import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

os.environ["TZ"] = "Asia/Jakarta"

logger = logging.getLogger(__name__)

DATABASE_URL = "sqlite+aiosqlite:///./rajawali.db"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created.")


class InMemoryStore(dict[str, str]):
    async def set(self, key: str, value: str) -> bool:
        self[key] = value
        return True

    async def get(self, key: str) -> str | None:
        return super().get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        del ttl
        return await self.set(key, value)

    async def ping(self) -> bool:
        return True


in_memory_store = InMemoryStore()
redis_client = in_memory_store


async def get_redis() -> InMemoryStore:
    return redis_client


async def init_redis():
    await redis_client.ping()
    logger.info("In-memory store initialized.")


async def close_redis():
    redis_client.clear()
    logger.info("In-memory store cleared.")
