import logging
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""


def create_app_engine() -> AsyncEngine:
    connection_url = str(settings.db.ASYNC_DATABASE_URI)

    engine: AsyncEngine = create_async_engine(
        connection_url,
        poolclass=NullPool,
        echo=settings.db.DB_ECHO,
        pool_pre_ping=True,
        connect_args={
            "server_settings": {
                "application_name": settings.app.PROJECT_NAME,
                "timezone": "UTC",
            }
        },
    )
    return engine


# Global database engine instance
async_engine: AsyncEngine = create_app_engine()

# Thread-safe async session factory
async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,  # Prevents attribute refresh errors after session commits
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an isolated, transactional AsyncSession.
    Automatically handles commit on success and rollback on exceptions.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except SQLAlchemyError as db_err:
            await session.rollback()
            logger.error(
                "Database transaction rolled back due to database error: %s",
                db_err,
                exc_info=True,
            )
            raise
        except Exception as exc:
            await session.rollback()
            logger.error(
                "Database transaction rolled back due to unhandled exception: %s",
                exc,
                exc_info=True,
            )
            raise


async def verify_database_connection() -> bool:
    """
    Diagnostic health-check helper executing a ping query against PostgreSQL.
    """
    try:
        async with async_engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:
        logger.critical("Database health check ping failed: %s", exc, exc_info=True)
        return False


async def init_db_engine() -> None:
    """
    Diagnostic lifecycle hook called on application startup.
    Validates connectivity to PostgreSQL before serving traffic.
    """
    is_connected = await verify_database_connection()
    if not is_connected:
        logger.warning(
            "Initial PostgreSQL ping failed. Database may be unreachable or initializing."
        )
    else:
        logger.info("PostgreSQL connection pool verified and ready.")


async def close_database_connection() -> None:
    """
    Gracefully disposes and drains all pooled connections during application shutdown.
    """
    if async_engine is not None:
        logger.info("Disposing PostgreSQL connection pool...")
        await async_engine.dispose()
        logger.info("PostgreSQL connection pool successfully closed.")


# ---------------------------------------------------------------------------
# Aliases consumed by app/main.py and external consumers
# ---------------------------------------------------------------------------
init_db = init_db_engine
close_db_engine = close_database_connection
