"""
Core Redis Configuration and Sliding-Window / Locking Services.
Manages persistent asynchronous connection pools using redis-py (asyncio),
distributed idempotency locks, sliding rate windows, health diagnostics, and graceful lifecycle teardowns.
"""

from collections.abc import AsyncGenerator
import logging
from typing import Optional

import redis.asyncio as aioredis
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

# Global singleton client reference
_redis_client: Optional[Redis] = None


def get_redis_connection_pool() -> aioredis.ConnectionPool:
    """Creates a connection pool honoring settings and TLS flags."""
    return aioredis.ConnectionPool.from_url(
        settings.redis.connection_url,
        max_connections=50,
        decode_responses=True,
    )


async def init_redis_client() -> Redis:
    """
    Initializes and verifies the global Redis connection pool.
    Executed during application startup lifecycle.
    """
    global _redis_client
    if _redis_client is None:
        pool = get_redis_connection_pool()
        _redis_client = aioredis.Redis(connection_pool=pool)
        try:
            await _redis_client.ping()
            logger.info("Redis connection pool initialized and ping verified.")
        except RedisError as exc:
            logger.warning("Redis ping failed during startup: %s. Continuing...", exc)
    return _redis_client


async def close_redis_client() -> None:
    """
    Gracefully closes connection pools during application teardown.
    Consumed by app/main.py lifespan context.
    """
    global _redis_client
    if _redis_client is not None:
        logger.info("Closing Redis connection pool...")
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection pool closed.")


async def get_redis() -> AsyncGenerator[Redis, None]:
    """FastAPI dependency yielding the shared active async Redis instance."""
    client = await get_redis_client()
    yield client


async def get_redis_client() -> Redis:
    """Retrieves or lazily instantiates the global async Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = await init_redis_client()
    return _redis_client


async def verify_redis_connection() -> bool:
    """
    Diagnostic health-check helper executing a ping against Redis.
    Consumed by app/api/v1/endpoints/health.py.
    """
    try:
        client = await get_redis_client()
        result = await client.ping()
        return bool(result)
    except Exception as exc:
        logger.warning("Redis health check ping failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Sliding-Window Counters & Distributed Idempotency Locks
# ---------------------------------------------------------------------------

async def check_idempotency_lock(key: str, ttl_seconds: int = 60) -> bool:
    """
    Atomic distributed lock using SET NX EX.
    Returns True if the lock was successfully acquired (first-time processing),
    or False if the key is already locked/in-flight.
    """
    client = await get_redis_client()
    try:
        acquired = await client.set(f"lock:idempotency:{key}", "1", ex=ttl_seconds, nx=True)
        return bool(acquired)
    except RedisError as exc:
        logger.error("Failed to acquire idempotency lock for key %s: %s", key, exc)
        return True  # Fail-open to avoid dropping events during Redis transient blips


async def release_idempotency_lock(key: str) -> None:
    """Releases an idempotency lock early upon task completion."""
    client = await get_redis_client()
    try:
        await client.delete(f"lock:idempotency:{key}")
    except RedisError as exc:
        logger.error("Failed to release idempotency lock for key %s: %s", key, exc)


async def increment_sliding_window_counter(
    entity_key: str,
    window_seconds: int = 3600,
    current_timestamp: Optional[float] = None,
) -> int:
    """
    Sliding window event frequency counter implemented using a Redis sorted set (ZSET).
    Removes entries older than `window_seconds` and returns current frequency count.
    """
    import time
    now = current_timestamp or time.time()
    cutoff = now - window_seconds
    redis_key = f"counter:sliding:{entity_key}"

    client = await get_redis_client()
    try:
        async with client.pipeline(transaction=True) as pipe:
            # 1. Clean out timestamps older than the correlation window
            pipe.zremrangebyscore(redis_key, 0, cutoff)
            # 2. Add current event timestamp
            pipe.zadd(redis_key, {str(now): now})
            # 3. Fetch count within current window
            pipe.zcard(redis_key)
            # 4. Set key expiration to ensure idle keys get cleaned up
            pipe.expire(redis_key, window_seconds + 60)

            results = await pipe.execute()
            return int(results[2])
    except RedisError as exc:
        logger.error("Failed executing sliding-window counter for entity %s: %s", entity_key, exc)
        return 1


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------
init_redis = init_redis_client
close_redis = close_redis_client
check_redis_connection = verify_redis_connection