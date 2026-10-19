"""
Integration verification suite for Redis sliding-window frequency counters and deduplication.
Verifies atomicity, sliding time-window evictions, idempotency locks,
and dynamic telemetry counter aggregations using an isolated Redis container.
"""

import asyncio
import time
from collections.abc import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from testcontainers.redis import RedisContainer


@pytest.fixture(scope="module")
def redis_container() -> RedisContainer:
    """Spins up an isolated Redis container for the integration test module."""
    container = RedisContainer("redis:7.2-alpine")
    container.start()
    yield container
    container.stop()


@pytest_asyncio.fixture
async def redis_client(redis_container: RedisContainer) -> AsyncGenerator[aioredis.Redis, None]:
    """Provides a connected, isolated async Redis client with automatic test cleanup."""
    host = redis_container.get_container_host_ip()
    port = int(redis_container.get_exposed_port(6379))
    client = aioredis.Redis(host=host, port=port, decode_responses=True)
    await client.flushall()
    yield client
    await client.flushall()
    await client.aclose()


class RedisSlidingWindowCounter:
    """
    Production-grade sliding-window counter using Redis sorted sets (ZSET).
    Maintains time-series event occurrences without drift across rolling intervals.
    """

    def __init__(self, client: aioredis.Redis, key_prefix: str = "counter") -> None:
        self.client = client
        self.key_prefix = key_prefix

    def _format_key(self, entity_id: str, metric: str) -> str:
        return f"{self.key_prefix}:{entity_id}:{metric}"

    async def record_occurrence(
        self,
        entity_id: str,
        metric: str,
        timestamp: float,
        event_id: str,
        window_seconds: int,
    ) -> int:
        """
        Records an event and trims expired occurrences outside the rolling window atomically.
        """
        key = self._format_key(entity_id, metric)
        min_allowed_time = timestamp - window_seconds

        # Pipeline executes cleanup, record insertion, count query, and TTL renewal atomically
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, "-inf", min_allowed_time)
            pipe.zadd(key, {event_id: timestamp})
            pipe.zcard(key)
            pipe.expire(key, window_seconds * 2)
            results = await pipe.execute()

        current_count: int = results[2]
        return current_count

    async def get_count(
        self,
        entity_id: str,
        metric: str,
        current_timestamp: float,
        window_seconds: int,
    ) -> int:
        """Computes current sliding window count after removing stale elements."""
        key = self._format_key(entity_id, metric)
        min_allowed_time = current_timestamp - window_seconds

        async with self.client.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, "-inf", min_allowed_time)
            pipe.zcard(key)
            results = await pipe.execute()

        return int(results[1])


class RedisIdempotencyLock:
    """
    Distributed deduplication guard enforcing idempotent request ingestion.
    """

    def __init__(self, client: aioredis.Redis, key_prefix: str = "idempotency") -> None:
        self.client = client
        self.key_prefix = key_prefix

    def _format_key(self, idempotency_key: str) -> str:
        return f"{self.key_prefix}:{idempotency_key}"

    async def acquire(self, idempotency_key: str, ttl_seconds: int = 60) -> bool:
        """Attempts to lock an event key atomically via SET NX EX."""
        key = self._format_key(idempotency_key)
        acquired = await self.client.set(key, "PROCESSING", ex=ttl_seconds, nx=True)
        return bool(acquired)

    async def set_payload_hash(self, idempotency_key: str, payload_hash: str, ttl_seconds: int = 3600) -> None:
        """Saves computed assessment fingerprint to return cached response on retry."""
        key = self._format_key(idempotency_key)
        await self.client.set(key, payload_hash, ex=ttl_seconds)

    async def get_status(self, idempotency_key: str) -> str | None:
        """Fetches current lock status or cached fingerprint."""
        key = self._format_key(idempotency_key)
        return await self.client.get(key)


@pytest.mark.asyncio
class TestRedisSlidingWindowCounters:
    """Verifies temporal aggregation and sliding-window event counting."""

    async def test_sliding_window_event_accumulation(self, redis_client: aioredis.Redis) -> None:
        """Verifies events accumulate accurately within the sliding window."""
        counter = RedisSlidingWindowCounter(redis_client, key_prefix="telemetry")
        source_ip = "1.2.3.4"
        metric = "events"
        window_seconds = 60
        now = time.time()

        for idx in range(17):
            count = await counter.record_occurrence(
                entity_id=source_ip,
                metric=metric,
                timestamp=now + (idx * 0.1),
                event_id=f"evt-{uuid4()}",
                window_seconds=window_seconds,
            )

        assert count == 17
        active_count = await counter.get_count(source_ip, metric, now + 5, window_seconds)
        assert active_count == 17

    async def test_sliding_window_temporal_eviction(self, redis_client: aioredis.Redis) -> None:
        """Verifies timestamps outside the sliding window expire and are excluded from counts."""
        counter = RedisSlidingWindowCounter(redis_client, key_prefix="telemetry")
        source_ip = "192.168.1.50"
        metric = "detections"
        window_seconds = 10
        base_time = 1000.0

        # Record 5 events at T=1000
        for _ in range(5):
            await counter.record_occurrence(
                entity_id=source_ip,
                metric=metric,
                timestamp=base_time,
                event_id=f"stale-{uuid4()}",
                window_seconds=window_seconds,
            )

        # Record 3 events at T=1008
        for _ in range(3):
            await counter.record_occurrence(
                entity_id=source_ip,
                metric=metric,
                timestamp=base_time + 8,
                event_id=f"fresh-{uuid4()}",
                window_seconds=window_seconds,
            )

        # Query at T=1009 (Window covers [999, 1009]) -> all 8 are valid
        count_t9 = await counter.get_count(source_ip, metric, base_time + 9, window_seconds)
        assert count_t9 == 8

        # Query at T=1012 (Window covers [1002, 1012]) -> initial 5 events expired
        count_t12 = await counter.get_count(source_ip, metric, base_time + 12, window_seconds)
        assert count_t12 == 3

    async def test_concurrent_counter_increments(self, redis_client: aioredis.Redis) -> None:
        """Ensures atomic execution under high-concurrency ingestion bursts."""
        counter = RedisSlidingWindowCounter(redis_client, key_prefix="concurrent")
        endpoint_id = "SRV-APP-01"
        metric = "hits"
        window_seconds = 120
        now = time.time()
        total_concurrent_writes = 50

        tasks = [
            counter.record_occurrence(
                entity_id=endpoint_id,
                metric=metric,
                timestamp=now + (i * 0.001),
                event_id=f"burst-{uuid4()}",
                window_seconds=window_seconds,
            )
            for i in range(total_concurrent_writes)
        ]

        await asyncio.gather(*tasks)

        final_count = await counter.get_count(endpoint_id, metric, now + 1, window_seconds)
        assert final_count == total_concurrent_writes


@pytest.mark.asyncio
class TestRedisDeduplicationAndIdempotency:
    """Verifies idempotency locks, atomic token acquisition, and duplicate suppression."""

    async def test_idempotent_lock_acquisition(self, redis_client: aioredis.Redis) -> None:
        """Ensures identical idempotency keys are blocked on duplicate entry."""
        lock = RedisIdempotencyLock(redis_client)
        idempotency_key = f"idemp-{uuid4()}"

        first_acquisition = await lock.acquire(idempotency_key, ttl_seconds=30)
        assert first_acquisition is True

        second_acquisition = await lock.acquire(idempotency_key, ttl_seconds=30)
        assert second_acquisition is False

    async def test_idempotency_payload_caching(self, redis_client: aioredis.Redis) -> None:
        """Verifies state updates persist for idempotent responses."""
        lock = RedisIdempotencyLock(redis_client)
        idempotency_key = f"evt-hash-{uuid4()}"
        assessment_digest = '{"risk_score": 83.5, "rating": "HIGH"}'

        await lock.acquire(idempotency_key, ttl_seconds=60)
        await lock.set_payload_hash(idempotency_key, assessment_digest, ttl_seconds=120)

        persisted = await lock.get_status(idempotency_key)
        assert persisted == assessment_digest