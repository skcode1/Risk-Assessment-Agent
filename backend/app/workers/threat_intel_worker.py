"""
Threat Intelligence Enrichment Worker.
Checks Redis cache, OpenSearch, and external feeds for threat indicators.
Normalizes and writes to Redis, publishes updates to Kafka.
Never modifies the deterministic kernel score - only enriches narrative context.
"""

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import redis.asyncio as aioredis
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from app.workers.opensearch_index import get_threat_intel_index_name

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.workers.threat_intel_worker")


@dataclass
class ThreatIndicator:
    """Normalized threat intelligence indicator."""

    indicator_type: str  # "ip", "domain", "hash", "url"
    value: str
    confidence: int  # 0-100
    severity: str  # "low", "medium", "high", "critical"
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = field(default_factory=list)
    tlp: str = "WHITE"  # Traffic Light Protocol

    def to_redis_hash(self) -> dict[str, str]:
        """Convert to Redis hash for storage."""
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "confidence": str(self.confidence),
            "severity": self.severity,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tags": json.dumps(self.tags),
            "tlp": self.tlp,
        }

    @classmethod
    def from_redis_hash(cls, data: dict[str, str]) -> "ThreatIndicator":
        """Create from Redis hash."""
        return cls(
            indicator_type=data["indicator_type"],
            value=data["value"],
            confidence=int(data["confidence"]),
            severity=data["severity"],
            source=data["source"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            tags=json.loads(data["tags"]) if data.get("tags") else [],
            tlp=data.get("tlp", "WHITE"),
        )


class ThreatIntelWorker:
    """
    Enriches threat intelligence from multiple sources:
    1. Redis cache (ti:{ip} with 24h TTL)
    2. OpenSearch threat-intel-indicators* indices
    3. External feeds via HTTP (with tenacity retry)

    Normalizes indicators and writes to Redis.
    Publishes updates to 'threat-intel-updates' Kafka topic.
    Enrichment flows ONLY into narrative context and SOC review queue.
    NEVER modifies the deterministic kernel score.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        opensearch_client=None,
        kafka_producer=None,
        external_feeds: list[dict[str, Any]] | None = None,
        cache_ttl: int = 86400,  # 24 hours
    ) -> None:
        self.redis = redis_client
        self.opensearch = opensearch_client
        self.kafka_producer = kafka_producer
        self.external_feeds = external_feeds or []
        self.cache_ttl = cache_ttl
        self._running = False

    def _make_redis_key(self, indicator_type: str, value: str) -> str:
        """Generate Redis key for threat indicator."""
        # Use hash for consistent key length
        hash_val = hashlib.sha256(f"{indicator_type}:{value}".encode()).hexdigest()[:16]
        return f"ti:{indicator_type}:{hash_val}"

    async def check_redis_cache(
        self, indicator_type: str, value: str
    ) -> ThreatIndicator | None:
        """Check Redis cache for threat indicator."""
        key = self._make_redis_key(indicator_type, value)
        try:
            data = await self.redis.hgetall(key)
            if data:
                logger.debug("Cache hit for %s:%s", indicator_type, value)
                return ThreatIndicator.from_redis_hash(data)
        except Exception as e:
            logger.warning(
                "Redis cache check failed for %s:%s: %s", indicator_type, value, e
            )
        return None

    async def write_redis_cache(self, indicator: ThreatIndicator) -> bool:
        """Write threat indicator to Redis cache."""
        key = self._make_redis_key(indicator.indicator_type, indicator.value)
        try:
            await self.redis.hset(key, mapping=indicator.to_redis_hash())
            await self.redis.expire(key, self.cache_ttl)
            return True
        except Exception as e:
            logger.error("Failed to write threat indicator to Redis: %s", e)
            return False

    @retry(
        wait=wait_exponential_jitter(initial=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def fetch_external_feed(
        self, feed_config: dict[str, Any]
    ) -> list[ThreatIndicator]:
        """Fetch and parse threat indicators from external feed with retry."""
        url = feed_config.get("url")
        feed_type = feed_config.get("type", "json")
        auth = feed_config.get("auth")
        headers = feed_config.get("headers", {})

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, auth=auth, headers=headers)
            response.raise_for_status()

            if feed_type == "json":
                data = response.json()
            elif feed_type == "text":
                # Parse line-delimited text (one indicator per line)
                data = [
                    {"value": line.strip(), "type": "ip"}
                    for line in response.text.splitlines()
                    if line.strip()
                ]
            else:
                raise ValueError(f"Unsupported feed type: {feed_type}")

            return self._parse_feed_data(data, feed_config.get("source", url))

    def _parse_feed_data(self, data: Any, source: str) -> list[ThreatIndicator]:
        """Parse feed data into ThreatIndicator objects."""
        indicators = []
        now = datetime.now(UTC)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    indicator = self._parse_indicator_dict(item, source, now)
                elif isinstance(item, str):
                    indicator = ThreatIndicator(
                        indicator_type="ip",
                        value=item.strip(),
                        confidence=50,
                        severity="medium",
                        source=source,
                        first_seen=now,
                        last_seen=now,
                    )
                else:
                    continue
                if indicator:
                    indicators.append(indicator)
        elif isinstance(data, dict):
            # Handle structured feeds like STIX, MISP, etc.
            for obj in data.get("objects", []):
                indicator = self._parse_indicator_dict(obj, source, now)
                if indicator:
                    indicators.append(indicator)

        return indicators

    def _parse_indicator_dict(
        self, obj: dict[str, Any], source: str, now: datetime
    ) -> ThreatIndicator | None:
        """Parse a single indicator from dict."""
        # Try to extract indicator type and value
        indicator_type = obj.get("type") or obj.get("indicator_type") or "ip"
        value = obj.get("value") or obj.get("pattern") or obj.get("ip")

        if not value:
            return None

        # Map common severity values
        severity_map = {
            "low": "low",
            "informational": "low",
            "info": "low",
            "medium": "medium",
            "moderate": "medium",
            "high": "high",
            "critical": "critical",
            "severe": "critical",
        }
        severity = severity_map.get(str(obj.get("severity", "")).lower(), "medium")

        confidence = int(obj.get("confidence", 50))
        confidence = max(0, min(100, confidence))

        return ThreatIndicator(
            indicator_type=indicator_type,
            value=str(value).strip(),
            confidence=confidence,
            severity=severity,
            source=source,
            first_seen=now,
            last_seen=now,
            tags=obj.get("tags", []) if isinstance(obj.get("tags"), list) else [],
            tlp=obj.get("tlp", "WHITE"),
        )

    async def query_opensearch(
        self, indicator_type: str, value: str
    ) -> list[ThreatIndicator]:
        """Query OpenSearch for threat indicators."""
        if self.opensearch is None:
            return []

        try:
            index_pattern = get_threat_intel_index_name()
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"indicator_type": indicator_type}},
                            {"term": {"value": value}},
                        ]
                    }
                },
                "size": 10,
                "sort": [{"last_seen": {"order": "desc"}}],
            }

            response = await self.opensearch.search(
                index=index_pattern,
                body=query,
            )

            indicators = []
            for hit in response.get("hits", {}).get("hits", []):
                source = hit.get("_source", {})
                indicator = self._parse_indicator_dict(
                    source, "opensearch", datetime.now(UTC)
                )
                if indicator:
                    indicators.append(indicator)

            return indicators
        except Exception as e:
            logger.warning("OpenSearch threat intel query failed: %s", e)
            return []

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> list[ThreatIndicator]:
        """
        Enrich a single indicator from all sources.
        Priority: Redis cache -> OpenSearch -> External feeds
        """
        all_indicators = []

        # 1. Check Redis cache
        cached = await self.check_redis_cache(indicator_type, value)
        if cached:
            all_indicators.append(cached)

        # 2. Query OpenSearch
        os_indicators = await self.query_opensearch(indicator_type, value)
        all_indicators.extend(os_indicators)

        # 3. Fetch from external feeds
        for feed in self.external_feeds:
            try:
                feed_indicators = await self.fetch_external_feed(feed)
                all_indicators.extend(feed_indicators)
            except Exception as e:
                logger.warning("External feed %s failed: %s", feed.get("url"), e)

        # Deduplicate by value, keep highest confidence
        deduped = {}
        for ind in all_indicators:
            key = f"{ind.indicator_type}:{ind.value}"
            if key not in deduped or ind.confidence > deduped[key].confidence:
                deduped[key] = ind

        final_indicators = list(deduped.values())

        # Write back to Redis cache
        for ind in final_indicators:
            await self.write_redis_cache(ind)

        return final_indicators

    async def publish_update(self, indicator: ThreatIndicator) -> None:
        """Publish threat intel update to Kafka."""
        if self.kafka_producer is None:
            return

        try:
            message = {
                "indicator_type": indicator.indicator_type,
                "value": indicator.value,
                "confidence": indicator.confidence,
                "severity": indicator.severity,
                "source": indicator.source,
                "timestamp": datetime.now(UTC).isoformat(),
            }

            self.kafka_producer.produce(
                "threat-intel-updates",
                key=indicator.value.encode(),
                value=json.dumps(message).encode(),
            )
            self.kafka_producer.poll(0)
        except Exception as e:
            logger.warning("Failed to publish threat intel update to Kafka: %s", e)

    async def run_enrichment_loop(self, indicators: list[tuple[str, str]]) -> None:
        """Run enrichment for a batch of indicators."""
        for indicator_type, value in indicators:
            if not self._running:
                break

            try:
                enriched = await self.enrich_indicator(indicator_type, value)

                for ind in enriched:
                    await self.publish_update(ind)

            except Exception as e:
                logger.error(
                    "Enrichment failed for %s:%s: %s", indicator_type, value, e
                )

            # Small delay to avoid overwhelming sources
            await asyncio.sleep(0.1)

    def start(self) -> None:
        """Mark worker as running."""
        self._running = True

    def stop(self) -> None:
        """Mark worker as stopped."""
        self._running = False


async def main() -> None:
    """Entry point for threat intel worker."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = aioredis.from_url(redis_url, decode_responses=True)

    try:
        await redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.error("Failed to connect to Redis: %s", e)
        return

    worker = ThreatIntelWorker(redis_client=redis_client)
    worker.start()

    # Example: enrich some IPs periodically
    test_indicators = [("ip", "1.2.3.4"), ("ip", "192.168.1.1")]

    try:
        while worker._running:
            await worker.run_enrichment_loop(test_indicators)
            await asyncio.sleep(300)  # Run every 5 minutes
    except asyncio.CancelledError:
        logger.info("Threat intel worker cancelled")
    finally:
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
