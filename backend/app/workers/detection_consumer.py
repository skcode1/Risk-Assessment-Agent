"""
Kafka Detection Consumer Worker.
Subscribes to 'detections' topic and updates Redis sliding-window counters atomically.
Implements at-least-once delivery semantics with offset commits after Redis success.
"""

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass

import redis.asyncio as aioredis
from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.serialization import StringDeserializer

from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.workers.detection_consumer")


@dataclass
class DetectionEventMessage:
    """Parsed detection event from Kafka."""
    event_id: str
    correlation_id: str
    source_ip: str
    detected_at: float  # Unix timestamp


class DetectionConsumer:
    """
    Consumes detection events from Kafka and updates Redis counters.
    
    Flow:
    1. Poll Kafka for messages
    2. Parse detection event
    3. Update Redis sliding window (ZREMRANGEBYSCORE + ZADD + EXPIRE) in pipeline
    4. Commit Kafka offset only after Redis success (at-least-once)
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        kafka_bootstrap_servers: str | None = None,
        kafka_group_id: str | None = None,
        kafka_topic: str = "detections",
        window_seconds: int | None = None,
    ) -> None:
        self.redis = redis_client
        self.topic = kafka_topic
        # Sliding window governed by SLIDING_WINDOW_SECONDS (settings -> env),
        # mirroring app/services/risk_service.py so frequency calculations and
        # counter pruning always use the same window.
        if window_seconds is None:
            window_seconds = int(getattr(settings.app, "SLIDING_WINDOW_SECONDS", 3600))
        self.window_seconds = window_seconds
        self._running = False
        self._consumer: Consumer | None = None

        bootstrap = kafka_bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        group = kafka_group_id or os.getenv("KAFKA_CONSUMER_GROUP", "detection-consumer-group")

        self._consumer = Consumer({
            "bootstrap.servers": bootstrap,
            "group.id": group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,  # Manual commit after Redis success
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 30000,
        })

        self._key_deserializer = StringDeserializer("utf-8")
        self._value_deserializer = StringDeserializer("utf-8")

    def _parse_message(self, value: str) -> DetectionEventMessage | None:
        """Parse Kafka message value into DetectionEventMessage."""
        try:
            data = json.loads(value)
            return DetectionEventMessage(
                event_id=data.get("event_id", ""),
                correlation_id=data.get("correlation_id", ""),
                source_ip=data.get("source_ip", ""),
                detected_at=float(data.get("detected_at", time.time())),
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            logger.warning("Failed to parse detection message: %s", e)
            return None

    async def _update_redis_counter(self, event: DetectionEventMessage) -> bool:
        """Update Redis sliding window counter for the source IP."""
        if not event.source_ip:
            logger.warning("Missing source_ip in detection event, skipping counter update")
            return False

        counter_key = f"counter:{event.source_ip}:events"
        now_ts = event.detected_at
        min_ts = now_ts - self.window_seconds

        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(counter_key, "-inf", min_ts)
                pipe.zadd(counter_key, {event.event_id: now_ts})
                pipe.expire(counter_key, self.window_seconds * 2)
                await pipe.execute()
            return True
        except Exception as e:
            logger.error("Redis counter update failed for %s: %s", event.source_ip, e)
            return False

    async def start(self) -> None:
        """Start consuming messages from Kafka."""
        self._running = True
        self._consumer.subscribe([self.topic])
        logger.info("Detection consumer started, subscribed to topic: %s", self.topic)

        # Handle graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        try:
            while self._running:
                # Poll with timeout to allow periodic checks of _running flag
                msg = self._consumer.poll(timeout=1.0)
                
                if msg is None:
                    continue
                
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        logger.debug("Reached end of partition: %s [%d]", msg.topic(), msg.partition())
                    else:
                        logger.error("Kafka error: %s", msg.error())
                    continue

                # Parse message
                event = self._parse_message(msg.value())
                if event is None:
                    # Still commit offset to avoid stuck on bad messages
                    self._consumer.commit(msg)
                    continue

                # Update Redis counter
                success = await self._update_redis_counter(event)
                
                if success:
                    # Commit offset only after Redis success (at-least-once)
                    try:
                        self._consumer.commit(msg)
                        logger.debug("Processed event %s for IP %s", event.event_id, event.source_ip)
                    except KafkaException as e:
                        logger.error("Failed to commit offset: %s", e)
                else:
                    # Don't commit offset, will retry on next poll
                    logger.warning("Redis update failed, will retry event %s", event.event_id)

        except asyncio.CancelledError:
            logger.info("Detection consumer cancelled")
        except Exception:
            logger.exception("Detection consumer error")
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the consumer gracefully."""
        if not self._running:
            return
        
        self._running = False
        logger.info("Stopping detection consumer...")
        
        if self._consumer:
            try:
                # Close consumer (this also commits any pending offsets)
                self._consumer.close()
            except Exception as e:
                logger.warning("Error closing Kafka consumer: %s", e)
        
        logger.info("Detection consumer stopped")


async def main() -> None:
    """Entry point for running the detection consumer as a standalone worker."""
    # Initialize Redis client
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = aioredis.from_url(redis_url, decode_responses=True)
    
    try:
        # Verify Redis connection
        await redis_client.ping()
        logger.info("Connected to Redis at %s", redis_url)
    except Exception as e:
        logger.error("Failed to connect to Redis: %s", e)
        return

    # Create and start consumer
    consumer = DetectionConsumer(redis_client=redis_client)
    
    try:
        await consumer.start()
    finally:
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())