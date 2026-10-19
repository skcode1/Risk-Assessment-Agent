import json
import logging
import os
from typing import Any

from confluent_kafka import Producer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.core.kafka")

_producer: Producer | None = None


def get_producer() -> Producer:
    """Return the shared Kafka producer, creating it on first use."""
    global _producer
    if _producer is None:
        bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        _producer = Producer(
            {
                "bootstrap.servers": bootstrap,
                "acks": "all",
                "enable.idempotence": True,
                "linger.ms": 5,
            },
        )
        logger.info("Initialized Kafka producer for %s", bootstrap)
    return _producer


def publish_detection_event(payload: dict[str, Any]) -> bool:
    """
    Publish a detection event to the 'detections' topic.

    The payload must contain the fields parsed by the detection consumer:
    event_id, correlation_id, source_ip, detected_at (unix timestamp).

    Returns True when the message was buffered and flushed successfully,
    False otherwise (failure is non-fatal for the ingestion path).
    """
    topic = os.getenv("KAFKA_TOPIC_DETECTIONS", "detections")
    try:
        producer = get_producer()
        key = str(payload.get("event_id", "")).encode()
        producer.produce(topic, key=key, value=json.dumps(payload).encode())
        remaining = producer.flush(timeout=5.0)
        if remaining > 0:
            logger.warning(
                "Kafka flush timed out for detection %s (%d messages still queued)",
                payload.get("event_id"),
                remaining,
            )
            return False
        return True
    except Exception as exc:
        logger.warning(
            "Failed to publish detection %s to Kafka: %s",
            payload.get("event_id"),
            exc,
        )
        return False
