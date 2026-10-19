"""
Domain entity models for DetectionEvent.
Represents immutable raw detection telemetry, confidence metrics, and network context
prior to normalization, correlation, and deterministic scoring.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from uuid import UUID, uuid4

from app.domain.models.enums import DetectionSeverity, DetectionSourceType


@dataclass(frozen=True, slots=True)
class DetectionMetrics:
    """
    Confidence, rule fidelity, and precision metrics attached to a detection.
    Supplies telemetry to the Behavior sub-score calculator.
    """
    confidence: Decimal
    fidelity: Decimal | None = None
    rule_accuracy_hint: Decimal | None = None

    def __post_init__(self) -> None:
        """Enforce Decimal precision and bounded numeric ranges."""
        conf = self.confidence
        if not isinstance(conf, Decimal):
            conf = Decimal(str(conf))
            object.__setattr__(self, "confidence", conf)

        q_conf = conf.quantize(Decimal("0.0001") if conf <= Decimal("1.0") else Decimal("0.1"), rounding=ROUND_HALF_UP)
        object.__setattr__(self, "confidence", q_conf)

        if not (Decimal("0.0") <= q_conf <= Decimal("100.0")):
            raise ValueError(
                f"Detection confidence must be bounded between [0.0, 100.0], got {q_conf}"
            )

        if self.fidelity is not None:
            fid = self.fidelity
            if not isinstance(fid, Decimal):
                fid = Decimal(str(fid))
                object.__setattr__(self, "fidelity", fid)
            q_fid = fid.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, "fidelity", q_fid)
            if not (Decimal("0.0") <= q_fid <= Decimal("1.0")):
                raise ValueError(
                    f"Fidelity indicator must be bounded between [0.0, 1.0], got {q_fid}"
                )

        if self.rule_accuracy_hint is not None:
            acc = self.rule_accuracy_hint
            if not isinstance(acc, Decimal):
                acc = Decimal(str(acc))
                object.__setattr__(self, "rule_accuracy_hint", acc)
            q_acc = acc.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, "rule_accuracy_hint", q_acc)
            if not (Decimal("0.0") <= q_acc <= Decimal("100.0")):
                raise ValueError(
                    f"Rule accuracy hint must be bounded between [0.0, 100.0], got {q_acc}"
                )


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """
    Host, user, signature, and network metadata tied to the detection.
    """
    rule_id: str
    rule_name: str
    technique_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("Rule ID cannot be empty.")
        if not self.rule_name or not self.rule_name.strip():
            raise ValueError("Rule Name cannot be empty.")


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """
    Authoritative immutable domain model representing an ingested detection event.
    Guarantees strict schema integrity, UTC timestamps, and unique distributed tracking IDs.
    """
    source_type: DetectionSourceType
    severity: DetectionSeverity
    metrics: DetectionMetrics
    context: DetectionContext
    event_id: UUID = field(default_factory=uuid4)
    correlation_id: UUID = field(default_factory=uuid4)
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ingested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate UTC timezone bounds for all timestamp fields."""
        for ts_field in ("detected_at", "ingested_at"):
            ts_val: datetime = getattr(self, ts_field)
            if ts_val.tzinfo is None:
                object.__setattr__(self, ts_field, ts_val.replace(tzinfo=UTC))
            else:
                object.__setattr__(self, ts_field, ts_val.astimezone(UTC))

    @property
    def confidence(self) -> Decimal:
        """Direct accessor for normalized confidence score [0.0, 100.0]."""
        return self.metrics.confidence

    @property
    def source_ip(self) -> str | None:
        """Direct accessor for event source IP address."""
        return self.context.source_ip

    @property
    def rule_id(self) -> str:
        """Direct accessor for detection rule identifier."""
        return self.context.rule_id

    def to_dict(self) -> dict[str, Any]:
        """Serializes the detection event to a JSON-compatible dictionary."""
        return {
            "event_id": str(self.event_id),
            "correlation_id": str(self.correlation_id),
            "source_type": self.source_type.value,
            "severity": self.severity.value,
            "metrics": {
                "confidence": float(self.metrics.confidence),
                "fidelity": float(self.metrics.fidelity) if self.metrics.fidelity is not None else None,
                "rule_accuracy_hint": (
                    float(self.metrics.rule_accuracy_hint)
                    if self.metrics.rule_accuracy_hint is not None
                    else None
                ),
            },
            "context": {
                "rule_id": self.context.rule_id,
                "rule_name": self.context.rule_name,
                "technique_id": self.context.technique_id,
                "source_ip": self.context.source_ip,
                "destination_ip": self.context.destination_ip,
                "hostname": self.context.hostname,
                "username": self.context.username,
                "raw_payload": self.context.raw_payload,
            },
            "detected_at": self.detected_at.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
        }