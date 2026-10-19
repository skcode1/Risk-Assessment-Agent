"""
SQLAlchemy 2.0 ORM Mapped Model for Security Detections.
Provides PostgreSQL schema mapping, strict Decimal metrics constraints,
foreign key cascades to assessments, and structured context storage.
"""

from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.domain.models.enums import DetectionSeverity, DetectionSourceType

if TYPE_CHECKING:
    from app.db.models.assessment import RiskAssessmentModel


class DetectionModel(Base):
    """
    Authoritative database entity for ingested security detection events.
    Preserves raw sensor signals, confidence bounds [0.0, 100.0],
    investigation metrics, and full contextual telemetry in JSONB.
    """

    __tablename__ = "detections"

    event_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    correlation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    source_type: Mapped[DetectionSourceType] = mapped_column(
        SAEnum(
            DetectionSourceType,
            name="detection_source_type_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )

    severity: Mapped[DetectionSeverity] = mapped_column(
        SAEnum(
            DetectionSeverity,
            name="detection_severity_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )

    # Core normalized confidence metric [0.0, 100.0]
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    # Optional signature precision / sensor fidelity metric [0.0, 1.0]
    fidelity: Mapped[Decimal | None] = mapped_column(
        Numeric(precision=4, scale=3, asdecimal=True),
        nullable=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    rule_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    raw_payload: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Rich detection telemetry context (MITRE ATT&CK tags, process trees, environment hints)
    context_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    # Ingestion & observation temporal metadata
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    risk_assessments: Mapped[list["RiskAssessmentModel"]] = relationship(
        "RiskAssessmentModel",
        back_populates="detection",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 100.0",
            name="ck_detections_confidence_bounds",
        ),
        CheckConstraint(
            "fidelity IS NULL OR (fidelity >= 0.0 AND fidelity <= 1.0)",
            name="ck_detections_fidelity_bounds",
        ),
        Index("ix_detections_correlation_detected_at", "correlation_id", "detected_at"),
        Index("ix_detections_source_ip_detected_at", "source_ip", "detected_at"),
        Index("ix_detections_rule_id_severity", "rule_id", "severity"),
    )
