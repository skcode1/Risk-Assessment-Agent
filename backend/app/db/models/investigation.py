"""
SQLAlchemy 2.0 ORM Mapped Model for Security Investigations.
Maps correlated investigation telemetry, lateral endpoint spread,
and recurrence metrics feeding into the deterministic risk scoring kernel.
"""

from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.domain.models.enums import EndpointClass

if TYPE_CHECKING:
    from app.db.models.detection import DetectionModel


class InvestigationModel(Base):
    """
    Authoritative database entity for security investigation telemetry.
    Stores sliding-window recurrence frequency, touched asset counts,
    dominant endpoint classification, and itemized compromised nodes.
    """

    __tablename__ = "investigations"

    investigation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    detection_event_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("detections.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    correlation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # Telemetry metrics feeding directly into kernel calculators
    event_frequency: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    endpoints_touched: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    dominant_endpoint_class: Mapped[EndpointClass] = mapped_column(
        SAEnum(
            EndpointClass,
            name="endpoint_class_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )

    historical_incident_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Optional qualitative severity hint from correlation rules [0.0, 100.0]
    severity_hint: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=True,
    )

    # Itemized network endpoints touched: [ {"endpoint_id": str, "endpoint_class": str, "is_compromised": bool} ]
    touched_endpoints_detail: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    # Extended telemetry context (e.g., process lineage, network flows, sandboxing IOCs)
    telemetry_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    investigated_by: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    detection: Mapped["DetectionModel"] = relationship(
        "DetectionModel",
        lazy="joined",
    )

    __table_args__ = (
        CheckConstraint(
            "event_frequency >= 0",
            name="ck_investigations_event_frequency_non_negative",
        ),
        CheckConstraint(
            "endpoints_touched >= 0",
            name="ck_investigations_endpoints_touched_non_negative",
        ),
        CheckConstraint(
            "historical_incident_count >= 0",
            name="ck_investigations_historical_incident_count_non_negative",
        ),
        CheckConstraint(
            "severity_hint IS NULL OR (severity_hint >= 0.0 AND severity_hint <= 100.0)",
            name="ck_investigations_severity_hint_bounds",
        ),
        Index("ix_investigations_correlation_created_at", "correlation_id", "created_at"),
        Index("ix_investigations_endpoint_class_frequency", "dominant_endpoint_class", "event_frequency"),
    )