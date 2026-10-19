"""
SQLAlchemy 2.0 ORM Mapped Model for Risk Assessments.
Provides PostgreSQL table mapping, strict Decimal precision columns,
foreign key relationships, audit triggers, and JSONB snapshot storage.
"""

from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
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
from app.domain.models.enums import RiskCategory

if TYPE_CHECKING:
    from app.db.models.audit import AuditLogModel
    from app.db.models.detection import DetectionModel
    from app.db.models.policy import PolicyModel


class RiskAssessmentModel(Base):
    """
    Authoritative database entity for evaluated risk assessments.
    Enforces check constraints for range bounds [0.0, 100.0] and preserves
    immutable JSONB snapshots of components and applied policy configuration.
    """

    __tablename__ = "risk_assessments"

    assessment_id: Mapped[UUID] = mapped_column(
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

    policy_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("policies.policy_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    correlation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),  # Supports IPv4 and full IPv6 notations
        nullable=False,
        index=True,
    )

    # Risk Score evaluated strictly to 1 decimal place [0.0, 100.0]
    risk_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    rating: Mapped[RiskCategory] = mapped_column(
        SAEnum(
            RiskCategory,
            name="risk_category_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )

    # Component sub-scores stored as fixed-precision numerics
    behavior_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    frequency_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    sensitivity_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    history_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=False,
    )

    # Immutable raw snapshot dictionaries for forensic reproducibility
    components_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    applied_policy_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    # Analyst override metadata (if modified post-assessment)
    override_score: Mapped[Decimal | None] = mapped_column(
        Numeric(precision=5, scale=1, asdecimal=True),
        nullable=True,
    )

    override_rating: Mapped[RiskCategory | None] = mapped_column(
        SAEnum(
            RiskCategory,
            name="risk_category_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=True,
    )

    override_justification: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    overridden_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    overridden_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Temporal tracking
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
    detection: Mapped["DetectionModel"] = relationship(
        "DetectionModel",
        back_populates="risk_assessments",
        lazy="joined",
    )

    policy: Mapped["PolicyModel"] = relationship(
        "PolicyModel",
        back_populates="risk_assessments",
        lazy="joined",
    )

    audit_logs: Mapped[list["AuditLogModel"]] = relationship(
        "AuditLogModel",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 100.0",
            name="ck_risk_assessments_risk_score_bounds",
        ),
        CheckConstraint(
            "behavior_score >= 0.0 AND behavior_score <= 100.0",
            name="ck_risk_assessments_behavior_score_bounds",
        ),
        CheckConstraint(
            "frequency_score >= 0.0 AND frequency_score <= 100.0",
            name="ck_risk_assessments_frequency_score_bounds",
        ),
        CheckConstraint(
            "sensitivity_score >= 0.0 AND sensitivity_score <= 100.0",
            name="ck_risk_assessments_sensitivity_score_bounds",
        ),
        CheckConstraint(
            "history_score >= 0.0 AND history_score <= 100.0",
            name="ck_risk_assessments_history_score_bounds",
        ),
        CheckConstraint(
            "override_score IS NULL OR (override_score >= 0.0 AND override_score <= 100.0)",
            name="ck_risk_assessments_override_score_bounds",
        ),
        Index("ix_risk_assessments_created_at_rating", "created_at", "rating"),
        Index("ix_risk_assessments_source_ip_created_at", "source_ip", "created_at"),
    )
