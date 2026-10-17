"""
SQLAlchemy 2.0 ORM Mapped Model for Risk Policies.
Provides PostgreSQL table mapping, strict Decimal weight constraints (sum to 1.00),
versioning, continuous threshold serialization in JSONB, and assessment relationships.
"""

from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.db.models.assessment import RiskAssessmentModel


class PolicyModel(Base):
    """
    Authoritative database entity for versioned Risk Scoring Policies.
    Persists deterministic weights, custom endpoint sensitivity overrides,
    and category threshold boundary definitions.
    """

    __tablename__ = "policies"

    policy_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    # Component weights stored as fixed-precision Decimals
    weight_behavior: Mapped[Decimal] = mapped_column(
        Numeric(precision=3, scale=2, asdecimal=True),
        nullable=False,
    )

    weight_frequency: Mapped[Decimal] = mapped_column(
        Numeric(precision=3, scale=2, asdecimal=True),
        nullable=False,
    )

    weight_sensitivity: Mapped[Decimal] = mapped_column(
        Numeric(precision=3, scale=2, asdecimal=True),
        nullable=False,
    )

    weight_history: Mapped[Decimal] = mapped_column(
        Numeric(precision=3, scale=2, asdecimal=True),
        nullable=False,
    )

    # Dynamic JSONB storage for category threshold intervals
    thresholds_config: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    # Dynamic overrides for specific asset endpoint classes (e.g. {"DOMAIN_CONTROLLER": 95.0})
    endpoint_class_weights: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    # Governance & regulatory audit metadata
    metadata_info: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    created_by: Mapped[Optional[str]] = mapped_column(
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
    risk_assessments: Mapped[List["RiskAssessmentModel"]] = relationship(
        "RiskAssessmentModel",
        back_populates="policy",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "weight_behavior >= 0.00 AND weight_behavior <= 1.00",
            name="ck_policies_weight_behavior_bounds",
        ),
        CheckConstraint(
            "weight_frequency >= 0.00 AND weight_frequency <= 1.00",
            name="ck_policies_weight_frequency_bounds",
        ),
        CheckConstraint(
            "weight_sensitivity >= 0.00 AND weight_sensitivity <= 1.00",
            name="ck_policies_weight_sensitivity_bounds",
        ),
        CheckConstraint(
            "weight_history >= 0.00 AND weight_history <= 1.00",
            name="ck_policies_weight_history_bounds",
        ),
        CheckConstraint(
            "(weight_behavior + weight_frequency + weight_sensitivity + weight_history) = 1.00",
            name="ck_policies_weights_sum_unity",
        ),
        Index("ix_policies_version_active", "version", "is_active"),
    )