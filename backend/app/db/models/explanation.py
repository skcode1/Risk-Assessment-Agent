"""
SQLAlchemy 2.0 ORM Mapped Model for LLM-Generated Risk Explanations.
Maps decoupled narrative explanations, evidence citations, primary component drivers,
guardrail validation checks, and foreign key relationships to RiskAssessmentModel.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
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
from app.domain.models.enums import ComponentDriver, ExplanationSource

if TYPE_CHECKING:
    from app.db.models.assessment import RiskAssessmentModel


class RiskExplanationModel(Base):
    """
    Authoritative database entity for LLM-generated risk explanations.
    Maintains complete isolation from numeric calculations, persisting narratives,
    grounding citations, source models, and guardrail pass/fail states in JSONB.
    """

    __tablename__ = "risk_explanations"

    explanation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    assessment_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("risk_assessments.assessment_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    summary_narrative: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    primary_driver: Mapped[ComponentDriver] = mapped_column(
        SAEnum(
            ComponentDriver,
            name="component_driver_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )

    # Key explanatory points stored as an array of strings
    key_factors: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    # Telemetry citations verifying grounding [ {claim, source_field, observed_value} ]
    evidence_citations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    source: Mapped[ExplanationSource] = mapped_column(
        SAEnum(
            ExplanationSource,
            name="explanation_source_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=ExplanationSource.CONSTRAINED_LLM,
        index=True,
    )

    model_identifier: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    # Guardrail evaluation outcome
    guardrails_passed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    guardrail_validation_details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    # LLM execution latency, token counts, and completion statistics
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
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
    assessment: Mapped["RiskAssessmentModel"] = relationship(
        "RiskAssessmentModel",
        lazy="joined",
    )

    __table_args__ = (
        Index("ix_risk_explanations_driver_created_at", "primary_driver", "created_at"),
        Index("ix_risk_explanations_source_created_at", "source", "created_at"),
    )