"""
SQLAlchemy 2.0 ORM Mapped Model for System and Analyst Audit Trails.
Enforces an immutable, append-only record of administrative overrides,
policy transitions, and risk score adjustments.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.db.models.assessment import RiskAssessmentModel


class AuditLogModel(Base):
    """
    Authoritative database entity for append-only audit trail logging.
    Captures actor identity, operational action, target entity linkage,
    before/after state diff snapshots, and correlation identifiers.
    """

    __tablename__ = "audit_logs"

    # Primary key UUID
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    # Actor identity (e.g. username, email, or token subject)
    actor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    # Action name (e.g. ANALYST_SCORE_OVERRIDE, POLICY_ACTIVATION)
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    # Target assessment foreign key reference
    assessment_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("risk_assessments.assessment_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Unique correlation identifier for tracing and deduplication
    correlation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        default=uuid4,
    )

    # State snapshots
    before_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    after_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # Additional contextual metadata / override details
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # Timestamp alias to support both created_at and timestamp accesses
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    @property
    def timestamp(self) -> datetime:
        return self.created_at

    @timestamp.setter
    def timestamp(self, value: datetime) -> None:
        self.created_at = value

    # Relationship to parent assessment
    assessment: Mapped["RiskAssessmentModel"] = relationship(
        "RiskAssessmentModel",
        back_populates="audit_logs",
        lazy="joined",
    )

    __table_args__ = (
        Index("ix_audit_logs_actor_created_at", "actor", "created_at"),
        Index("ix_audit_logs_action_created_at", "action", "created_at"),
        Index("ix_audit_logs_assessment_created_at", "assessment_id", "created_at"),
    )
