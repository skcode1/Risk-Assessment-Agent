"""
Pydantic v2 Schema Definitions for RiskAssessment Payloads.
Fully aligned with canonical schemas/risk/risk-assessment-v1.json and integration test suites.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from app.domain.models.enums import DetectionSeverity, DetectionSourceType, RiskCategory

if TYPE_CHECKING:
    from app.db.models.assessment import RiskAssessmentModel
    from app.domain.models.assessment import RiskAssessment


class RiskComponentsBreakdown(BaseModel):
    """Normalized sub-scores (0.0 - 100.0) calculated by deterministic calculators."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    behavior: Annotated[float, Field(..., ge=0.0, le=100.0)]
    frequency: Annotated[float, Field(..., ge=0.0, le=100.0)]
    sensitivity: Annotated[float, Field(..., ge=0.0, le=100.0)]
    history: Annotated[float, Field(..., ge=0.0, le=100.0)]


class DetectionMetricsRequest(BaseModel):
    """Strict detector confidence metrics for deterministic scoring."""

    model_config = ConfigDict(extra="ignore")

    confidence: Annotated[float, Field(..., ge=0.0, le=100.0)]
    fidelity: Annotated[float | None, Field(default=None, ge=0.0, le=1.0)]
    rule_accuracy_hint: Annotated[float | None, Field(default=None, ge=0.0, le=100.0)]


class DetectionContextRequest(BaseModel):
    """Host, user, and network context attached to a detection event."""

    model_config = ConfigDict(extra="ignore")

    rule_id: Annotated[str, Field(..., min_length=1, max_length=128)]
    rule_name: Annotated[str, Field(..., min_length=1, max_length=255)]
    technique_id: Annotated[str | None, Field(default=None)]
    source_ip: Annotated[str | None, Field(default=None, max_length=45)]
    destination_ip: Annotated[str | None, Field(default=None, max_length=45)]
    hostname: Annotated[str | None, Field(default=None, max_length=255)]
    username: Annotated[str | None, Field(default=None, max_length=128)]
    raw_payload: Annotated[dict[str, Any], Field(default_factory=dict)]


class DetectionEventRequest(BaseModel):
    """
    Strict ingestion contract for detection_event on POST /risk-assessments.

    A malformed correlation_id (or event_id) is rejected with HTTP 422 at the
    API boundary before any persistence or idempotency lock work occurs.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: Annotated[UUID | None, Field(default=None)]
    correlation_id: Annotated[UUID, Field(...)]
    source_type: Annotated[DetectionSourceType, Field(default=DetectionSourceType.EDR)]
    severity: Annotated[DetectionSeverity, Field(default=DetectionSeverity.HIGH)]
    metrics: Annotated[DetectionMetricsRequest, Field(...)]
    context: Annotated[DetectionContextRequest, Field(...)]


class AssessmentBase(BaseModel):
    """Core domain fields representing a risk evaluation."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    source_ip: Annotated[str | None, Field(default=None, max_length=64)]
    detection_id: Annotated[UUID | None, Field(default=None)]
    investigation_id: Annotated[UUID | None, Field(default=None)]
    policy_id: Annotated[UUID | None, Field(default=None)]


class AssessmentCreateRequest(AssessmentBase):
    """
    Ingest payload contract consumed by POST /api/v1/risk-assessments.
    Supports both canonical specification payloads and on-demand overrides.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    assessment_id: Annotated[UUID | None, Field(default=None)]
    detection_event: Annotated[DetectionEventRequest | None, Field(default=None)]
    investigation_result: Annotated[Any | None, Field(default=None)]
    components_override: Annotated[RiskComponentsBreakdown | None, Field(default=None)]


RiskAssessmentCreateRequest = AssessmentCreateRequest


class AssessmentResponse(AssessmentBase):
    """Standard serialized risk assessment entity returned by API endpoints."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    assessment_id: Annotated[UUID, Field(...)]
    risk_score: Annotated[float, Field(..., ge=0.0, le=100.0)]
    rating: Annotated[RiskCategory, Field(...)]
    components: Annotated[RiskComponentsBreakdown, Field(...)]
    applied_policy: Annotated[dict[str, Any] | None, Field(default=None)]
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(UTC))]

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @classmethod
    def from_domain_and_model(
        cls,
        *,
        assessment: "RiskAssessment",
        assessment_model: "RiskAssessmentModel",
    ) -> "AssessmentResponse":
        """Build the API response from the computed domain entity and its row."""
        return cls(
            assessment_id=assessment.assessment_id,
            detection_id=assessment.detection_event_id,
            investigation_id=assessment.investigation_id,
            policy_id=assessment_model.policy_id,
            source_ip=assessment.source_ip,
            risk_score=float(assessment.risk_score),
            rating=assessment.rating.value,
            components=assessment.components.to_dict(),
            applied_policy=assessment.applied_policy.to_dict(),
            created_at=assessment_model.created_at or datetime.now(UTC),
        )


RiskAssessmentResponse = AssessmentResponse


class AssessmentDetailResponse(AssessmentResponse):
    """Expanded audit payload returned by GET /api/v1/risk-assessments/{id}."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    policy_version: Annotated[str | int | None, Field(default=1)]
    narrative_explanation: Annotated[str | None, Field(default=None)]
    mitre_attack_context: Annotated[list[str], Field(default_factory=list)]
    metadata: Annotated[dict[str, Any], Field(default_factory=dict)]

    @classmethod
    def from_record(cls, record: "RiskAssessmentModel") -> "AssessmentDetailResponse":
        """
        Build a detail response directly from the ORM row.

        Explicit construction avoids pydantic ``from_attributes`` collisions
        with SQLAlchemy internals (``Base.metadata`` vs. the response
        ``metadata`` field) and maps snapshot columns (``components_snapshot``)
        onto the response contract.
        """
        snapshot = record.applied_policy_snapshot or {}
        metadata: dict[str, Any] = {}
        if record.override_score is not None:
            metadata["override"] = {
                "score": float(record.override_score),
                "rating": record.override_rating.value
                if record.override_rating
                else None,
                "justification": record.override_justification,
                "overridden_by": record.overridden_by,
                "overridden_at": record.overridden_at.isoformat()
                if record.overridden_at
                else None,
            }

        return cls(
            assessment_id=record.assessment_id,
            detection_id=record.detection_event_id,
            policy_id=record.policy_id,
            source_ip=record.source_ip,
            risk_score=float(record.risk_score),
            rating=record.rating.value
            if hasattr(record.rating, "value")
            else record.rating,
            components={
                "behavior": float(record.behavior_score),
                "frequency": float(record.frequency_score),
                "sensitivity": float(record.sensitivity_score),
                "history": float(record.history_score),
            },
            applied_policy=snapshot,
            policy_version=snapshot.get("version"),
            created_at=record.created_at,
            metadata=metadata,
        )


RiskAssessmentDetailResponse = AssessmentDetailResponse


class AssessmentOverrideRequest(BaseModel):
    """Schema for human-in-the-loop analyst score override and containment workflows."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    override_score: Annotated[float, Field(..., ge=0.0, le=100.0)]
    override_rating: RiskCategory = Field(...)
    justification: Annotated[str, Field(..., min_length=10, max_length=1024)]
    ticket_reference: Annotated[str | None, Field(default=None, max_length=64)]


class AssessmentListResponse(BaseModel):
    """Paginated collection wrapper for risk assessment entities."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    items: Annotated[list[AssessmentResponse], Field(default_factory=list)]
    total: Annotated[int, Field(default=0, ge=0)]
    limit: Annotated[int, Field(default=50, ge=1)]
    offset: Annotated[int, Field(default=0, ge=0)]


RiskAssessmentListResponse = AssessmentListResponse
