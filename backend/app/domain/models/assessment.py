"""
Domain entity models for Risk Assessment.
Defines immutable domain representation, mathematical invariants,
and persistence mappings for authoritative risk scoring outputs.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from uuid import UUID, uuid4

from app.domain.models.enums import AssessmentStatus, RiskCategory


@dataclass(frozen=True, slots=True)
class RiskComponents:
    """
    Immutable representation of normalized sub-scores (0.0 to 100.0 scale).
    Risk formula: 0.4*B + 0.3*F + 0.2*S + 0.1*H.
    """

    behavior: Decimal
    frequency: Decimal
    sensitivity: Decimal
    history: Decimal

    def __post_init__(self) -> None:
        """Validate component bounds and quantize to 1 decimal place."""
        for field_name in ("behavior", "frequency", "sensitivity", "history"):
            val: Decimal = getattr(self, field_name)
            if not isinstance(val, Decimal):
                val = Decimal(str(val))
                object.__setattr__(self, field_name, val)

            q_val = val.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, field_name, q_val)

            if not (Decimal("0.0") <= q_val <= Decimal("100.0")):
                raise ValueError(
                    f"Component sub-score '{field_name}' must be within [0.0, 100.0], got {q_val}"
                )

    def to_dict(self) -> dict[str, float]:
        return {
            "behavior": float(self.behavior),
            "frequency": float(self.frequency),
            "sensitivity": float(self.sensitivity),
            "history": float(self.history),
        }


@dataclass(frozen=True, slots=True)
class AppliedPolicySnapshot:
    """
    Preserved snapshot of policy parameters active during score calculation.
    Guarantees replayability and deterministic validation across simulation runs.
    """

    policy_id: UUID
    version: str
    weights: dict[str, Decimal]
    thresholds: dict[str, Any]  # Category thresholds for rating resolution

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("Policy version identifier cannot be empty")
        if not self.weights:
            raise ValueError("Applied weights dictionary cannot be empty")
        if not self.thresholds:
            raise ValueError("Applied thresholds dictionary cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable forensic snapshot of applied policy parameters."""
        return {
            "policy_id": str(self.policy_id),
            "version": self.version,
            "weights": {key: str(value) for key, value in self.weights.items()},
            "thresholds": self.thresholds,
        }

    def resolve_category(self, score: Decimal) -> RiskCategory:
        """Resolve category using the snapshot's thresholds."""
        q_score = score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        # Reconstruct threshold tiers from snapshot
        tiers = self.thresholds.get("tiers", [])
        for tier in tiers:
            min_score = Decimal(str(tier["min_score"]))
            max_score = Decimal(str(tier["max_score"]))
            if min_score <= q_score <= max_score:
                return RiskCategory(tier["category"])

        # Fallback to spec defaults
        if q_score < Decimal("40.0"):
            return RiskCategory.LOW
        elif q_score < Decimal("65.0"):
            return RiskCategory.MEDIUM
        elif q_score < Decimal("85.0"):
            return RiskCategory.HIGH
        else:
            return RiskCategory.CRITICAL


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """
    Authoritative domain entity for computed risk assessments.
    Enforces deterministic reproducibility, data immutability, and spec invariants.
    """

    detection_event_id: UUID
    investigation_id: UUID
    correlation_id: UUID
    source_ip: str | None
    risk_score: Decimal
    rating: RiskCategory
    components: RiskComponents
    applied_policy: AppliedPolicySnapshot
    assessment_id: UUID = field(default_factory=uuid4)
    status: AssessmentStatus = field(default=AssessmentStatus.COMPUTED)
    explanation_id: UUID | None = None
    evidence_keys: list[str] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate score quantization, range bounds, and category invariants."""
        # Ensure Decimal type and 1-decimal-place quantization
        score = self.risk_score
        if not isinstance(score, Decimal):
            score = Decimal(str(score))
            object.__setattr__(self, "risk_score", score)

        q_score = score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        object.__setattr__(self, "risk_score", q_score)

        if not (Decimal("0.0") <= q_score <= Decimal("100.0")):
            raise ValueError(
                f"authoritative risk_score must be between 0.0 and 100.0, got {q_score}"
            )

        # Ensure UTC timezone integrity
        if self.computed_at.tzinfo is None:
            object.__setattr__(
                self, "computed_at", self.computed_at.replace(tzinfo=UTC)
            )
        else:
            object.__setattr__(self, "computed_at", self.computed_at.astimezone(UTC))

        # Enforce threshold mapping invariants using applied policy snapshot
        expected_rating = self.applied_policy.resolve_category(q_score)
        if self.rating != expected_rating:
            raise ValueError(
                f"Rating invariant violation: Score {q_score} maps strictly to {expected_rating.value}, "
                f"but received {self.rating.value}."
            )

    @classmethod
    def create(
        cls,
        detection_event_id: UUID,
        investigation_id: UUID,
        correlation_id: UUID,
        source_ip: str | None,
        components: RiskComponents,
        applied_policy: AppliedPolicySnapshot,
        explanation_id: UUID | None = None,
        evidence_keys: list[str] | None = None,
        assessment_id: UUID | None = None,
    ) -> "RiskAssessment":
        """
        Factory to calculate weighted score deterministically and construct RiskAssessment.
        Calculates: Risk = w_b*B + w_f*F + w_s*S + w_h*H.
        Category is resolved via applied_policy snapshot thresholds.
        """
        w_b = applied_policy.weights.get("behavior", Decimal("0.4"))
        w_f = applied_policy.weights.get("frequency", Decimal("0.3"))
        w_s = applied_policy.weights.get("sensitivity", Decimal("0.2"))
        w_h = applied_policy.weights.get("history", Decimal("0.1"))

        raw_score = (
            (components.behavior * w_b)
            + (components.frequency * w_f)
            + (components.sensitivity * w_s)
            + (components.history * w_h)
        )
        calculated_score = raw_score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        # Resolve category using policy thresholds from snapshot
        category = applied_policy.resolve_category(calculated_score)

        return cls(
            assessment_id=assessment_id or uuid4(),
            detection_event_id=detection_event_id,
            investigation_id=investigation_id,
            correlation_id=correlation_id,
            source_ip=source_ip,
            risk_score=calculated_score,
            rating=category,
            components=components,
            applied_policy=applied_policy,
            status=AssessmentStatus.COMPUTED,
            explanation_id=explanation_id,
            evidence_keys=evidence_keys or [],
            computed_at=datetime.now(UTC),
        )

    def to_spec_dict(self) -> dict[str, Any]:
        """
        Serializes into the exact JSON format defined in the 6.3 spec:
        {
          "source_ip": "1.2.3.4",
          "risk_score": 83.5,
          "rating": "HIGH",
          "components": { ... }
        }
        """
        return {
            "source_ip": self.source_ip,
            "risk_score": float(self.risk_score),
            "rating": self.rating.value,
            "components": self.components.to_dict(),
        }
