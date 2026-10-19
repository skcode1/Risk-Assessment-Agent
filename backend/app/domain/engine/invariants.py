"""
Deterministic Risk Scoring Kernel Invariant Verifier.
Enforces strict IEEE-754 precision immunity, rounding rules, range bounds [0.0, 100.0],
non-null guarantees, and contract integrity across all components and engine outputs.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any
from uuid import UUID

from app.domain.models.assessment import RiskAssessment, RiskComponents
from app.domain.models.detection import DetectionEvent
from app.domain.models.investigation import InvestigationResult
from app.domain.models.policy import RiskPolicy


class InvariantViolationError(ValueError):
    """Raised when an architectural, mathematical, or integrity invariant is violated."""

    def __init__(
        self, rule_name: str, message: str, context: Mapping[str, Any] | None = None
    ) -> None:
        self.rule_name = rule_name
        self.context = dict(context) if context else {}
        # Public contract used by exception handlers and the orchestration
        # services when translating invariant failures into API errors.
        self.message = message
        self.details = self.context
        super().__init__(
            f"[{rule_name}] Invariant Violation: {message} | Context: {self.context}"
        )


@dataclass(frozen=True, slots=True)
class InvariantRuleConfig:
    """
    Dynamic parameters governing precision bounds, quantization formats, and thresholds.
    Eliminates hardcoded mathematical assertions and enables runtime policy synchronization.
    """

    min_score_bound: Decimal = Decimal("0.0")
    max_score_bound: Decimal = Decimal("100.0")
    quantization_precision: Decimal = Decimal("0.1")
    rounding_mode: str = ROUND_HALF_UP
    enforce_weight_sum_unity: bool = True
    required_component_keys: Sequence[str] = (
        "behavior",
        "frequency",
        "sensitivity",
        "history",
    )

    def __post_init__(self) -> None:
        if self.min_score_bound >= self.max_score_bound:
            raise InvariantViolationError(
                rule_name="CONFIG_BOUNDS_ORDER",
                message=f"min_score_bound ({self.min_score_bound}) must be less than max_score_bound ({self.max_score_bound})",
            )


class ScoringInvariantVerifier:
    """
    Production-grade mathematical and schema invariant verifier.
    Executes pre-calculation, in-flight component verification, and post-calculation validation.
    """

    def __init__(self, config: InvariantRuleConfig | None = None) -> None:
        self._config = config or InvariantRuleConfig()

    def enforce_non_null(self, target: Any, param_name: str) -> Any:
        """Enforces that a critical engine input or object reference is not None."""
        if target is None:
            raise InvariantViolationError(
                rule_name="NON_NULL_GUARANTEE",
                message=f"Parameter '{param_name}' cannot be null or None.",
                context={"parameter": param_name},
            )
        return target

    def enforce_valid_uuid(self, identifier: UUID | None, field_name: str) -> UUID:
        """Enforces non-null tracking ID format for telemetry correlation."""
        self.enforce_non_null(identifier, field_name)
        if not isinstance(identifier, UUID):
            try:
                parsed_uuid = UUID(str(identifier))
                return parsed_uuid
            except (ValueError, TypeError) as err:
                raise InvariantViolationError(
                    rule_name="UUID_INTEGRITY",
                    message=f"Field '{field_name}' must be a valid UUID instance.",
                    context={"field": field_name, "raw_value": identifier},
                ) from err
        return identifier

    def enforce_decimal_quantization(self, value: Any, field_name: str) -> Decimal:
        """
        Guarantees that a numeric value is converted safely to a Decimal,
        quantized strictly to configured decimal precision, and rounded using ROUND_HALF_UP.
        Prevents IEEE-754 floating-point drift across calculation kernels.
        """
        self.enforce_non_null(value, field_name)

        if not isinstance(value, Decimal):
            try:
                decimal_val = Decimal(str(value))
            except (InvalidOperation, TypeError, ValueError) as err:
                raise InvariantViolationError(
                    rule_name="DECIMAL_CONVERSION_ERROR",
                    message=f"Field '{field_name}' with value '{value}' cannot be converted to Decimal.",
                    context={"field": field_name, "value": str(value)},
                ) from err
        else:
            decimal_val = value

        if decimal_val.is_nan() or decimal_val.is_infinite():
            raise InvariantViolationError(
                rule_name="FINITE_NUMBER_REQUIRED",
                message=f"Field '{field_name}' must be a finite numerical value, got {decimal_val}.",
                context={"field": field_name, "value": str(decimal_val)},
            )

        quantized = decimal_val.quantize(
            self._config.quantization_precision,
            rounding=self._config.rounding_mode,
        )
        return quantized

    def enforce_score_bounds(self, score: Decimal, field_name: str) -> Decimal:
        """
        Enforces that a score or sub-score falls strictly within [min_score_bound, max_score_bound] inclusive.
        """
        q_score = self.enforce_decimal_quantization(score, field_name)

        if not (
            self._config.min_score_bound <= q_score <= self._config.max_score_bound
        ):
            raise InvariantViolationError(
                rule_name="SCORE_BOUND_VIOLATION",
                message=(
                    f"Score '{field_name}' with value {q_score} falls outside permitted range "
                    f"[{self._config.min_score_bound}, {self._config.max_score_bound}]."
                ),
                context={
                    "field": field_name,
                    "value": str(q_score),
                    "min_bound": str(self._config.min_score_bound),
                    "max_bound": str(self._config.max_score_bound),
                },
            )
        return q_score

    def verify_components(self, components: RiskComponents) -> None:
        """
        Verifies that all normalized sub-scores satisfy non-null, Decimal quantization,
        and [0.0, 100.0] range invariants.
        """
        self.enforce_non_null(components, "components")

        for key in self._config.required_component_keys:
            if not hasattr(components, key):
                raise InvariantViolationError(
                    rule_name="MISSING_COMPONENT_SUB_SCORE",
                    message=f"RiskComponents is missing required component field '{key}'.",
                    context={"missing_field": key},
                )
            raw_val = getattr(components, key)
            self.enforce_score_bounds(raw_val, f"components.{key}")

    def verify_policy_invariants(self, policy: RiskPolicy) -> None:
        """
        Verifies policy versioning, non-null properties, dynamic weights, and threshold configuration.
        """
        self.enforce_non_null(policy, "policy")
        self.enforce_non_null(policy.version, "policy.version")
        if not str(policy.version).strip():
            raise InvariantViolationError(
                rule_name="POLICY_VERSION_EMPTY",
                message="Policy version string cannot be blank or empty.",
            )

        self.enforce_non_null(policy.weights, "policy.weights")
        if self._config.enforce_weight_sum_unity:
            total_weight = (
                self.enforce_decimal_quantization(
                    policy.weights.behavior, "policy.weights.behavior"
                )
                + self.enforce_decimal_quantization(
                    policy.weights.frequency, "policy.weights.frequency"
                )
                + self.enforce_decimal_quantization(
                    policy.weights.sensitivity, "policy.weights.sensitivity"
                )
                + self.enforce_decimal_quantization(
                    policy.weights.history, "policy.weights.history"
                )
            )
            if total_weight != Decimal("1.00"):
                raise InvariantViolationError(
                    rule_name="WEIGHTS_SUM_INVARIANT",
                    message=f"Policy weights must sum exactly to 1.00, received sum: {total_weight}.",
                    context={"weight_sum": str(total_weight)},
                )

        self.enforce_non_null(policy.thresholds, "policy.thresholds")

    def verify_inputs(
        self,
        detection: DetectionEvent,
        investigation: InvestigationResult,
        policy: RiskPolicy,
    ) -> None:
        """Pre-execution integrity verification on raw input telemetry entities."""
        self.enforce_non_null(detection, "detection")
        self.enforce_valid_uuid(detection.event_id, "detection.event_id")
        self.enforce_valid_uuid(detection.correlation_id, "detection.correlation_id")

        self.enforce_non_null(investigation, "investigation")
        self.enforce_valid_uuid(
            investigation.investigation_id, "investigation.investigation_id"
        )
        self.enforce_valid_uuid(
            investigation.correlation_id, "investigation.correlation_id"
        )

        if detection.correlation_id != investigation.correlation_id:
            raise InvariantViolationError(
                rule_name="CORRELATION_ID_MISMATCH",
                message="Detection and investigation records carry mismatched correlation IDs.",
                context={
                    "detection_correlation_id": str(detection.correlation_id),
                    "investigation_correlation_id": str(investigation.correlation_id),
                },
            )

        self.verify_policy_invariants(policy)

    def verify_assessment(self, assessment: RiskAssessment, policy: RiskPolicy) -> None:
        """
        Post-calculation verification ensuring output scores and categorical ratings
        adhere strictly to documented thresholds and mathematical invariants.
        """
        self.enforce_non_null(assessment, "assessment")
        self.enforce_valid_uuid(assessment.assessment_id, "assessment.assessment_id")
        self.enforce_valid_uuid(
            assessment.detection_event_id, "assessment.detection_event_id"
        )
        self.enforce_valid_uuid(
            assessment.investigation_id, "assessment.investigation_id"
        )
        self.enforce_valid_uuid(assessment.correlation_id, "assessment.correlation_id")

        # 1. Bounds check on the authoritative score
        score = self.enforce_score_bounds(
            assessment.risk_score, "assessment.risk_score"
        )

        # 2. Component sub-score checks
        self.verify_components(assessment.components)

        # 3. Deterministic Category Mapping Invariant Verification
        expected_category = policy.resolve_category(score)
        if assessment.rating != expected_category:
            raise InvariantViolationError(
                rule_name="CATEGORY_MAPPING_INVARIANT",
                message=(
                    f"Assessment rating '{assessment.rating.value}' does not match policy resolution "
                    f"'{expected_category.value}' for risk_score {score}."
                ),
                context={
                    "score": str(score),
                    "actual_rating": assessment.rating.value,
                    "expected_rating": expected_category.value,
                    "policy_version": policy.version,
                },
            )

        # 4. Strict spec numerical invariant check: Verify calculation determinism
        w_b = self.enforce_decimal_quantization(
            policy.weights.behavior, "weights.behavior"
        )
        w_f = self.enforce_decimal_quantization(
            policy.weights.frequency, "weights.frequency"
        )
        w_s = self.enforce_decimal_quantization(
            policy.weights.sensitivity, "weights.sensitivity"
        )
        w_h = self.enforce_decimal_quantization(
            policy.weights.history, "weights.history"
        )

        recalculated_raw = (
            (assessment.components.behavior * w_b)
            + (assessment.components.frequency * w_f)
            + (assessment.components.sensitivity * w_s)
            + (assessment.components.history * w_h)
        )
        recalculated_quantized = recalculated_raw.quantize(
            self._config.quantization_precision,
            rounding=self._config.rounding_mode,
        )

        if score != recalculated_quantized:
            raise InvariantViolationError(
                rule_name="DETERMINISTIC_REPRODUCIBILITY_FAILURE",
                message=(
                    f"Persisted score {score} does not match recalculated value {recalculated_quantized} "
                    f"for components B={assessment.components.behavior}, F={assessment.components.frequency}, "
                    f"S={assessment.components.sensitivity}, H={assessment.components.history}."
                ),
                context={
                    "persisted_score": str(score),
                    "recalculated_score": str(recalculated_quantized),
                },
            )
