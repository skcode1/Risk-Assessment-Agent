"""
Deterministic Risk Scoring Kernel.
Executes the authoritative weighted risk calculation:
    Risk = 0.4B + 0.3F + 0.2S + 0.1H
Guarantees mathematical invariance, IEEE-754 precision immunity,
versioned governance, and complete execution auditability.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Mapping, Optional
from uuid import UUID, uuid4

from app.domain.models.assessment import (
    AppliedPolicySnapshot,
    RiskAssessment,
    RiskComponents,
)
from app.domain.models.detection import DetectionEvent
from app.domain.models.enums import RiskCategory
from app.domain.models.investigation import InvestigationResult
from app.domain.models.policy import PolicyWeights, RiskPolicy
from app.domain.engine.calculators.behavior import DynamicBehaviorCalculator
from app.domain.engine.calculators.frequency import DynamicFrequencyCalculator
from app.domain.engine.calculators.history import DynamicHistoryCalculator
from app.domain.engine.calculators.sensitivity import DynamicSensitivityCalculator
from app.domain.engine.resolver import DynamicRiskCategoryResolver


@dataclass(frozen=True, slots=True)
class KernelExecutionAudit:
    """Audit trace capturing raw evaluation steps and precision checkpoints."""
    kernel_execution_id: UUID
    policy_id: UUID
    policy_version: str
    raw_weighted_sum: Decimal
    quantized_score: Decimal
    resolved_category: RiskCategory
    weights_applied: Dict[str, Decimal]


@dataclass(frozen=True, slots=True)
class ScoringKernelResult:
    """Authoritative result emitted by the scoring engine prior to pipeline routing."""
    risk_score: Decimal
    rating: RiskCategory
    components: RiskComponents
    applied_policy: AppliedPolicySnapshot
    audit_trace: KernelExecutionAudit


class RiskScoringEngineInterface(ABC):
    """Abstract interface defining the deterministic risk scoring engine contract."""

    @abstractmethod
    def evaluate(
        self,
        detection: DetectionEvent,
        investigation: InvestigationResult,
        policy: RiskPolicy,
        runtime_parameters: Optional[Mapping[str, Any]] = None,
    ) -> RiskAssessment:
        """Evaluates detection and investigation contexts into an authoritative RiskAssessment."""
        pass


class DeterministicRiskScoringKernel(RiskScoringEngineInterface):
    """
    Authoritative, non-LLM Deterministic Scoring Kernel.
    Orchestrates B, F, S, H calculators and maps the weighted sum against versioned policies.
    
    Formula:
        Risk = w_b * B + w_f * F + w_s * S + w_h * H
    
    Default spec invariants:
        w_b = 0.40, w_f = 0.30, w_s = 0.20, w_h = 0.10
    """

    def __init__(
        self,
        behavior_calculator: Optional[DynamicBehaviorCalculator] = None,
        frequency_calculator: Optional[DynamicFrequencyCalculator] = None,
        sensitivity_calculator: Optional[DynamicSensitivityCalculator] = None,
        history_calculator: Optional[DynamicHistoryCalculator] = None,
        category_resolver: Optional[DynamicRiskCategoryResolver] = None,
    ) -> None:
        self._behavior_calculator = behavior_calculator or DynamicBehaviorCalculator()
        self._frequency_calculator = frequency_calculator or DynamicFrequencyCalculator()
        self._sensitivity_calculator = sensitivity_calculator or DynamicSensitivityCalculator()
        self._history_calculator = history_calculator or DynamicHistoryCalculator()
        self._category_resolver = category_resolver or DynamicRiskCategoryResolver()

    def evaluate(
        self,
        detection: DetectionEvent,
        investigation: InvestigationResult,
        policy: RiskPolicy,
        runtime_parameters: Optional[Mapping[str, Any]] = None,
    ) -> RiskAssessment:
        """
        Calculates normalized components, executes strict Decimal weighted arithmetic,
        resolves categorical rating via policy thresholds, and constructs an immutable RiskAssessment.
        """
        params = runtime_parameters or {}

        # 1. Dynamically compute the 4 normalized sub-scores (0-100 scale)
        behavior_score = self._behavior_calculator.calculate(
            detection=detection,
            investigation=investigation,
            parameters=params.get("behavior"),
        )
        frequency_score = self._frequency_calculator.calculate(
            investigation=investigation,
            parameters=params.get("frequency"),
        )
        sensitivity_score = self._sensitivity_calculator.calculate(
            investigation=investigation,
            policy=policy,
            parameters=params.get("sensitivity"),
        )
        history_score = self._history_calculator.calculate(
            investigation=investigation,
            policy=policy,
            parameters=params.get("history"),
        )

        components = RiskComponents(
            behavior=behavior_score,
            frequency=frequency_score,
            sensitivity=sensitivity_score,
            history=history_score,
        )

        # 2. Compute authoritative weighted score
        kernel_result = self.calculate_from_components(
            components=components,
            policy=policy,
        )

        # 3. Assemble and return authoritative domain entity
        return RiskAssessment.create(
            detection_event_id=detection.event_id,
            investigation_id=investigation.investigation_id,
            correlation_id=detection.correlation_id,
            source_ip=detection.source_ip,
            components=components,
            applied_policy=kernel_result.applied_policy,
        )

    def calculate_from_components(
        self,
        components: RiskComponents,
        policy: RiskPolicy,
    ) -> ScoringKernelResult:
        """
        Pure calculation kernel: executes Decimal weighted sum directly from sub-scores.
        Ensures identical inputs and policy versions always yield identical outputs.
        """
        weights: PolicyWeights = policy.weights

        # Extract weights as Decimal
        w_b = self._to_decimal(weights.behavior)
        w_f = self._to_decimal(weights.frequency)
        w_s = self._to_decimal(weights.sensitivity)
        w_h = self._to_decimal(weights.history)

        # Weighted product arithmetic
        term_behavior = components.behavior * w_b
        term_frequency = components.frequency * w_f
        term_sensitivity = components.sensitivity * w_s
        term_history = components.history * w_h

        raw_weighted_sum = term_behavior + term_frequency + term_sensitivity + term_history

        # Quantize to 1 decimal place with round-half-up
        quantized_score = raw_weighted_sum.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        # Bounds safety clamp: [0.0, 100.0]
        bounded_score = max(Decimal("0.0"), min(Decimal("100.0"), quantized_score))

        # Dynamic category resolution via versioned policy
        category = self._category_resolver.resolve(
            score=bounded_score,
            policy=policy,
        )

        applied_policy_snapshot = AppliedPolicySnapshot(
            policy_id=policy.policy_id,
            version=policy.version,
            weights={
                "behavior": w_b,
                "frequency": w_f,
                "sensitivity": w_s,
                "history": w_h,
            },
        )

        audit_trace = KernelExecutionAudit(
            kernel_execution_id=uuid4(),
            policy_id=policy.policy_id,
            policy_version=policy.version,
            raw_weighted_sum=raw_weighted_sum,
            quantized_score=bounded_score,
            resolved_category=category,
            weights_applied=applied_policy_snapshot.weights,
        )

        return ScoringKernelResult(
            risk_score=bounded_score,
            rating=category,
            components=components,
            applied_policy=applied_policy_snapshot,
            audit_trace=audit_trace,
        )

    @staticmethod
    def _to_decimal(val: Any) -> Decimal:
        """Ensures numeric values are converted to Decimal without floating-point drift."""
        if isinstance(val, Decimal):
            return val
        try:
            return Decimal(str(val))
        except (InvalidOperation, TypeError, ValueError) as err:
            raise ValueError(f"Value '{val}' cannot be converted to Decimal: {err}") from err