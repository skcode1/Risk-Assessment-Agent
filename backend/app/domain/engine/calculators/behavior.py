"""
Dynamic Behavior Sub-Score Calculator.
Normalizes detection confidence, sensor fidelity, and rule severity signals
into a bounded 0-100 sub-score for the deterministic risk scoring kernel.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Mapping, Optional

from app.domain.models.detection import DetectionEvent, DetectionMetrics
from app.domain.models.enums import DetectionSeverity
from app.domain.models.investigation import InvestigationResult


class BehaviorNormalizationStrategy(ABC):
    """Abstract strategy for dynamic behavior normalization workflows."""

    @abstractmethod
    def calculate(
        self,
        detection: DetectionEvent,
        investigation: Optional[InvestigationResult] = None,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> Decimal:
        """
        Calculate the normalized Behavior sub-score bounded to [0.0, 100.0].
        """
        pass


@dataclass(frozen=True, slots=True)
class ConfidenceScaleConfig:
    """
    Configuration parameters governing the confidence normalization function.
    Eliminates hardcoded scaling assumptions and supports dynamic unit conversions.
    """
    source_scale_max: Decimal = Decimal("1.0")
    target_scale_max: Decimal = Decimal("100.0")
    apply_fidelity_adjustment: bool = False
    fidelity_weight: Decimal = Decimal("0.15")
    apply_severity_damping: bool = False
    severity_weight: Decimal = Decimal("0.20")
    apply_severity_hint_blend: bool = True

    def __post_init__(self) -> None:
        if self.source_scale_max <= Decimal("0.0"):
            raise ValueError(f"source_scale_max must be positive, got {self.source_scale_max}")
        if self.target_scale_max <= Decimal("0.0"):
            raise ValueError(f"target_scale_max must be positive, got {self.target_scale_max}")
        if not (Decimal("0.0") <= self.fidelity_weight <= Decimal("1.0")):
            raise ValueError(f"fidelity_weight must be bounded [0.0, 1.0], got {self.fidelity_weight}")
        if not (Decimal("0.0") <= self.severity_weight <= Decimal("1.0")):
            raise ValueError(f"severity_weight must be bounded [0.0, 1.0], got {self.severity_weight}")


class DynamicBehaviorCalculator(BehaviorNormalizationStrategy):
    """
    Production-grade behavior sub-score calculator.
    Detects whether incoming telemetry confidence is natively on a [0.0, 1.0] scale
    or already on a [0.0, 100.0] scale, applies precision quantization, and integrates
    optional investigation severity hints dynamically.
    """

    DEFAULT_SEVERITY_FACTORS: Mapping[DetectionSeverity, Decimal] = {
        DetectionSeverity.INFORMATIONAL: Decimal("0.20"),
        DetectionSeverity.LOW: Decimal("0.40"),
        DetectionSeverity.MEDIUM: Decimal("0.65"),
        DetectionSeverity.HIGH: Decimal("0.85"),
        DetectionSeverity.CRITICAL: Decimal("1.00"),
    }

    def __init__(
        self,
        default_config: Optional[ConfidenceScaleConfig] = None,
        severity_factors: Optional[Mapping[DetectionSeverity, Decimal]] = None,
    ) -> None:
        self._config = default_config or ConfidenceScaleConfig()
        self._severity_factors = (
            dict(severity_factors) if severity_factors else dict(self.DEFAULT_SEVERITY_FACTORS)
        )

    def calculate(
        self,
        detection: DetectionEvent,
        investigation: Optional[InvestigationResult] = None,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> Decimal:
        """
        Executes dynamic normalization of detection confidence into a Decimal bounded [0.0, 100.0].

        If the raw confidence input is in fractional decimal notation (0.0 <= confidence <= 1.0),
        it dynamically scales via:
            Behavior = (Confidence / source_scale_max) * target_scale_max
        If the confidence is already normalized to a 0-100 baseline, it preserves the rating.
        """
        metrics: DetectionMetrics = detection.metrics
        raw_confidence = metrics.confidence

        if not isinstance(raw_confidence, Decimal):
            try:
                raw_confidence = Decimal(str(raw_confidence))
            except (InvalidOperation, TypeError, ValueError) as err:
                raise ValueError(f"Unable to parse detection confidence into Decimal: {err}") from err

        config = self._resolve_runtime_config(parameters)

        normalized_behavior = self._normalize_confidence(
            raw_confidence=raw_confidence,
            source_max=config.source_scale_max,
            target_max=config.target_scale_max,
        )

        if config.apply_fidelity_adjustment and metrics.fidelity is not None:
            normalized_behavior = self._adjust_for_fidelity(
                base_score=normalized_behavior,
                fidelity=metrics.fidelity,
                weight=config.fidelity_weight,
            )

        if config.apply_severity_damping:
            severity_factor = self._severity_factors.get(
                detection.severity, Decimal("0.50")
            )
            normalized_behavior = self._adjust_for_severity(
                base_score=normalized_behavior,
                severity_factor=severity_factor,
                weight=config.severity_weight,
            )

        if (
            investigation is not None
            and investigation.severity_hint is not None
            and config.apply_severity_hint_blend
        ):
            normalized_behavior = self._blend_investigation_severity_hint(
                base_score=normalized_behavior,
                severity_hint=investigation.severity_hint,
                blend_ratio=Decimal("0.10"),
            )

        bounded_score = self._clamp_and_quantize(normalized_behavior)
        return bounded_score

    def _normalize_confidence(
        self,
        raw_confidence: Decimal,
        source_max: Decimal,
        target_max: Decimal,
    ) -> Decimal:
        """
        Dynamically handles scale discrepancies.
        If the confidence is less than or equal to source_max (e.g. <= 1.0), it scales by (target_max / source_max).
        If the confidence already exceeds source_max, it assumes it is already aligned to the target scale.
        """
        if raw_confidence < Decimal("0.0"):
            return Decimal("0.0")

        if raw_confidence <= source_max and source_max < target_max:
            scaled = (raw_confidence / source_max) * target_max
            return scaled

        return raw_confidence

    def _adjust_for_fidelity(
        self,
        base_score: Decimal,
        fidelity: Decimal,
        weight: Decimal,
    ) -> Decimal:
        """Modulates base score using the detection signature historical precision/fidelity."""
        clamped_fidelity = max(Decimal("0.0"), min(Decimal("1.0"), fidelity))
        fidelity_delta = (clamped_fidelity - Decimal("1.0")) * Decimal("100.0")
        adjustment = fidelity_delta * weight
        return base_score + adjustment

    def _adjust_for_severity(
        self,
        base_score: Decimal,
        severity_factor: Decimal,
        weight: Decimal,
    ) -> Decimal:
        """Blends the detector's qualitative severity rating into the behavior confidence."""
        scaled_severity = severity_factor * Decimal("100.0")
        blended = (base_score * (Decimal("1.0") - weight)) + (scaled_severity * weight)
        return blended

    def _blend_investigation_severity_hint(
        self,
        base_score: Decimal,
        severity_hint: Decimal,
        blend_ratio: Decimal,
    ) -> Decimal:
        """Incorporates correlated severity hints generated by the investigation layer."""
        clamped_hint = max(Decimal("0.0"), min(Decimal("100.0"), severity_hint))
        blended = (base_score * (Decimal("1.0") - blend_ratio)) + (clamped_hint * blend_ratio)
        return blended

    def _clamp_and_quantize(self, value: Decimal) -> Decimal:
        """Strictly clamps the calculated component to [0.0, 100.0] with 1 decimal place."""
        clamped = max(Decimal("0.0"), min(Decimal("100.0"), value))
        return clamped.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    def _resolve_runtime_config(
        self, parameters: Optional[Mapping[str, Any]]
    ) -> ConfidenceScaleConfig:
        """Extracts runtime overrides from request context or policy governance metadata."""
        if not parameters:
            return self._config

        try:
            return ConfidenceScaleConfig(
                source_scale_max=Decimal(str(parameters.get("source_scale_max", self._config.source_scale_max))),
                target_scale_max=Decimal(str(parameters.get("target_scale_max", self._config.target_scale_max))),
                apply_fidelity_adjustment=bool(
                    parameters.get("apply_fidelity_adjustment", self._config.apply_fidelity_adjustment)
                ),
                fidelity_weight=Decimal(str(parameters.get("fidelity_weight", self._config.fidelity_weight))),
                apply_severity_damping=bool(
                    parameters.get("apply_severity_damping", self._config.apply_severity_damping)
                ),
                severity_weight=Decimal(str(parameters.get("severity_weight", self._config.severity_weight))),
                apply_severity_hint_blend=bool(
                    parameters.get(
                        "apply_severity_hint_blend",
                        self._config.apply_severity_hint_blend,
                    )
                ),
            )
        except (InvalidOperation, TypeError, ValueError):
            return self._config