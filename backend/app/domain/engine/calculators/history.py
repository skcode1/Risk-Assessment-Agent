"""
Dynamic History Sub-Score Calculator.
Normalizes historical security incident counts for a source entity into a bounded 0-100 sub-score
via deterministic scaling functions (linear saturation, exponential risk ramp, or logarithmic curves).
"""

import math
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from app.domain.models.investigation import InvestigationResult
from app.domain.models.policy import RiskPolicy


class HistoryMappingStrategy(ABC):
    """Abstract strategy for dynamic historical incident normalization workflows."""

    @abstractmethod
    def calculate(
        self,
        investigation: InvestigationResult,
        policy: RiskPolicy | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> Decimal:
        """
        Calculate the normalized History sub-score bounded to [0.0, 100.0].
        """


@dataclass(frozen=True, slots=True)
class HistoryScaleConfig:
    """
    Configuration parameters governing the historical incident count normalization.
    Eliminates hardcoded multipliers and supports dynamic curves and scaling ceilings.
    """
    incident_saturation_ceiling: int = 5
    scaling_curve: str = "linear"  # "linear", "logarithmic", "exponential"
    min_score: Decimal = Decimal("0.0")
    max_score: Decimal = Decimal("100.0")
    exponential_rate: float = 0.5

    def __post_init__(self) -> None:
        if self.incident_saturation_ceiling <= 0:
            raise ValueError(
                f"incident_saturation_ceiling must be positive, got {self.incident_saturation_ceiling}"
            )
        if self.min_score < Decimal("0.0") or self.max_score > Decimal("100.0"):
            raise ValueError("Scores must be bounded within [0.0, 100.0].")
        if self.min_score >= self.max_score:
            raise ValueError("min_score must be strictly less than max_score.")
        if self.exponential_rate <= 0.0:
            raise ValueError(f"exponential_rate must be positive, got {self.exponential_rate}")


class DynamicHistoryCalculator(HistoryMappingStrategy):
    """
    Production-grade historical incident sub-score calculator.
    Normalizes historical incident counts observed for the source entity (capped at 100).
    Supports dynamic parameter configuration via runtime overrides or policy metadata.
    """

    def __init__(
        self,
        default_config: HistoryScaleConfig | None = None,
    ) -> None:
        self._config = default_config or HistoryScaleConfig()

    def calculate(
        self,
        investigation: InvestigationResult,
        policy: RiskPolicy | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> Decimal:
        """
        Calculates normalized History sub-score:
          1. Extracts historical incident count from investigation telemetry.
          2. Resolves configuration parameters from runtime overrides or policy metadata.
          3. Applies the selected scaling curve (linear, logarithmic, or exponential).
          4. Clamps and quantizes strictly to [0.0, 100.0] with 1-decimal-place precision.
        """
        count = investigation.historical_incident_count
        if count <= 0:
            return self._config.min_score

        config = self._resolve_config(policy=policy, parameters=parameters)

        curve = config.scaling_curve.lower()
        if curve == "logarithmic":
            raw_score = self._calculate_logarithmic(count, config)
        elif curve == "exponential":
            raw_score = self._calculate_exponential(count, config)
        else:
            raw_score = self._calculate_linear(count, config)

        return self._clamp_and_quantize(raw_score, config.min_score, config.max_score)

    def _calculate_linear(self, count: int, config: HistoryScaleConfig) -> Decimal:
        """
        Linear saturation scaling:
        Directly scales up to incident_saturation_ceiling where it hits max_score (100.0).
        """
        if count >= config.incident_saturation_ceiling:
            return config.max_score

        count_dec = Decimal(str(count))
        ceil_dec = Decimal(str(config.incident_saturation_ceiling))
        span_dec = config.max_score - config.min_score

        return config.min_score + ((count_dec / ceil_dec) * span_dec)

    def _calculate_logarithmic(self, count: int, config: HistoryScaleConfig) -> Decimal:
        """
        Logarithmic scaling:
        Produces rapid ramp-up for early incidents with asymptotic approach to max_score.
        """
        k = 1.0
        x = float(count)
        s = float(config.incident_saturation_ceiling)
        max_s = float(config.max_score)
        min_s = float(config.min_score)

        denom = math.log(1.0 + (k * s))
        if denom <= 0.0:
            return config.min_score

        numer = math.log(1.0 + (k * x))
        raw_val = (numer / denom) * (max_s - min_s) + min_s

        try:
            return Decimal(str(raw_val))
        except (InvalidOperation, TypeError, ValueError):
            return Decimal(f"{raw_val:.4f}")

    def _calculate_exponential(self, count: int, config: HistoryScaleConfig) -> Decimal:
        """
        Exponential scaling:
        Penalizes repeat offenders exponentially until saturation.
        """
        r = config.exponential_rate
        x = float(min(count, config.incident_saturation_ceiling))
        s = float(config.incident_saturation_ceiling)
        max_s = float(config.max_score)
        min_s = float(config.min_score)

        denom = math.exp(r * s) - 1.0
        if denom <= 0.0:
            return config.min_score

        numer = math.exp(r * x) - 1.0
        raw_val = (numer / denom) * (max_s - min_s) + min_s

        try:
            return Decimal(str(raw_val))
        except (InvalidOperation, TypeError, ValueError):
            return Decimal(f"{raw_val:.4f}")

    def _clamp_and_quantize(
        self,
        score: Decimal,
        min_bound: Decimal,
        max_bound: Decimal,
    ) -> Decimal:
        """Clamps the score strictly within bounds and enforces 1-decimal-place precision."""
        clamped = max(min_bound, min(max_bound, score))
        return clamped.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    def _resolve_config(
        self,
        policy: RiskPolicy | None,
        parameters: Mapping[str, Any] | None,
    ) -> HistoryScaleConfig:
        """Dynamically extracts configuration parameters from request context or policy metadata."""
        merged_params: dict[str, Any] = {}

        if policy and hasattr(policy, "metadata") and isinstance(policy.metadata, dict):
            history_policy_meta = policy.metadata.get("history_config", {})
            if isinstance(history_policy_meta, dict):
                merged_params.update(history_policy_meta)

        if parameters:
            merged_params.update(parameters)

        if not merged_params:
            return self._config

        try:
            return HistoryScaleConfig(
                incident_saturation_ceiling=int(
                    merged_params.get(
                        "incident_saturation_ceiling",
                        self._config.incident_saturation_ceiling,
                    )
                ),
                scaling_curve=str(
                    merged_params.get("scaling_curve", self._config.scaling_curve)
                ),
                min_score=Decimal(str(merged_params.get("min_score", self._config.min_score))),
                max_score=Decimal(str(merged_params.get("max_score", self._config.max_score))),
                exponential_rate=float(
                    merged_params.get("exponential_rate", self._config.exponential_rate)
                ),
            )
        except (InvalidOperation, TypeError, ValueError):
            return self._config