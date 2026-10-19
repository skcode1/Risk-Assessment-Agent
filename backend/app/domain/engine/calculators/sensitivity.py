"""
Dynamic Sensitivity Sub-Score Calculator.
Maps endpoint classes and asset criticality classifications to a bounded 0-100 scale,
factoring in individual touched endpoints, lateral spread, and policy-configured asset weights.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from app.domain.models.enums import EndpointClass
from app.domain.models.investigation import InvestigationResult, TouchedEndpoint
from app.domain.models.policy import RiskPolicy


class SensitivityMappingStrategy(ABC):
    """Abstract strategy for dynamic asset sensitivity normalization."""

    @abstractmethod
    def calculate(
        self,
        investigation: InvestigationResult,
        policy: RiskPolicy | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> Decimal:
        """
        Calculates the normalized Sensitivity sub-score bounded to [0.0, 100.0].
        """


@dataclass(frozen=True, slots=True)
class SensitivityAggregationConfig:
    """
    Configuration parameters governing asset sensitivity aggregation and multi-node amplification.
    Eliminates hardcoded multiplier assumptions and supports dynamic policy injection.
    """
    apply_lateral_spread_boost: bool = True
    lateral_boost_per_endpoint: Decimal = Decimal("2.5")
    lateral_boost_cap: Decimal = Decimal("15.0")
    compromise_multiplier: Decimal = Decimal("1.10")
    min_score: Decimal = Decimal("0.0")
    max_score: Decimal = Decimal("100.0")

    def __post_init__(self) -> None:
        if self.min_score < Decimal("0.0") or self.max_score > Decimal("100.0"):
            raise ValueError("Scores must be bounded within [0.0, 100.0].")
        if self.min_score >= self.max_score:
            raise ValueError("min_score must be strictly less than max_score.")
        if self.lateral_boost_per_endpoint < Decimal("0.0"):
            raise ValueError("lateral_boost_per_endpoint cannot be negative.")
        if self.compromise_multiplier < Decimal("1.0"):
            raise ValueError("compromise_multiplier must be >= 1.0.")


class DynamicSensitivityCalculator(SensitivityMappingStrategy):
    """
    Production-grade sensitivity component calculator.
    Resolves static sensitivity weightings dynamically per endpoint class from the active RiskPolicy.
    Evaluates both dominant endpoint classifications and itemized touched endpoints lists.
    """

    def __init__(
        self,
        default_config: SensitivityAggregationConfig | None = None,
    ) -> None:
        self._config = default_config or SensitivityAggregationConfig()

    def calculate(
        self,
        investigation: InvestigationResult,
        policy: RiskPolicy | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> Decimal:
        """
        Calculates normalized Sensitivity sub-score:
          1. Resolves asset weight from the dominant endpoint or aggregates across touched endpoints.
          2. Applies dynamic policy overrides for endpoint classes (e.g., Domain Controller, Workstation).
          3. Applies lateral spread boost based on endpoints_touched count.
          4. Clamps and quantizes strictly to [0.0, 100.0] with 1-decimal-place precision.
        """
        config = self._resolve_config(parameters)

        # Step 1: Compute base score from endpoints
        if investigation.touched_endpoints:
            base_score = self._calculate_from_endpoint_collection(
                endpoints=investigation.touched_endpoints,
                policy=policy,
                config=config,
            )
        else:
            base_score = self._calculate_from_dominant_class(
                dominant_class=investigation.endpoint_class,
                policy=policy,
            )

        # Step 2: Apply lateral movement / multi-endpoint boost
        adjusted_score = base_score
        if config.apply_lateral_spread_boost and investigation.endpoints_touched > 1:
            adjusted_score = self._apply_lateral_spread(
                current_score=base_score,
                endpoints_touched=investigation.endpoints_touched,
                config=config,
            )

        return self._clamp_and_quantize(adjusted_score, config.min_score, config.max_score)

    def _calculate_from_dominant_class(
        self,
        dominant_class: EndpointClass,
        policy: RiskPolicy | None,
    ) -> Decimal:
        """
        Extracts sensitivity weight for the single dominant endpoint class.
        Delegates to policy configuration if provided; otherwise falls back to domain default.
        """
        if policy is not None:
            return policy.get_endpoint_weight(dominant_class)

        return Decimal(str(dominant_class.default_base_weight)).quantize(
            Decimal("0.1"), rounding=ROUND_HALF_UP
        )

    def _calculate_from_endpoint_collection(
        self,
        endpoints: list[TouchedEndpoint],
        policy: RiskPolicy | None,
        config: SensitivityAggregationConfig,
    ) -> Decimal:
        """
        Evaluates a collection of touched endpoints.
        Takes the maximum sensitivity observed, with priority given to confirmed compromised nodes.
        """
        highest_weight = Decimal("0.0")

        for endpoint in endpoints:
            if policy is not None:
                ep_weight = policy.get_endpoint_weight(endpoint.endpoint_class)
            else:
                ep_weight = Decimal(str(endpoint.endpoint_class.default_base_weight))

            if endpoint.is_compromised:
                ep_weight = ep_weight * config.compromise_multiplier

            highest_weight = max(highest_weight, ep_weight)

        return highest_weight

    def _apply_lateral_spread(
        self,
        current_score: Decimal,
        endpoints_touched: int,
        config: SensitivityAggregationConfig,
    ) -> Decimal:
        """
        Amplifies sensitivity score when an incident cascades across multiple network nodes.
        """
        extra_nodes = Decimal(str(max(0, endpoints_touched - 1)))
        raw_boost = extra_nodes * config.lateral_boost_per_endpoint
        capped_boost = min(raw_boost, config.lateral_boost_cap)
        return current_score + capped_boost

    def _clamp_and_quantize(
        self,
        score: Decimal,
        min_bound: Decimal,
        max_bound: Decimal,
    ) -> Decimal:
        """Clamps the result within configured score bounds and enforces 1-decimal-place precision."""
        clamped = max(min_bound, min(max_bound, score))
        return clamped.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    def _resolve_config(
        self,
        parameters: Mapping[str, Any] | None,
    ) -> SensitivityAggregationConfig:
        """Dynamically parses and merges runtime parameters over defaults."""
        if not parameters:
            return self._config

        try:
            return SensitivityAggregationConfig(
                apply_lateral_spread_boost=bool(
                    parameters.get(
                        "apply_lateral_spread_boost", self._config.apply_lateral_spread_boost
                    )
                ),
                lateral_boost_per_endpoint=Decimal(
                    str(
                        parameters.get(
                            "lateral_boost_per_endpoint", self._config.lateral_boost_per_endpoint
                        )
                    )
                ),
                lateral_boost_cap=Decimal(
                    str(parameters.get("lateral_boost_cap", self._config.lateral_boost_cap))
                ),
                compromise_multiplier=Decimal(
                    str(
                        parameters.get(
                            "compromise_multiplier", self._config.compromise_multiplier
                        )
                    )
                ),
                min_score=Decimal(str(parameters.get("min_score", self._config.min_score))),
                max_score=Decimal(str(parameters.get("max_score", self._config.max_score))),
            )
        except (InvalidOperation, TypeError, ValueError):
            return self._config