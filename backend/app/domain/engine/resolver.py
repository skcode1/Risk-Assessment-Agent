"""
Dynamic Risk Category Resolver.
Maps an arbitrary raw or quantized numerical score S in [0.0, 100.0] into a categorical rating:
LOW, MEDIUM, HIGH, or CRITICAL based on versioned, configurable policy thresholds.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from app.domain.models.enums import RiskCategory
from app.domain.models.policy import RiskPolicy, ThresholdConfig


class BaseRiskCategoryResolver(ABC):
    """Abstract interface for categorical risk resolution strategies."""

    @abstractmethod
    def resolve(
        self,
        score: Decimal,
        policy: RiskPolicy | None = None,
        threshold_config: ThresholdConfig | None = None,
    ) -> RiskCategory:
        """
        Maps a score strictly bounded within [0.0, 100.0] to a RiskCategory enum.
        """


@dataclass(frozen=True, slots=True)
class ThresholdTier:
    """
    Represents an inclusive numerical boundary tier for category classification.
    """

    category: RiskCategory
    min_score: Decimal
    max_score: Decimal

    def __post_init__(self) -> None:
        for attr in ("min_score", "max_score"):
            raw_val = getattr(self, attr)
            if not isinstance(raw_val, Decimal):
                try:
                    raw_val = Decimal(str(raw_val))
                except (InvalidOperation, TypeError, ValueError) as err:
                    raise ValueError(
                        f"Boundary '{attr}' must be convertible to Decimal: {err}"
                    ) from err
                object.__setattr__(self, attr, raw_val)

            q_val = raw_val.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, attr, q_val)

        if self.min_score > self.max_score:
            raise ValueError(
                f"Range violation for tier {self.category.value}: "
                f"min_score ({self.min_score}) cannot exceed max_score ({self.max_score})."
            )

    def contains(self, score: Decimal) -> bool:
        """Evaluates whether score falls within [min_score, max_score] inclusive."""
        return self.min_score <= score <= self.max_score


@dataclass(frozen=True, slots=True)
class DynamicThresholdProfile:
    """
    Container for an ordered collection of category threshold tiers.
    Validates range order, step gaps, and domain boundaries.
    """

    tiers: tuple[ThresholdTier, ...]

    def __post_init__(self) -> None:
        if not self.tiers:
            raise ValueError(
                "Threshold profile must define at least one category tier."
            )

        sorted_tiers = sorted(self.tiers, key=lambda t: t.min_score)
        object.__setattr__(self, "tiers", tuple(sorted_tiers))

        if sorted_tiers[0].min_score != Decimal("0.0"):
            raise ValueError(
                f"Threshold boundaries must start at exactly 0.0, got {sorted_tiers[0].min_score}."
            )
        if sorted_tiers[-1].max_score != Decimal("100.0"):
            raise ValueError(
                f"Threshold boundaries must end at exactly 100.0, got {sorted_tiers[-1].max_score}."
            )

        for i in range(len(sorted_tiers) - 1):
            curr_tier = sorted_tiers[i]
            next_tier = sorted_tiers[i + 1]

            if curr_tier.max_score >= next_tier.min_score:
                raise ValueError(
                    f"Overlapping boundaries between {curr_tier.category.value} "
                    f"([{curr_tier.min_score}, {curr_tier.max_score}]) and {next_tier.category.value} "
                    f"([{next_tier.min_score}, {next_tier.max_score}])."
                )

    def resolve(self, score: Decimal) -> RiskCategory:
        """
        Resolves score against sorted tiers with boundary delta tolerance.
        """
        for tier in self.tiers:
            if tier.contains(score):
                return tier.category

        # Safety clamps for precision edge cases
        if score <= self.tiers[0].min_score:
            return self.tiers[0].category
        if score >= self.tiers[-1].max_score:
            return self.tiers[-1].category

        # Inter-tier step gap resolution (e.g., 39.1 to 39.9 maps to lower tier boundary)
        for i in range(len(self.tiers) - 1):
            if self.tiers[i].max_score < score < self.tiers[i + 1].min_score:
                return self.tiers[i].category

        return self.tiers[-1].category

    @classmethod
    def from_mapping(
        cls, mapping: Mapping[str, Sequence[Any]]
    ) -> "DynamicThresholdProfile":
        """
        Dynamically builds a threshold profile from a dictionary mapping category names
        to [min, max] pairs. Example:
        {
            "LOW": [0, 39],
            "MEDIUM": [40, 64],
            "HIGH": [65, 84],
            "CRITICAL": [85, 100]
        }
        """
        built_tiers = []
        for cat_name, bounds in mapping.items():
            if len(bounds) != 2:
                raise ValueError(
                    f"Tier definition for {cat_name} must contain exactly [min, max], got {bounds}."
                )
            built_tiers.append(
                ThresholdTier(
                    category=RiskCategory(cat_name.upper()),
                    min_score=Decimal(str(bounds[0])),
                    max_score=Decimal(str(bounds[1])),
                )
            )
        return cls(tiers=tuple(built_tiers))


class DynamicRiskCategoryResolver(BaseRiskCategoryResolver):
    """
    Production-grade dynamic risk category resolver.
    Dynamically prioritizes:
      1. Explicit runtime threshold configuration parameter
      2. Active RiskPolicy domain configuration
      3. Injected default profile matching documented specification thresholds
    """

    def __init__(self, default_profile: DynamicThresholdProfile | None = None) -> None:
        self._default_profile = (
            default_profile or self._build_default_specification_profile()
        )

    def resolve(
        self,
        score: Decimal,
        policy: RiskPolicy | None = None,
        threshold_config: ThresholdConfig | None = None,
    ) -> RiskCategory:
        """
        Resolves score S in [0.0, 100.0] to a RiskCategory.
        Enforces decimal quantization and dynamic policy delegation.
        """
        quantized_score = self._normalize_score(score)

        # 1. Direct threshold config override
        if threshold_config is not None:
            return threshold_config.resolve(quantized_score)

        # 2. RiskPolicy dynamic thresholds
        if policy is not None and hasattr(policy, "thresholds"):
            return policy.resolve_category(quantized_score)

        # 3. Dynamic default profile
        return self._default_profile.resolve(quantized_score)

    def _normalize_score(self, score: Any) -> Decimal:
        """Converts score to Decimal, validates domain bounds [0.0, 100.0], and quantizes."""
        if not isinstance(score, Decimal):
            try:
                score = Decimal(str(score))
            except (InvalidOperation, TypeError, ValueError) as err:
                raise ValueError(
                    f"Invalid score value '{score}', cannot convert to Decimal: {err}"
                ) from err

        clamped = max(Decimal("0.0"), min(Decimal("100.0"), score))
        return clamped.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    @staticmethod
    def _build_default_specification_profile() -> DynamicThresholdProfile:
        """
        Constructs the baseline specification profile:
          - LOW:      0.0  to 39.9
          - MEDIUM:  40.0  to 64.9
          - HIGH:    65.0  to 84.9
          - CRITICAL: 85.0 to 100.0
        """
        return DynamicThresholdProfile(
            tiers=(
                ThresholdTier(
                    category=RiskCategory.LOW,
                    min_score=Decimal("0.0"),
                    max_score=Decimal("39.9"),
                ),
                ThresholdTier(
                    category=RiskCategory.MEDIUM,
                    min_score=Decimal("40.0"),
                    max_score=Decimal("64.9"),
                ),
                ThresholdTier(
                    category=RiskCategory.HIGH,
                    min_score=Decimal("65.0"),
                    max_score=Decimal("84.9"),
                ),
                ThresholdTier(
                    category=RiskCategory.CRITICAL,
                    min_score=Decimal("85.0"),
                    max_score=Decimal("100.0"),
                ),
            )
        )
