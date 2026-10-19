"""
Domain entity models for Risk Policy and Governance Configuration.
Defines dynamic versioning, fully configurable component weights,
arbitrary continuous category thresholds, and runtime category resolution.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

from app.domain.models.enums import EndpointClass, RiskCategory


@dataclass(frozen=True, slots=True)
class PolicyWeights:
    """
    Dynamic weighting coefficients applied to the 4 normalized sub-scores.
    Enforces exact Decimal precision and dynamically validates that weights sum strictly to 1.00.
    """
    behavior: Decimal
    frequency: Decimal
    sensitivity: Decimal
    history: Decimal

    def __post_init__(self) -> None:
        """Quantize weights and verify mathematical invariants dynamically."""
        for field_name in ("behavior", "frequency", "sensitivity", "history"):
            raw_val = getattr(self, field_name)
            if not isinstance(raw_val, Decimal):
                try:
                    raw_val = Decimal(str(raw_val))
                except (InvalidOperation, TypeError, ValueError) as err:
                    raise ValueError(f"Weight '{field_name}' must be convertible to Decimal: {err}") from err
                object.__setattr__(self, field_name, raw_val)

            quantized_val = raw_val.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, field_name, quantized_val)

            if not (Decimal("0.00") <= quantized_val <= Decimal("1.00")):
                raise ValueError(
                    f"Weight coefficient '{field_name}' must be within [0.00, 1.00], got {quantized_val}"
                )

        total_weight = self.behavior + self.frequency + self.sensitivity + self.history
        if total_weight != Decimal("1.00"):
            raise ValueError(
                f"Policy weights must sum up to exactly 1.00. Current sum: {total_weight} "
                f"(behavior={self.behavior}, frequency={self.frequency}, "
                f"sensitivity={self.sensitivity}, history={self.history})"
            )

    def to_dict(self) -> dict[str, float]:
        return {
            "behavior": float(self.behavior),
            "frequency": float(self.frequency),
            "sensitivity": float(self.sensitivity),
            "history": float(self.history),
        }

    def to_decimal_dict(self) -> dict[str, Decimal]:
        return {
            "behavior": self.behavior,
            "frequency": self.frequency,
            "sensitivity": self.sensitivity,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PolicyWeights":
        """Dynamically parses and constructs PolicyWeights from an arbitrary dictionary."""
        required = {"behavior", "frequency", "sensitivity", "history"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required policy weights: {missing}")

        return cls(
            behavior=Decimal(str(data["behavior"])),
            frequency=Decimal(str(data["frequency"])),
            sensitivity=Decimal(str(data["sensitivity"])),
            history=Decimal(str(data["history"])),
        )


@dataclass(frozen=True, slots=True)
class CategoryThresholdRange:
    """
    Defines an inclusive lower boundary and an inclusive upper boundary for a risk category tier.
    """
    category: RiskCategory
    min_score: Decimal
    max_score: Decimal

    def __post_init__(self) -> None:
        for field_name in ("min_score", "max_score"):
            raw_val = getattr(self, field_name)
            if not isinstance(raw_val, Decimal):
                try:
                    raw_val = Decimal(str(raw_val))
                except (InvalidOperation, TypeError, ValueError) as err:
                    raise ValueError(f"Threshold '{field_name}' must be a valid Decimal: {err}") from err
                object.__setattr__(self, field_name, raw_val)

            q_val = raw_val.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, field_name, q_val)

            if not (Decimal("0.0") <= q_val <= Decimal("100.0")):
                raise ValueError(
                    f"Threshold boundary '{field_name}' must be bounded between [0.0, 100.0], got {q_val}"
                )

        if self.min_score > self.max_score:
            raise ValueError(
                f"Range invariant violation for {self.category.value}: "
                f"min_score ({self.min_score}) cannot exceed max_score ({self.max_score})"
            )

    def contains(self, score: Decimal) -> bool:
        """Evaluates whether a given score falls inclusively within this threshold range."""
        q_score = score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        return self.min_score <= q_score <= self.max_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "min_score": float(self.min_score),
            "max_score": float(self.max_score),
        }


@dataclass(frozen=True, slots=True)
class ThresholdConfig:
    """
    Dynamic container for all risk category boundaries.
    Validates range continuity, checks for gaps and overlaps, and enforces global coverage across [0.0, 100.0].
    """
    tiers: tuple[CategoryThresholdRange, ...]

    def __post_init__(self) -> None:
        if not self.tiers:
            raise ValueError("Threshold configuration must define at least one category tier.")

        # Sort tiers strictly by lower boundary
        sorted_tiers = sorted(self.tiers, key=lambda t: t.min_score)
        object.__setattr__(self, "tiers", tuple(sorted_tiers))

        # Enforce global bounds coverage
        if sorted_tiers[0].min_score != Decimal("0.0"):
            raise ValueError(
                f"Threshold boundaries must start at exactly 0.0, got {sorted_tiers[0].min_score}"
            )
        if sorted_tiers[-1].max_score != Decimal("100.0"):
            raise ValueError(
                f"Threshold boundaries must terminate at exactly 100.0, got {sorted_tiers[-1].max_score}"
            )

        # Ensure continuity without gaps or overlapping ranges
        for i in range(len(sorted_tiers) - 1):
            curr_tier = sorted_tiers[i]
            next_tier = sorted_tiers[i + 1]

            if curr_tier.max_score >= next_tier.min_score:
                raise ValueError(
                    f"Overlapping category thresholds detected between {curr_tier.category.value} "
                    f"([ {curr_tier.min_score}, {curr_tier.max_score} ]) and {next_tier.category.value} "
                    f"([ {next_tier.min_score}, {next_tier.max_score} ])"
                )

            # Continuous step tolerance check: maximum gap cannot exceed 0.1
            step_gap = next_tier.min_score - curr_tier.max_score
            if step_gap > Decimal("0.1"):
                raise ValueError(
                    f"Uncovered gap detected between {curr_tier.category.value} "
                    f"(ends at {curr_tier.max_score}) and {next_tier.category.value} "
                    f"(starts at {next_tier.min_score}). Step delta is {step_gap}"
                )

    def resolve(self, score: Decimal) -> RiskCategory:
        """
        Dynamically locates the applicable category tier for an arbitrary score.
        If rounding lands score directly on the gap border, binds safely to the nearest tier.
        """
        q_score = score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        for tier in self.tiers:
            if tier.contains(q_score):
                return tier.category

        # Fallback boundary resolution for edge precision deltas
        if q_score <= self.tiers[0].min_score:
            return self.tiers[0].category
        if q_score >= self.tiers[-1].max_score:
            return self.tiers[-1].category

        for i in range(len(self.tiers) - 1):
            if self.tiers[i].max_score < q_score < self.tiers[i + 1].min_score:
                return self.tiers[i].category

        raise ValueError(f"Score {q_score} could not be resolved against configured thresholds.")

    def to_dict(self) -> dict[str, Any]:
        return {tier.category.value.lower(): tier.to_dict() for tier in self.tiers}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ThresholdConfig":
        """
        Constructs ThresholdConfig dynamically from JSON / dict configurations.
        Accepts key-value pairs formatted either as:
        { "low": {"min": 0.0, "max": 39.9}, ... } or
        { "LOW": [0.0, 39.9], ... }
        """
        parsed_ranges: list[CategoryThresholdRange] = []

        for cat_key, bounds in data.items():
            category_enum = RiskCategory(cat_key.upper())
            if isinstance(bounds, (list, tuple)) and len(bounds) == 2:
                min_s, max_s = bounds
            elif isinstance(bounds, dict):
                min_s = bounds.get("min_score") or bounds.get("min") or bounds.get("min_val")
                max_s = bounds.get("max_score") or bounds.get("max") or bounds.get("max_val")
            else:
                raise ValueError(f"Unsupported format for threshold bounds definition: {bounds}")

            parsed_ranges.append(
                CategoryThresholdRange(
                    category=category_enum,
                    min_score=Decimal(str(min_s)),
                    max_score=Decimal(str(max_s)),
                )
            )

        return cls(tiers=tuple(parsed_ranges))


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """
    Authoritative domain model for versioned Risk Assessment policies.
    Maintains weights, thresholds, dynamic asset sensitivity overrides, and full lifecycle metadata.
    """
    name: str
    version: str
    weights: PolicyWeights
    thresholds: ThresholdConfig
    policy_id: UUID = field(default_factory=uuid4)
    description: str | None = None
    is_active: bool = True
    endpoint_class_weights: dict[EndpointClass, Decimal] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Policy name cannot be empty.")
        if not self.version or not self.version.strip():
            raise ValueError("Policy version cannot be empty.")

        # Ensure UTC normalization
        for ts_field in ("created_at", "updated_at"):
            ts_val: datetime = getattr(self, ts_field)
            if ts_val.tzinfo is None:
                object.__setattr__(self, ts_field, ts_val.replace(tzinfo=UTC))
            else:
                object.__setattr__(self, ts_field, ts_val.astimezone(UTC))

        # Quantize and validate custom endpoint class weights if provided
        if self.endpoint_class_weights:
            validated_weights: dict[EndpointClass, Decimal] = {}
            for ep_class, raw_wt in self.endpoint_class_weights.items():
                if not isinstance(raw_wt, Decimal):
                    raw_wt = Decimal(str(raw_wt))
                q_wt = raw_wt.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
                if not (Decimal("0.0") <= q_wt <= Decimal("100.0")):
                    raise ValueError(
                        f"Custom weight for {ep_class.value} must be within [0.0, 100.0], got {q_wt}"
                    )
                validated_weights[ep_class] = q_wt
            object.__setattr__(self, "endpoint_class_weights", validated_weights)

    def resolve_category(self, score: Decimal) -> RiskCategory:
        """Delegates category classification to the validated dynamic threshold hierarchy."""
        return self.thresholds.resolve(score)

    def get_endpoint_weight(self, endpoint_class: EndpointClass) -> Decimal:
        """
        Dynamically returns the policy-specific sensitivity weight for an endpoint class,
        falling back to the default domain base weight if an explicit override is not configured.
        """
        if endpoint_class in self.endpoint_class_weights:
            return self.endpoint_class_weights[endpoint_class]
        return Decimal(str(endpoint_class.default_base_weight)).quantize(
            Decimal("0.1"), rounding=ROUND_HALF_UP
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes the complete risk policy state to a clean JSON-compatible dictionary."""
        return {
            "policy_id": str(self.policy_id),
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "is_active": self.is_active,
            "weights": self.weights.to_dict(),
            "thresholds": self.thresholds.to_dict(),
            "endpoint_class_weights": {
                ep.value: float(wt) for ep, wt in self.endpoint_class_weights.items()
            },
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def create_spec_default(cls, version: str = "risk-policy-2026-01") -> "RiskPolicy":
        """
        Factory helper initializing the authoritative spec baseline without hardcoded magic numbers in callers:
        Weights: B=0.40, F=0.30, S=0.20, H=0.10
        Thresholds:
          - LOW:      0.0  to 39.9
          - MEDIUM:  40.0  to 64.9
          - HIGH:    65.0  to 84.9
          - CRITICAL: 85.0 to 100.0
        Calculator Configs (moved to metadata for governance):
          - frequency_config: saturation_count=50, curvature_constant=1.0
          - history_config: incident_saturation_ceiling=5, scaling_curve="linear"
          - sensitivity_config: apply_lateral_spread_boost=True, lateral_boost_per_endpoint=2.5, lateral_boost_cap=15.0, compromise_multiplier=1.10
          - behavior_config: apply_severity_hint_blend=False
        """
        weights = PolicyWeights(
            behavior=Decimal("0.40"),
            frequency=Decimal("0.30"),
            sensitivity=Decimal("0.20"),
            history=Decimal("0.10"),
        )
        thresholds = ThresholdConfig(
            tiers=(
                CategoryThresholdRange(
                    category=RiskCategory.LOW,
                    min_score=Decimal("0.0"),
                    max_score=Decimal("39.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.MEDIUM,
                    min_score=Decimal("40.0"),
                    max_score=Decimal("64.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.HIGH,
                    min_score=Decimal("65.0"),
                    max_score=Decimal("84.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.CRITICAL,
                    min_score=Decimal("85.0"),
                    max_score=Decimal("100.0"),
                ),
            )
        )
        return cls(
            name="Authoritative Spec Risk Policy",
            version=version,
            description="Default versioned policy baseline matching 6.3 spec weights and category boundaries",
            weights=weights,
            thresholds=thresholds,
            endpoint_class_weights={
                # Canonical 6.3 spec sensitivity for the reference database
                # asset: S = 80.0 in the authoritative scoring example.
                EndpointClass.DATABASE_SERVER: Decimal("80.0"),
            },
            metadata={
                "frequency_config": {
                    "saturation_count": 50,
                    "curvature_constant": 1.0,
                    "min_score": "0.0",
                    "max_score": "100.0",
                },
                "history_config": {
                    "incident_saturation_ceiling": 5,
                    "scaling_curve": "linear",
                    "min_score": "0.0",
                    "max_score": "100.0",
                    "exponential_rate": 0.5,
                },
                "sensitivity_config": {
                    "apply_lateral_spread_boost": True,
                    "lateral_boost_per_endpoint": "2.5",
                    "lateral_boost_cap": "15.0",
                    "compromise_multiplier": "1.10",
                    "min_score": "0.0",
                    "max_score": "100.0",
                },
                "behavior_config": {
                    "apply_severity_hint_blend": False,
                },
            },
            is_active=True,
        )