"""
Unit verification suite for the Dynamic Risk Category Resolver.
Tests boundary continuity, cutoff edge cases, custom policy overrides,
precision quantization, and strict invariance mapping across
LOW, MEDIUM, HIGH, and CRITICAL tiers.
"""

from decimal import Decimal

import pytest

from app.domain.engine.resolver import (
    DynamicRiskCategoryResolver,
    DynamicThresholdProfile,
    ThresholdTier,
)
from app.domain.models.enums import RiskCategory
from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)


@pytest.fixture
def category_resolver() -> DynamicRiskCategoryResolver:
    """Fixture supplying an instance of the dynamic category resolver."""
    return DynamicRiskCategoryResolver()


@pytest.fixture
def spec_default_policy() -> RiskPolicy:
    """Fixture supplying the authoritative default policy baseline."""
    return RiskPolicy.create_spec_default(version="risk-policy-2026-01")


class TestSpecificationDefaultThresholds:
    """
    Validates category resolution against canonical 6.3 spec thresholds:
      - 0.0  to 39.9 -> LOW
      - 40.0 to 64.9 -> MEDIUM
      - 65.0 to 84.9 -> HIGH
      - 85.0 to 100.0 -> CRITICAL
    """

    @pytest.mark.parametrize(
        ("score", "expected_category"),
        [
            # LOW boundaries and interior
            (Decimal("0.0"), RiskCategory.LOW),
            (Decimal("20.5"), RiskCategory.LOW),
            (Decimal("39.0"), RiskCategory.LOW),
            (Decimal("39.9"), RiskCategory.LOW),
            # Boundary shift: 39.95 rounds half up to 40.0 -> MEDIUM
            (Decimal("39.95"), RiskCategory.MEDIUM),
            # MEDIUM boundaries and interior
            (Decimal("40.0"), RiskCategory.MEDIUM),
            (Decimal("52.3"), RiskCategory.MEDIUM),
            (Decimal("64.0"), RiskCategory.MEDIUM),
            (Decimal("64.9"), RiskCategory.MEDIUM),
            # Boundary shift: 64.95 rounds half up to 65.0 -> HIGH
            (Decimal("64.95"), RiskCategory.HIGH),
            # HIGH boundaries and interior
            (Decimal("65.0"), RiskCategory.HIGH),
            (Decimal("75.0"), RiskCategory.HIGH),
            (Decimal("83.5"), RiskCategory.HIGH),  # Canonical test invariant
            (Decimal("84.0"), RiskCategory.HIGH),
            (Decimal("84.9"), RiskCategory.HIGH),
            # Boundary shift: 84.95 rounds half up to 85.0 -> CRITICAL
            (Decimal("84.95"), RiskCategory.CRITICAL),
            # CRITICAL boundaries and interior
            (Decimal("85.0"), RiskCategory.CRITICAL),
            (Decimal("92.1"), RiskCategory.CRITICAL),
            (Decimal("99.9"), RiskCategory.CRITICAL),
            (Decimal("100.0"), RiskCategory.CRITICAL),
        ],
    )
    def test_canonical_score_threshold_resolution(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
        score: Decimal,
        expected_category: RiskCategory,
    ) -> None:
        """Verifies categorical resolution across interior points and strict boundary limits."""
        resolved = category_resolver.resolve(score=score, policy=spec_default_policy)
        assert resolved == expected_category

    def test_canonical_test_score_invariant(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
    ) -> None:
        """
        Directly checks canonical test fixture score:
        83.5 strictly resolves to HIGH.
        """
        canonical_score = Decimal("83.5")
        category = category_resolver.resolve(
            score=canonical_score, policy=spec_default_policy
        )
        assert category == RiskCategory.HIGH


class TestBoundarySafetyClampingAndQuantization:
    """Verifies edge clamp protections and IEEE-754 conversion resistance."""

    def test_out_of_bounds_clamping(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
    ) -> None:
        """Ensures scores below 0.0 or above 100.0 clamp cleanly to LOW and CRITICAL."""
        assert (
            category_resolver.resolve(Decimal("-10.0"), policy=spec_default_policy)
            == RiskCategory.LOW
        )
        assert (
            category_resolver.resolve(Decimal("150.0"), policy=spec_default_policy)
            == RiskCategory.CRITICAL
        )

    @pytest.mark.parametrize(
        ("input_value", "expected_category"),
        [
            ("83.5", RiskCategory.HIGH),
            (83.5, RiskCategory.HIGH),
            ("40.0", RiskCategory.MEDIUM),
            (85, RiskCategory.CRITICAL),
        ],
    )
    def test_heterogeneous_type_conversion(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
        input_value: object,
        expected_category: RiskCategory,
    ) -> None:
        """Verifies that strings, floats, and ints safely convert to Decimal without floating-point artifacts."""
        resolved = category_resolver.resolve(
            Decimal(str(input_value)), policy=spec_default_policy
        )
        assert resolved == expected_category

    def test_invalid_score_rejection(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
    ) -> None:
        """Verifies that non-numeric objects raise ValueError."""
        with pytest.raises(ValueError, match="cannot convert to Decimal"):
            category_resolver.resolve("not-a-number", policy=spec_default_policy)  # type: ignore[arg-type]


class TestCustomAndDynamicPolicyThresholds:
    """Verifies runtime threshold overrides, non-standard cutoffs, and dynamic profiles."""

    def test_custom_threshold_config_override(
        self,
        category_resolver: DynamicRiskCategoryResolver,
    ) -> None:
        """
        Tests resolution against an aggressive security policy configuration:
          - LOW:      0.0 to 19.9
          - MEDIUM:  20.0 to 49.9
          - HIGH:    50.0 to 74.9
          - CRITICAL: 75.0 to 100.0
        """
        aggressive_thresholds = ThresholdConfig(
            tiers=(
                CategoryThresholdRange(
                    category=RiskCategory.LOW,
                    min_score=Decimal("0.0"),
                    max_score=Decimal("19.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.MEDIUM,
                    min_score=Decimal("20.0"),
                    max_score=Decimal("49.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.HIGH,
                    min_score=Decimal("50.0"),
                    max_score=Decimal("74.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.CRITICAL,
                    min_score=Decimal("75.0"),
                    max_score=Decimal("100.0"),
                ),
            )
        )

        custom_policy = RiskPolicy(
            name="Aggressive SOC Policy",
            version="custom-v2",
            weights=PolicyWeights(
                behavior=Decimal("0.40"),
                frequency=Decimal("0.30"),
                sensitivity=Decimal("0.20"),
                history=Decimal("0.10"),
            ),
            thresholds=aggressive_thresholds,
        )

        # Under the default policy 83.5 is HIGH; under the aggressive policy (>= 75.0) it is CRITICAL
        test_score = Decimal("83.5")
        resolved = category_resolver.resolve(score=test_score, policy=custom_policy)
        assert resolved == RiskCategory.CRITICAL

        # 60.0 is MEDIUM in default, but HIGH in aggressive policy
        assert (
            category_resolver.resolve(Decimal("60.0"), policy=custom_policy)
            == RiskCategory.HIGH
        )

    def test_direct_threshold_config_argument_priority(
        self,
        category_resolver: DynamicRiskCategoryResolver,
        spec_default_policy: RiskPolicy,
    ) -> None:
        """Verifies that an explicitly passed threshold_config takes precedence over the policy object."""
        custom_direct_thresholds = ThresholdConfig(
            tiers=(
                CategoryThresholdRange(
                    category=RiskCategory.LOW,
                    min_score=Decimal("0.0"),
                    max_score=Decimal("89.9"),
                ),
                CategoryThresholdRange(
                    category=RiskCategory.CRITICAL,
                    min_score=Decimal("90.0"),
                    max_score=Decimal("100.0"),
                ),
            )
        )

        # Pass both: the explicit threshold_config should override the policy
        result = category_resolver.resolve(
            score=Decimal("83.5"),
            policy=spec_default_policy,
            threshold_config=custom_direct_thresholds,
        )
        assert result == RiskCategory.LOW

    def test_dynamic_profile_from_mapping_construction(self) -> None:
        """Verifies programmatic construction of DynamicThresholdProfile via dictionary mapping."""
        profile_map: dict[str, list[int]] = {
            "LOW": [0, 49],
            "MEDIUM": [50, 69],
            "HIGH": [70, 89],
            "CRITICAL": [90, 100],
        }

        profile = DynamicThresholdProfile.from_mapping(profile_map)
        resolver = DynamicRiskCategoryResolver(default_profile=profile)

        assert resolver.resolve(Decimal("45.0")) == RiskCategory.LOW
        assert resolver.resolve(Decimal("55.0")) == RiskCategory.MEDIUM
        assert resolver.resolve(Decimal("75.0")) == RiskCategory.HIGH
        assert resolver.resolve(Decimal("95.0")) == RiskCategory.CRITICAL

    def test_reject_invalid_threshold_profile_bounds(self) -> None:
        """Ensures that gap-ridden or overlapping threshold profiles raise ValueError."""
        # Overlapping tiers
        overlapping_tiers: tuple[ThresholdTier, ...] = (
            ThresholdTier(
                category=RiskCategory.LOW,
                min_score=Decimal("0.0"),
                max_score=Decimal("50.0"),
            ),
            ThresholdTier(
                category=RiskCategory.HIGH,
                min_score=Decimal("45.0"),
                max_score=Decimal("100.0"),
            ),
        )
        with pytest.raises(ValueError, match="Overlapping boundaries"):
            DynamicThresholdProfile(tiers=overlapping_tiers)

        # Non-zero start bound
        invalid_start_tiers: tuple[ThresholdTier, ...] = (
            ThresholdTier(
                category=RiskCategory.LOW,
                min_score=Decimal("10.0"),
                max_score=Decimal("100.0"),
            ),
        )
        with pytest.raises(ValueError, match="must start at exactly 0.0"):
            DynamicThresholdProfile(tiers=invalid_start_tiers)
