"""
tests/unit/test_scoring_formula_verification.py

Independent mathematical verification of the core scoring kernel:
R = 0.4B + 0.3F + 0.2S + 0.1H
"""

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import pytest

from app.domain.engine.kernel import DeterministicRiskScoringKernel
from app.domain.engine.resolver import DynamicRiskCategoryResolver
from app.domain.models.assessment import RiskComponents
from app.domain.models.enums import RiskCategory
from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)


@pytest.fixture
def standard_policy() -> RiskPolicy:
    """Instantiates authoritative default RiskPolicy using standard tiers."""
    standard_tiers = (
        CategoryThresholdRange(RiskCategory.LOW, Decimal("0.0"), Decimal("39.9")),
        CategoryThresholdRange(RiskCategory.MEDIUM, Decimal("40.0"), Decimal("64.9")),
        CategoryThresholdRange(RiskCategory.HIGH, Decimal("65.0"), Decimal("84.9")),
        CategoryThresholdRange(RiskCategory.CRITICAL, Decimal("85.0"), Decimal("100.0")),
    )
    return RiskPolicy(
        name="Authoritative Baseline Verification Policy",
        version="risk-policy-baseline-v1",
        weights=PolicyWeights(
            behavior=Decimal("0.4"),
            frequency=Decimal("0.3"),
            sensitivity=Decimal("0.2"),
            history=Decimal("0.1"),
        ),
        thresholds=ThresholdConfig(tiers=standard_tiers),
    )


@pytest.fixture
def resolver() -> DynamicRiskCategoryResolver:
    return DynamicRiskCategoryResolver()


@pytest.fixture
def kernel() -> DeterministicRiskScoringKernel:
    return DeterministicRiskScoringKernel()


# ============================================================================
# 1. 7 Authoritative Input/Output Matrix Test Cases
# ============================================================================

@pytest.mark.parametrize(
    "case_name, b, f, s, h, expected_score, expected_category",
    [
        ("Minimum", Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), RiskCategory.LOW),
        ("Low", Decimal("20.0"), Decimal("20.0"), Decimal("20.0"), Decimal("20.0"), Decimal("20.0"), RiskCategory.LOW),
        ("Medium", Decimal("50.0"), Decimal("50.0"), Decimal("50.0"), Decimal("50.0"), Decimal("50.0"), RiskCategory.MEDIUM),
        ("High", Decimal("70.0"), Decimal("70.0"), Decimal("70.0"), Decimal("70.0"), Decimal("70.0"), RiskCategory.HIGH),
        ("Critical", Decimal("90.0"), Decimal("90.0"), Decimal("90.0"), Decimal("90.0"), Decimal("90.0"), RiskCategory.CRITICAL),
        ("Mixed", Decimal("90.0"), Decimal("85.0"), Decimal("80.0"), Decimal("60.0"), Decimal("83.5"), RiskCategory.HIGH),
        ("Boundary", Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), RiskCategory.CRITICAL),
    ],
)
def test_authoritative_scoring_matrix(
    standard_policy: RiskPolicy,
    resolver: DynamicRiskCategoryResolver,
    case_name: str,
    b: Decimal,
    f: Decimal,
    s: Decimal,
    h: Decimal,
    expected_score: Decimal,
    expected_category: RiskCategory,
):
    components = RiskComponents(behavior=b, frequency=f, sensitivity=s, history=h)

    calculated_score = (
        (standard_policy.weights.behavior * components.behavior)
        + (standard_policy.weights.frequency * components.frequency)
        + (standard_policy.weights.sensitivity * components.sensitivity)
        + (standard_policy.weights.history * components.history)
    ).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    assert calculated_score == expected_score, f"{case_name} failed score computation: {calculated_score} != {expected_score}"

    resolved_category = resolver.resolve(calculated_score, policy=standard_policy)
    assert resolved_category == expected_category, f"{case_name} failed category resolution: {resolved_category} != {expected_category}"


# ============================================================================
# 2. Strict Threshold Boundary Invariance Checks
# ============================================================================

@pytest.mark.parametrize(
    "boundary_score, expected_category",
    [
        (Decimal("0.0"), RiskCategory.LOW),
        (Decimal("39.0"), RiskCategory.LOW),
        (Decimal("39.9"), RiskCategory.LOW),
        (Decimal("40.0"), RiskCategory.MEDIUM),
        (Decimal("64.0"), RiskCategory.MEDIUM),
        (Decimal("64.9"), RiskCategory.MEDIUM),
        (Decimal("65.0"), RiskCategory.HIGH),
        (Decimal("84.0"), RiskCategory.HIGH),
        (Decimal("84.9"), RiskCategory.HIGH),
        (Decimal("85.0"), RiskCategory.CRITICAL),
        (Decimal("87.0"), RiskCategory.CRITICAL),  # Conflict check: 87 must resolve to CRITICAL
        (Decimal("100.0"), RiskCategory.CRITICAL),
    ],
)
def test_threshold_boundary_transitions(
    resolver: DynamicRiskCategoryResolver,
    standard_policy: RiskPolicy,
    boundary_score: Decimal,
    expected_category: RiskCategory,
):
    resolved = resolver.resolve(boundary_score, policy=standard_policy)
    assert resolved == expected_category, f"Score {boundary_score} resolved to {resolved}, expected {expected_category}"


# ============================================================================
# 3. Invalid Ranges, Types, Non-Numeric, and Rejection Checks
# ============================================================================

@pytest.mark.parametrize(
    "b, f, s, h",
    [
        (Decimal("-0.1"), Decimal("10.0"), Decimal("10.0"), Decimal("10.0")),
        (Decimal("10.0"), Decimal("-5.0"), Decimal("10.0"), Decimal("10.0")),
        (Decimal("10.0"), Decimal("10.0"), Decimal("-0.1"), Decimal("10.0")),
        (Decimal("10.0"), Decimal("10.0"), Decimal("10.0"), Decimal("-1.0")),
        (Decimal("100.1"), Decimal("50.0"), Decimal("50.0"), Decimal("50.0")),
        (Decimal("50.0"), Decimal("101.0"), Decimal("50.0"), Decimal("50.0")),
        (Decimal("50.0"), Decimal("50.0"), Decimal("200.0"), Decimal("50.0")),
        (Decimal("50.0"), Decimal("50.0"), Decimal("50.0"), Decimal("100.5")),
    ],
)
def test_reject_out_of_bounds_inputs(b: Decimal, f: Decimal, s: Decimal, h: Decimal):
    with pytest.raises(ValueError):
        RiskComponents(behavior=b, frequency=f, sensitivity=s, history=h)


@pytest.mark.parametrize(
    "invalid_val",
    [
        None,
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        [],
        {},
    ],
)
def test_reject_invalid_subscore_types(invalid_val):
    with pytest.raises((TypeError, ValueError, InvalidOperation)):
        RiskComponents(
            behavior=invalid_val,  # type: ignore
            frequency=Decimal("50.0"),
            sensitivity=Decimal("50.0"),
            history=Decimal("50.0"),
        )


# ============================================================================
# 4. Deterministic Idempotence Check
# ============================================================================

def test_repeated_scoring_invariance(
    standard_policy: RiskPolicy,
    resolver: DynamicRiskCategoryResolver,
):
    components = RiskComponents(
        behavior=Decimal("82.4"),
        frequency=Decimal("65.2"),
        sensitivity=Decimal("91.0"),
        history=Decimal("40.0"),
    )

    scores = []
    ratings = []
    for _ in range(50):
        score = (
            (standard_policy.weights.behavior * components.behavior)
            + (standard_policy.weights.frequency * components.frequency)
            + (standard_policy.weights.sensitivity * components.sensitivity)
            + (standard_policy.weights.history * components.history)
        ).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        category = resolver.resolve(score, policy=standard_policy)
        scores.append(score)
        ratings.append(category)

    assert len(set(scores)) == 1, "Idempotence failed: floating variance detected in score calculation"
    assert len(set(ratings)) == 1, "Idempotence failed: variance detected in rating resolution"
    assert scores[0] == Decimal("74.7")
    assert ratings[0] == RiskCategory.HIGH