"""
Phase 1 — Governance verification suite.

Verifies that all hardcoded decisions have been removed from the scoring
pipeline and that authority flows through versioned RiskPolicy configuration.
"""

from decimal import Decimal
from uuid import uuid4

from app.domain.engine.calculators.frequency import DynamicFrequencyCalculator
from app.domain.engine.calculators.sensitivity import DynamicSensitivityCalculator
from app.domain.models.assessment import (
    AppliedPolicySnapshot,
    RiskAssessment,
    RiskComponents,
)
from app.domain.models.enums import EndpointClass, RiskCategory
from app.domain.models.investigation import (
    InvestigationResult,
    InvestigationTelemetry,
    TouchedEndpoint,
)
from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)
from app.services.investigation_service import InvestigationOrchestrationService


def _custom_low_0_29_policy() -> RiskPolicy:
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
                max_score=Decimal("29.9"),
            ),
            CategoryThresholdRange(
                category=RiskCategory.MEDIUM,
                min_score=Decimal("30.0"),
                max_score=Decimal("59.9"),
            ),
            CategoryThresholdRange(
                category=RiskCategory.HIGH,
                min_score=Decimal("60.0"),
                max_score=Decimal("79.9"),
            ),
            CategoryThresholdRange(
                category=RiskCategory.CRITICAL,
                min_score=Decimal("80.0"),
                max_score=Decimal("100.0"),
            ),
        )
    )
    return RiskPolicy(
        name="Custom Low-0-29 Policy",
        version="custom-policy-low-0-29",
        description="Custom thresholds where LOW caps at 29.9",
        weights=weights,
        thresholds=thresholds,
        endpoint_class_weights={},
        metadata={},
        is_active=True,
    )


def _spec_thresholds() -> ThresholdConfig:
    return ThresholdConfig(
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


def _snapshot(policy: RiskPolicy) -> AppliedPolicySnapshot:
    return AppliedPolicySnapshot(
        policy_id=policy.policy_id,
        version=policy.version,
        weights={
            "behavior": policy.weights.behavior,
            "frequency": policy.weights.frequency,
            "sensitivity": policy.weights.sensitivity,
            "history": policy.weights.history,
        },
        thresholds={
            "tiers": [
                {
                    "category": t.category.value,
                    "min_score": str(t.min_score),
                    "max_score": str(t.max_score),
                }
                for t in policy.thresholds.tiers
            ]
        },
    )


class TestStep10RatingFromPolicy:
    """Rating must resolve from the active policy, never from hardcoded branches."""

    def test_custom_low_0_29_policy_does_not_raise_invariant_violation(self) -> None:
        """Step 10: A custom policy with LOW 0-29 must not trigger
        'Rating invariant violation' in RiskAssessment.create()."""
        policy = _custom_low_0_29_policy()
        components = RiskComponents(
            behavior=Decimal("40.0"),
            frequency=Decimal("40.0"),
            sensitivity=Decimal("40.0"),
            history=Decimal("40.0"),
        )
        # Weighted: 0.4*40 + 0.3*40 + 0.2*40 + 0.1*40 = 40.0 -> MEDIUM under custom policy
        assessment = RiskAssessment.create(
            detection_event_id=uuid4(),
            investigation_id=uuid4(),
            correlation_id=uuid4(),
            source_ip="10.0.0.1",
            components=components,
            applied_policy=_snapshot(policy),
        )
        assert assessment.rating == RiskCategory.MEDIUM

    def test_custom_policy_score_83_5_is_critical_not_high(self) -> None:
        """Step 10: Under custom LOW 0-29 policy, 83.5 maps to CRITICAL (>=80.0),
        proving category comes from policy, not hardcoded spec branches."""
        policy = _custom_low_0_29_policy()
        components = RiskComponents(
            behavior=Decimal("90.0"),
            frequency=Decimal("85.0"),
            sensitivity=Decimal("80.0"),
            history=Decimal("60.0"),
        )
        assessment = RiskAssessment.create(
            detection_event_id=uuid4(),
            investigation_id=uuid4(),
            correlation_id=uuid4(),
            source_ip="10.0.0.1",
            components=components,
            applied_policy=_snapshot(policy),
        )
        assert assessment.rating == RiskCategory.CRITICAL


class TestStep11EndpointWeightsFromPolicy:
    """Sensitivity must use RiskPolicy.get_endpoint_weight() endpoint_class_weights."""

    def test_policy_endpoint_weight_changes_sensitivity_score(self) -> None:
        """Step 11: Changing DATABASE_SERVER weight in policy changes the
        sensitivity score computed by DynamicSensitivityCalculator."""
        touched = [
            TouchedEndpoint(
                endpoint_id="SRV-DB-01",
                endpoint_class=EndpointClass.DATABASE_SERVER,
                is_compromised=False,
            )
        ]
        inv = InvestigationResult(
            detection_event_id=uuid4(),
            correlation_id=uuid4(),
            telemetry=InvestigationTelemetry(
                event_frequency=1,
                endpoints_touched=1,
                endpoint_class=EndpointClass.DATABASE_SERVER,
                historical_incident_count=0,
            ),
            touched_endpoints=touched,
        )

        calc = DynamicSensitivityCalculator()

        # Policy A: DATABASE_SERVER weight = 80.0 (spec default)
        policy_a = RiskPolicy.create_spec_default(version="policy-a")
        score_a = calc.calculate(inv, policy=policy_a)
        assert score_a == Decimal("80.0")

        # Policy B: DATABASE_SERVER weight = 30.0
        policy_b = RiskPolicy(
            name="Policy B",
            version="policy-b",
            description="Low DB weight",
            weights=PolicyWeights(
                behavior=Decimal("0.40"),
                frequency=Decimal("0.30"),
                sensitivity=Decimal("0.20"),
                history=Decimal("0.10"),
            ),
            thresholds=_spec_thresholds(),
            endpoint_class_weights={EndpointClass.DATABASE_SERVER: Decimal("30.0")},
            metadata={},
            is_active=True,
        )
        score_b = calc.calculate(inv, policy=policy_b)
        assert score_b == Decimal("30.0")
        assert score_a != score_b


class TestStep12CalculatorConfigsInMetadata:
    """Calculator defaults must be overridable via RiskPolicy.metadata."""

    def test_frequency_saturation_count_from_policy_metadata(self) -> None:
        """Step 12: Overriding saturation_count in frequency_config changes
        the frequency sub-score produced by DynamicFrequencyCalculator."""
        inv = InvestigationResult(
            detection_event_id=uuid4(),
            correlation_id=uuid4(),
            telemetry=InvestigationTelemetry(
                event_frequency=25,
                endpoints_touched=1,
                endpoint_class=EndpointClass.WORKSTATION,
                historical_incident_count=0,
            ),
            touched_endpoints=[],
        )
        calc = DynamicFrequencyCalculator()

        # Default policy: saturation_count=50 -> ln(26)/ln(51)*100 = ~82.9
        default_policy = RiskPolicy.create_spec_default(version="default-freq")
        score_default = calc.calculate(inv, policy=default_policy)
        assert score_default == Decimal("82.9")

        # Custom policy: saturation_count=25 -> ln(26)/ln(26)*100 = 100.0
        custom_policy = RiskPolicy(
            name="Custom Frequency Policy",
            version="custom-freq",
            description="Lower saturation count",
            weights=PolicyWeights(
                behavior=Decimal("0.40"),
                frequency=Decimal("0.30"),
                sensitivity=Decimal("0.20"),
                history=Decimal("0.10"),
            ),
            thresholds=_spec_thresholds(),
            endpoint_class_weights={},
            metadata={
                "frequency_config": {
                    "saturation_count": 25,
                    "curvature_constant": 1.0,
                    "min_score": "0.0",
                    "max_score": "100.0",
                }
            },
            is_active=True,
        )
        score_custom = calc.calculate(inv, policy=custom_policy)
        assert score_custom == Decimal("100.0")
        assert score_default != score_custom


class TestStep13NoHardcodedHierarchy:
    """Dominant endpoint class must resolve from policy weights, not hardcoded dict."""

    def test_dominant_endpoint_uses_policy_weights(self) -> None:
        """Step 13: _determine_dominant_endpoint_class must use
        RiskPolicy.get_endpoint_weight() when a policy is supplied."""
        service = InvestigationOrchestrationService.__new__(
            InvestigationOrchestrationService
        )

        endpoints = [
            TouchedEndpoint(
                endpoint_id="EP-WS-01",
                endpoint_class=EndpointClass.WORKSTATION,
                is_compromised=False,
            ),
            TouchedEndpoint(
                endpoint_id="EP-DB-01",
                endpoint_class=EndpointClass.DATABASE_SERVER,
                is_compromised=False,
            ),
        ]

        # Policy where WORKSTATION (90) > DATABASE_SERVER (30) — inverted from seed defaults
        policy = RiskPolicy(
            name="Inverted Weights Policy",
            version="inverted-weights",
            description="Workstation more sensitive than DB",
            weights=PolicyWeights(
                behavior=Decimal("0.40"),
                frequency=Decimal("0.30"),
                sensitivity=Decimal("0.20"),
                history=Decimal("0.10"),
            ),
            thresholds=_spec_thresholds(),
            endpoint_class_weights={
                EndpointClass.WORKSTATION: Decimal("90.0"),
                EndpointClass.DATABASE_SERVER: Decimal("30.0"),
            },
            metadata={},
            is_active=True,
        )

        dominant = service._determine_dominant_endpoint_class(endpoints, policy=policy)
        assert dominant == EndpointClass.WORKSTATION

        # Without policy, falls back to default_base_weight (DB=85 > WS=40)
        dominant_no_policy = service._determine_dominant_endpoint_class(endpoints)
        assert dominant_no_policy == EndpointClass.DATABASE_SERVER


class TestStep14PolicyActivation:
    """Activating a new policy version must change the rating of a fixed score."""

    def test_policy_activation_changes_rating(self) -> None:
        """Step 14: Same score (60.0) is MEDIUM under spec default but HIGH
        under an aggressive policy (LOW 0-29, MEDIUM 30-59, HIGH 60+)."""
        score = Decimal("60.0")

        # Spec default: 60.0 -> MEDIUM
        default_policy = RiskPolicy.create_spec_default(version="spec-default")
        assert default_policy.resolve_category(score) == RiskCategory.MEDIUM

        # Aggressive policy: 60.0 -> HIGH (LOW 0-29, MEDIUM 30-59.9, HIGH 60-79.9)
        aggressive = _custom_low_0_29_policy()
        assert aggressive.resolve_category(score) == RiskCategory.HIGH
