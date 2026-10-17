"""
Unit verification suite for component calculators.
Tests Behavior, Frequency, Sensitivity, and History calculators against
dynamic configurations, boundary ranges [0.0, 100.0], and specification targets.
"""

from decimal import Decimal
from typing import Optional
from uuid import uuid4
import pytest

from app.domain.engine.calculators.behavior import (
    ConfidenceScaleConfig,
    DynamicBehaviorCalculator,
)
from app.domain.engine.calculators.frequency import (
    DynamicFrequencyCalculator,
    LinearCappedCurveConfig,
    LogarithmicCurveConfig,
)
from app.domain.engine.calculators.history import (
    DynamicHistoryCalculator,
    HistoryScaleConfig,
)
from app.domain.engine.calculators.sensitivity import (
    DynamicSensitivityCalculator,
    SensitivityAggregationConfig,
)
from app.domain.models.detection import (
    DetectionContext,
    DetectionEvent,
    DetectionMetrics,
)
from app.domain.models.enums import (
    DetectionSeverity,
    DetectionSourceType,
    EndpointClass,
)
from app.domain.models.investigation import (
    InvestigationResult,
    InvestigationTelemetry,
    TouchedEndpoint,
)
from app.domain.models.policy import RiskPolicy


def build_test_detection(
    confidence: Decimal,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    fidelity: Optional[Decimal] = None,
) -> DetectionEvent:
    """Helper to dynamically construct DetectionEvent instances for testing."""
    return DetectionEvent(
        correlation_id=uuid4(),
        source_type=DetectionSourceType.EDR,
        severity=severity,
        metrics=DetectionMetrics(confidence=confidence, fidelity=fidelity),
        context=DetectionContext(
            rule_id="RULE-CALC-001",
            rule_name="Process Injection Attempt",
            source_ip="10.0.0.15",
        ),
    )


def build_test_investigation(
    event_frequency: int,
    endpoints_touched: int = 1,
    endpoint_class: EndpointClass = EndpointClass.WORKSTATION,
    historical_incident_count: int = 0,
    severity_hint: Optional[Decimal] = None,
    touched_endpoints: Optional[list[TouchedEndpoint]] = None,
) -> InvestigationResult:
    """Helper to dynamically construct InvestigationResult instances for testing."""
    return InvestigationResult(
        detection_event_id=uuid4(),
        correlation_id=uuid4(),
        telemetry=InvestigationTelemetry(
            event_frequency=event_frequency,
            endpoints_touched=endpoints_touched,
            endpoint_class=endpoint_class,
            historical_incident_count=historical_incident_count,
            severity_hint=severity_hint,
        ),
        touched_endpoints=touched_endpoints or [],
    )


@pytest.fixture
def spec_default_policy() -> RiskPolicy:
    """Fixture supplying the authoritative default policy baseline."""
    return RiskPolicy.create_spec_default(version="risk-policy-2026-01")


class TestBehaviorCalculator:
    """Verifies confidence normalization and severity/fidelity adjustments."""

    def test_direct_0_to_100_confidence_normalization(self) -> None:
        """Verifies that confidence values already in [0.0, 100.0] scale directly without drift."""
        calculator = DynamicBehaviorCalculator()
        detection = build_test_detection(confidence=Decimal("90.0"))

        score = calculator.calculate(detection=detection)
        assert score == Decimal("90.0")

    def test_fractional_confidence_scaling(self) -> None:
        """Verifies that 0.0-1.0 confidence ranges scale dynamically to 0-100 target scales."""
        calculator = DynamicBehaviorCalculator(
            default_config=ConfidenceScaleConfig(
                source_scale_max=Decimal("1.0"),
                target_scale_max=Decimal("100.0"),
            )
        )
        detection = build_test_detection(confidence=Decimal("0.85"))

        score = calculator.calculate(detection=detection)
        assert score == Decimal("85.0")

    def test_confidence_boundary_clamping(self) -> None:
        """Ensures Behavior sub-scores clamp within strictly bounded [0.0, 100.0] limits."""
        calculator = DynamicBehaviorCalculator()
        min_detection = build_test_detection(confidence=Decimal("0.0"))
        max_detection = build_test_detection(confidence=Decimal("100.0"))

        assert calculator.calculate(detection=min_detection) == Decimal("0.0")
        assert calculator.calculate(detection=max_detection) == Decimal("100.0")

    def test_severity_hint_blending(self) -> None:
        """Verifies dynamic blending when investigation provides a correlated severity hint."""
        calculator = DynamicBehaviorCalculator()
        detection = build_test_detection(confidence=Decimal("90.0"))
        investigation = build_test_investigation(
            event_frequency=5,
            severity_hint=Decimal("80.0"),
        )

        score = calculator.calculate(detection=detection, investigation=investigation)
        # Expected blend: 90 * 0.9 + 80 * 0.1 = 81.0 + 8.0 = 89.0
        assert score == Decimal("89.0")


class TestFrequencyCalculator:
    """Verifies sliding-window recurrence count normalization curves."""

    def test_linear_capped_frequency_curve(self) -> None:
        """Verifies proportional linear saturation scaling against a dynamic cap ceiling."""
        calculator = DynamicFrequencyCalculator(
            default_linear_config=LinearCappedCurveConfig(cap_threshold=20)
        )

        zero_inv = build_test_investigation(event_frequency=0)
        mid_inv = build_test_investigation(event_frequency=10)
        cap_inv = build_test_investigation(event_frequency=20)
        overflow_inv = build_test_investigation(event_frequency=50)

        params = {"curve_type": "linear"}
        assert calculator.calculate(zero_inv, parameters=params) == Decimal("0.0")
        assert calculator.calculate(mid_inv, parameters=params) == Decimal("50.0")
        assert calculator.calculate(cap_inv, parameters=params) == Decimal("100.0")
        assert calculator.calculate(overflow_inv, parameters=params) == Decimal("100.0")

    def test_logarithmic_frequency_curve(self) -> None:
        """Verifies logarithmic decay curve behavior and saturation boundaries."""
        calculator = DynamicFrequencyCalculator(
            default_log_config=LogarithmicCurveConfig(saturation_count=50)
        )

        zero_inv = build_test_investigation(event_frequency=0)
        sat_inv = build_test_investigation(event_frequency=50)

        assert calculator.calculate(zero_inv) == Decimal("0.0")
        assert calculator.calculate(sat_inv) == Decimal("100.0")

        # Monotonically increasing check
        inv_5 = build_test_investigation(event_frequency=5)
        inv_25 = build_test_investigation(event_frequency=25)
        score_5 = calculator.calculate(inv_5)
        score_25 = calculator.calculate(inv_25)

        assert score_5 < score_25 < Decimal("100.0")


class TestSensitivityCalculator:
    """Verifies asset classification weighting, policy overrides, and lateral movement amplification."""

    def test_dominant_endpoint_sensitivity_mapping(
        self, spec_default_policy: RiskPolicy
    ) -> None:
        """Verifies baseline weighting per EndpointClass tier."""
        calculator = DynamicSensitivityCalculator()

        dc_inv = build_test_investigation(
            event_frequency=1, endpoint_class=EndpointClass.DOMAIN_CONTROLLER
        )
        ws_inv = build_test_investigation(
            event_frequency=1, endpoint_class=EndpointClass.WORKSTATION
        )

        assert calculator.calculate(dc_inv, policy=spec_default_policy) == Decimal("95.0")
        assert calculator.calculate(ws_inv, policy=spec_default_policy) == Decimal("40.0")

    def test_policy_endpoint_weight_overrides(self) -> None:
        """Verifies policy-configured asset sensitivity overrides take precedence over domain defaults."""
        custom_policy = RiskPolicy.create_spec_default()
        # Custom override: Database server set to 80.0
        object.__setattr__(
            custom_policy,
            "endpoint_class_weights",
            {EndpointClass.DATABASE_SERVER: Decimal("80.0")},
        )

        calculator = DynamicSensitivityCalculator()
        inv = build_test_investigation(
            event_frequency=1, endpoint_class=EndpointClass.DATABASE_SERVER
        )

        assert calculator.calculate(inv, policy=custom_policy) == Decimal("80.0")

    def test_lateral_spread_boost(self, spec_default_policy: RiskPolicy) -> None:
        """Verifies multi-node lateral movements apply bounded boost to sensitivity."""
        calculator = DynamicSensitivityCalculator(
            default_config=SensitivityAggregationConfig(
                apply_lateral_spread_boost=True,
                lateral_boost_per_endpoint=Decimal("2.5"),
                lateral_boost_cap=Decimal("15.0"),
            )
        )
        # Workstation base is 40.0; 4 endpoints touched adds 3 * 2.5 = 7.5
        inv = build_test_investigation(
            event_frequency=1,
            endpoints_touched=4,
            endpoint_class=EndpointClass.WORKSTATION,
        )

        score = calculator.calculate(inv, policy=spec_default_policy)
        assert score == Decimal("47.5")

    def test_itemized_compromised_endpoint_escalation(
        self, spec_default_policy: RiskPolicy
    ) -> None:
        """Verifies collection aggregation prioritizes confirmed compromised nodes."""
        calculator = DynamicSensitivityCalculator(
            default_config=SensitivityAggregationConfig(
                compromise_multiplier=Decimal("1.10"),
                apply_lateral_spread_boost=False,
            )
        )
        touched = [
            TouchedEndpoint(
                endpoint_id="EP-1",
                endpoint_class=EndpointClass.WORKSTATION,
                is_compromised=False,
            ),
            TouchedEndpoint(
                endpoint_id="EP-2",
                endpoint_class=EndpointClass.INTERNAL_SERVER,
                is_compromised=True,
            ),
        ]
        inv = build_test_investigation(
            event_frequency=1,
            endpoints_touched=2,
            endpoint_class=EndpointClass.WORKSTATION,
            touched_endpoints=touched,
        )

        # Internal Server base is 65.0 * 1.10 = 71.5
        score = calculator.calculate(inv, policy=spec_default_policy)
        assert score == Decimal("71.5")


class TestHistoryCalculator:
    """Verifies normalization of historical incidents associated with the source."""

    def test_zero_history_baseline(self, spec_default_policy: RiskPolicy) -> None:
        """Verifies zero previous incidents return 0.0 without bias."""
        calculator = DynamicHistoryCalculator()
        inv = build_test_investigation(event_frequency=1, historical_incident_count=0)

        assert calculator.calculate(inv, policy=spec_default_policy) == Decimal("0.0")

    def test_linear_history_saturation(self, spec_default_policy: RiskPolicy) -> None:
        """Verifies linear saturation curve reaches maximum at configured ceiling."""
        calculator = DynamicHistoryCalculator(
            default_config=HistoryScaleConfig(
                incident_saturation_ceiling=5,
                scaling_curve="linear",
            )
        )

        inv_3 = build_test_investigation(event_frequency=1, historical_incident_count=3)
        inv_5 = build_test_investigation(event_frequency=1, historical_incident_count=5)
        inv_10 = build_test_investigation(event_frequency=1, historical_incident_count=10)

        # 3 / 5 * 100 = 60.0
        assert calculator.calculate(inv_3, policy=spec_default_policy) == Decimal("60.0")
        assert calculator.calculate(inv_5, policy=spec_default_policy) == Decimal("100.0")
        assert calculator.calculate(inv_10, policy=spec_default_policy) == Decimal("100.0")

    def test_exponential_history_curve(self, spec_default_policy: RiskPolicy) -> None:
        """Verifies exponential curve accelerates penalty for repeat incident sources."""
        calculator = DynamicHistoryCalculator(
            default_config=HistoryScaleConfig(
                incident_saturation_ceiling=5,
                scaling_curve="exponential",
                exponential_rate=0.4,
            )
        )

        inv_1 = build_test_investigation(event_frequency=1, historical_incident_count=1)
        inv_2 = build_test_investigation(event_frequency=1, historical_incident_count=2)
        inv_5 = build_test_investigation(event_frequency=1, historical_incident_count=5)

        score_1 = calculator.calculate(inv_1, policy=spec_default_policy)
        score_2 = calculator.calculate(inv_2, policy=spec_default_policy)
        score_5 = calculator.calculate(inv_5, policy=spec_default_policy)

        assert Decimal("0.0") < score_1 < score_2 < score_5 == Decimal("100.0")