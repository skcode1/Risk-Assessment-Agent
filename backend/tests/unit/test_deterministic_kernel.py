"""
Unit verification suite for the Deterministic Risk Scoring Kernel.
Tests mathematical invariance, specification grounding, boundary edge conditions,
IEEE-754 precision immunity, and non-null guarantees.
"""

from decimal import Decimal
from typing import Any, Dict
from uuid import uuid4
import pytest

from app.domain.engine.invariants import (
    InvariantRuleConfig,
    InvariantViolationError,
    ScoringInvariantVerifier,
)
from app.domain.engine.kernel import (
    DeterministicRiskScoringKernel,
    ScoringKernelResult,
)
from app.domain.models.assessment import RiskComponents
from app.domain.models.detection import (
    DetectionContext,
    DetectionEvent,
    DetectionMetrics,
)
from app.domain.models.enums import (
    DetectionSeverity,
    DetectionSourceType,
    EndpointClass,
    RiskCategory,
)
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


@pytest.fixture
def spec_default_policy() -> RiskPolicy:
    """Fixture providing the versioned baseline policy matching documented spec parameters."""
    return RiskPolicy.create_spec_default(version="risk-policy-2026-01")


@pytest.fixture
def scoring_kernel() -> DeterministicRiskScoringKernel:
    """Fixture providing an instance of the deterministic risk scoring kernel."""
    return DeterministicRiskScoringKernel()


@pytest.fixture
def invariant_verifier() -> ScoringInvariantVerifier:
    """Fixture providing an invariant verification engine."""
    return ScoringInvariantVerifier(InvariantRuleConfig())


@pytest.fixture
def spec_canonical_components() -> RiskComponents:
    """
    Canonical fixtures defined in 6.3 spec:
    Behavior = 90.0, Frequency = 85.0, Sensitivity = 80.0, History = 60.0.
    """
    return RiskComponents(
        behavior=Decimal("90.0"),
        frequency=Decimal("85.0"),
        sensitivity=Decimal("80.0"),
        history=Decimal("60.0"),
    )


class TestDeterministicKernelSpecification:
    """Direct verification of the specification mathematical invariants."""

    def test_spec_canonical_calculation_invariance(
        self,
        scoring_kernel: DeterministicRiskScoringKernel,
        spec_default_policy: RiskPolicy,
        spec_canonical_components: RiskComponents,
        invariant_verifier: ScoringInvariantVerifier,
    ) -> None:
        """
        Calculates:
            Risk = 0.4(90) + 0.3(85) + 0.2(80) + 0.1(60)
                 = 36.0 + 25.5 + 16.0 + 6.0
                 = 83.5 -> HIGH
        Verifies exact numerical invariance, rating resolution, and metadata snapshots.
        """
        result: ScoringKernelResult = scoring_kernel.calculate_from_components(
            components=spec_canonical_components,
            policy=spec_default_policy,
        )

        # Mathematical verification
        expected_score = Decimal("83.5")
        assert result.risk_score == expected_score
        assert result.rating == RiskCategory.HIGH

        # Audit & Policy verification
        assert result.applied_policy.version == "risk-policy-2026-01"
        assert result.applied_policy.weights["behavior"] == Decimal("0.40")
        assert result.applied_policy.weights["frequency"] == Decimal("0.30")
        assert result.applied_policy.weights["sensitivity"] == Decimal("0.20")
        assert result.applied_policy.weights["history"] == Decimal("0.10")

        # Invariant verifier assertions
        invariant_verifier.verify_components(result.components)

    @pytest.mark.parametrize(
        ("b", "f", "s", "h", "expected_score", "expected_category"),
        [
            # Boundary Min
            (Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), Decimal("0.0"), RiskCategory.LOW),
            # Low Tier Threshold (Upper limit: 39.9)
            (Decimal("39.0"), Decimal("39.0"), Decimal("39.0"), Decimal("39.0"), Decimal("39.0"), RiskCategory.LOW),
            # Medium Tier Threshold (Lower limit: 40.0)
            (Decimal("40.0"), Decimal("40.0"), Decimal("40.0"), Decimal("40.0"), Decimal("40.0"), RiskCategory.MEDIUM),
            # Medium Tier Threshold (Upper limit: 64.9)
            (Decimal("64.0"), Decimal("64.0"), Decimal("64.0"), Decimal("64.0"), Decimal("64.0"), RiskCategory.MEDIUM),
            # High Tier Threshold (Lower limit: 65.0)
            (Decimal("65.0"), Decimal("65.0"), Decimal("65.0"), Decimal("65.0"), Decimal("65.0"), RiskCategory.HIGH),
            # High Tier Spec Check (Canonical 83.5)
            (Decimal("90.0"), Decimal("85.0"), Decimal("80.0"), Decimal("60.0"), Decimal("83.5"), RiskCategory.HIGH),
            # Critical Tier Threshold (Lower limit: 85.0)
            (Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), Decimal("85.0"), RiskCategory.CRITICAL),
            # Boundary Max
            (Decimal("100.0"), Decimal("100.0"), Decimal("100.0"), Decimal("100.0"), Decimal("100.0"), RiskCategory.CRITICAL),
        ],
    )
    def test_threshold_category_mappings(
        self,
        scoring_kernel: DeterministicRiskScoringKernel,
        spec_default_policy: RiskPolicy,
        b: Decimal,
        f: Decimal,
        s: Decimal,
        h: Decimal,
        expected_score: Decimal,
        expected_category: RiskCategory,
    ) -> None:
        """Verifies category boundaries across LOW, MEDIUM, HIGH, and CRITICAL."""
        components = RiskComponents(behavior=b, frequency=f, sensitivity=s, history=h)
        result = scoring_kernel.calculate_from_components(components, spec_default_policy)

        assert result.risk_score == expected_score
        assert result.rating == expected_category

    def test_reproducibility_simulation_runs(
        self,
        scoring_kernel: DeterministicRiskScoringKernel,
        spec_default_policy: RiskPolicy,
        spec_canonical_components: RiskComponents,
    ) -> None:
        """
        Validates the success criterion:
        Produces consistent, reproducible ratings across repeated simulation runs.
        """
        runs = [
            scoring_kernel.calculate_from_components(spec_canonical_components, spec_default_policy)
            for _ in range(100)
        ]

        base_score = runs[0].risk_score
        base_category = runs[0].rating

        assert all(run.risk_score == base_score for run in runs)
        assert all(run.rating == base_category for run in runs)


class TestFullPipelineEvaluation:
    """Tests end-to-end evaluation flow from Detection and Investigation entities to RiskAssessment."""

    def test_evaluate_from_raw_telemetry_entities(
        self,
        scoring_kernel: DeterministicRiskScoringKernel,
        spec_default_policy: RiskPolicy,
        invariant_verifier: ScoringInvariantVerifier,
    ) -> None:
        """Verifies full resolution pipeline using domain models without pre-computed components."""
        correlation_id = uuid4()

        detection = DetectionEvent(
            correlation_id=correlation_id,
            source_type=DetectionSourceType.EDR,
            severity=DetectionSeverity.HIGH,
            metrics=DetectionMetrics(confidence=Decimal("90.0")),
            context=DetectionContext(
                rule_id="RULE-SIG-001",
                rule_name="Credential Dumping Activity",
                source_ip="1.2.3.4",
            ),
        )

        investigation = InvestigationResult(
            detection_event_id=detection.event_id,
            correlation_id=correlation_id,
            telemetry=InvestigationTelemetry(
                event_frequency=17,
                endpoints_touched=4,
                endpoint_class=EndpointClass.DATABASE_SERVER,
                historical_incident_count=3,
            ),
            touched_endpoints=[
                TouchedEndpoint(
                    endpoint_id="SRV-DB-PROD-01",
                    endpoint_class=EndpointClass.DATABASE_SERVER,
                ),
                TouchedEndpoint(
                    endpoint_id="DC-AUTH-01",
                    endpoint_class=EndpointClass.DOMAIN_CONTROLLER,
                ),
            ],
        )

        assessment = scoring_kernel.evaluate(
            detection=detection,
            investigation=investigation,
            policy=spec_default_policy,
        )

        # Enforce mathematical invariants & guarantees
        invariant_verifier.verify_inputs(detection, investigation, spec_default_policy)
        invariant_verifier.verify_assessment(assessment, spec_default_policy)

        # Output schema checks
        output_payload: Dict[str, Any] = assessment.to_spec_dict()
        assert output_payload["source_ip"] == "1.2.3.4"
        assert isinstance(output_payload["risk_score"], float)
        assert output_payload["rating"] in {cat.value for cat in RiskCategory}
        assert "components" in output_payload
        assert set(output_payload["components"].keys()) == {
            "behavior",
            "frequency",
            "sensitivity",
            "history",
        }


class TestInvariantFailureModes:
    """Verifies that the engine rejects invalid ranges, NaN, null inputs, and policy deviations."""

    def test_reject_out_of_bounds_components(self) -> None:
        """Enforces that sub-scores outside [0.0, 100.0] are strictly rejected."""
        with pytest.raises(ValueError, match="must be within"):
            RiskComponents(
                behavior=Decimal("105.0"),
                frequency=Decimal("50.0"),
                sensitivity=Decimal("50.0"),
                history=Decimal("50.0"),
            )

        with pytest.raises(ValueError, match="must be within"):
            RiskComponents(
                behavior=Decimal("-1.0"),
                frequency=Decimal("50.0"),
                sensitivity=Decimal("50.0"),
                history=Decimal("50.0"),
            )

    def test_reject_mismatched_weights_sum(self) -> None:
        """Enforces that policy weights must sum up to exactly 1.00."""
        with pytest.raises(ValueError, match="must sum up to exactly 1.00"):
            PolicyWeights(
                behavior=Decimal("0.50"),
                frequency=Decimal("0.50"),
                sensitivity=Decimal("0.20"),
                history=Decimal("0.10"),
            )

    def test_reject_correlation_mismatch(
        self,
        scoring_kernel: DeterministicRiskScoringKernel,
        spec_default_policy: RiskPolicy,
        invariant_verifier: ScoringInvariantVerifier,
    ) -> None:
        """Ensures mismatched correlation tracking triggers an invariant violation error."""
        detection = DetectionEvent(
            correlation_id=uuid4(),
            source_type=DetectionSourceType.EDR,
            severity=DetectionSeverity.MEDIUM,
            metrics=DetectionMetrics(confidence=Decimal("50.0")),
            context=DetectionContext(rule_id="RULE-01", rule_name="Test Rule"),
        )
        investigation = InvestigationResult(
            detection_event_id=detection.event_id,
            correlation_id=uuid4(),  # Mismatched correlation ID
            telemetry=InvestigationTelemetry(
                event_frequency=1,
                endpoints_touched=1,
                endpoint_class=EndpointClass.WORKSTATION,
                historical_incident_count=0,
            ),
        )

        with pytest.raises(InvariantViolationError, match="CORRELATION_ID_MISMATCH"):
            invariant_verifier.verify_inputs(detection, investigation, spec_default_policy)