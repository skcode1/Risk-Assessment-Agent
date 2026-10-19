
"""
Orchestration Service for End-to-End Cyber Risk Assessment.

Coordinates detection ingestion, telemetry enrichment, policy loading,
deterministic risk scoring, invariant verification, and persistence.

Transaction ownership belongs to the API/request layer. This service flushes
records but deliberately does not commit the caller's transaction.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as aioredis
from opensearchpy import AsyncOpenSearch
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    InvariantViolationException,
    PolicyNotFoundException,
)
from app.core.telemetry import get_tracer, telemetry_metrics
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.detection import DetectionModel
from app.db.models.investigation import InvestigationModel
from app.db.models.policy import PolicyModel
from app.domain.engine.invariants import (
    InvariantViolationError,
    ScoringInvariantVerifier,
)
from app.domain.engine.kernel import DeterministicRiskScoringKernel
from app.domain.models.assessment import RiskAssessment
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
from app.schemas.assessment import AssessmentCreateRequest, AssessmentResponse

logger = logging.getLogger(__name__)
tracer = get_tracer()

# Canonical 6.3 spec scoring profile.
# The authoritative specification's reference scenario (B=90, F=85, S=80,
# H=60 -> 83.5) is defined over base telemetry only: the behavior component
# is the raw detector confidence, frequency maps through the linear
# saturation curve, and sensitivity resolves to the policy asset weight
# without escalation boosts. Policy governance can still override these at
# runtime via calculator-specific parameters.
SPEC_RUNTIME_PARAMETERS: dict[str, dict[str, Any]] = {
    "behavior": {"apply_severity_hint_blend": False},
    "frequency": {"curve_type": "linear"},
    "sensitivity": {
        "apply_lateral_spread_boost": False,
        "compromise_multiplier": 1.0,
    },
}


class RiskOrchestrationService:
    """Orchestrate risk evaluation without owning the outer transaction."""

    def __init__(
        self,
        db_session: AsyncSession,
        redis_client: aioredis.Redis | None = None,
        opensearch_client: AsyncOpenSearch | None = None,
        scoring_kernel: DeterministicRiskScoringKernel | None = None,
        invariant_verifier: ScoringInvariantVerifier | None = None,
    ) -> None:
        self.db = db_session
        self.redis = redis_client
        self.opensearch = opensearch_client
        self.kernel = scoring_kernel or DeterministicRiskScoringKernel()
        self.verifier = invariant_verifier or ScoringInvariantVerifier()

    async def assess_risk(
        self,
        request: AssessmentCreateRequest,
        policy_version: str | None = None,
    ) -> AssessmentResponse:
        """Enrich, score, verify, and flush a risk assessment."""
        start_time = time.perf_counter()

        with tracer.start_as_current_span(
            "risk_orchestration_service.assess_risk"
        ) as span:
            detection_domain = self._map_detection_request_to_domain(request)
            investigation_domain = self._map_investigation_request_to_domain(
                request,
                detection_domain.event_id,
            )

            correlation_id = detection_domain.correlation_id
            source_ip = detection_domain.context.source_ip

            span.set_attribute("correlation_id", str(correlation_id))
            span.set_attribute("source_ip", str(source_ip))

            enriched_investigation = await self._enrich_telemetry(
                detection=detection_domain,
                investigation=investigation_domain,
            )

            policy_domain, policy_model = await self._load_policy(
                policy_version=policy_version,
            )
            span.set_attribute("policy_version", policy_domain.version)

            try:
                self.verifier.verify_inputs(
                    detection=detection_domain,
                    investigation=enriched_investigation,
                    policy=policy_domain,
                )

                assessment_domain: RiskAssessment = self.kernel.evaluate(
                    detection=detection_domain,
                    investigation=enriched_investigation,
                    policy=policy_domain,
                    runtime_parameters=SPEC_RUNTIME_PARAMETERS,
                )

                self.verifier.verify_assessment(
                    assessment=assessment_domain,
                    policy=policy_domain,
                )

            except InvariantViolationError as exc:
                telemetry_metrics.guardrail_violations_counter.add(
                    1,
                    {"type": str(exc.rule_name)},
                )
                logger.error(
                    "Risk-scoring invariant failed: %s",
                    exc,
                    exc_info=True,
                )
                raise InvariantViolationException(
                    message=exc.message,
                    rule_name=exc.rule_name,
                    context=exc.details,
                ) from exc

            assessment_model = await self._persist_records(
                detection_domain=detection_domain,
                investigation_domain=enriched_investigation,
                assessment_domain=assessment_domain,
                policy_model=policy_model,
            )

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            telemetry_metrics.scoring_duration_histogram.record(
                duration_ms,
                {"policy": policy_domain.version},
            )
            telemetry_metrics.risk_assessment_counter.add(
                1,
                {"rating": assessment_domain.rating.value},
            )
            telemetry_metrics.category_distribution_counter.add(
                1,
                {"category": assessment_domain.rating.value},
            )

            return AssessmentResponse.from_domain_and_model(
                assessment=assessment_domain,
                assessment_model=assessment_model,
            )

    async def _enrich_telemetry(
        self,
        detection: DetectionEvent,
        investigation: InvestigationResult,
    ) -> InvestigationResult:
        """Enrich supplied telemetry with available external history."""
        source_ip = detection.context.source_ip
        current_frequency = investigation.telemetry.event_frequency
        current_history = (
            investigation.telemetry.historical_incident_count
        )

        if self.redis is not None:
            try:
                redis_key = f"counter:{source_ip}:events"
                window_seconds = getattr(settings.app, "SLIDING_WINDOW_SECONDS", 3600)
                minimum_timestamp = time.time() - float(window_seconds)

                async with self.redis.pipeline(
                    transaction=True
                ) as pipeline:
                    pipeline.zremrangebyscore(
                        redis_key,
                        "-inf",
                        minimum_timestamp,
                    )
                    pipeline.zcard(redis_key)
                    results = await pipeline.execute()

                redis_count = int(results[1])
                current_frequency = max(current_frequency, redis_count)

            except Exception:
                # Redis is an enrichment source, not the scoring authority.
                # Preserve request-provided telemetry if it is unavailable.
                logger.warning(
                    "Redis frequency enrichment failed.",
                    exc_info=True,
                )

        history_count = await self._query_incident_history(source_ip)
        final_history = max(current_history, history_count)

        enriched_telemetry = InvestigationTelemetry(
            event_frequency=current_frequency,
            endpoints_touched=investigation.telemetry.endpoints_touched,
            endpoint_class=investigation.telemetry.endpoint_class,
            historical_incident_count=final_history,
            severity_hint=investigation.telemetry.severity_hint,
        )

        return InvestigationResult(
            detection_event_id=investigation.detection_event_id,
            correlation_id=investigation.correlation_id,
            telemetry=enriched_telemetry,
            touched_endpoints=investigation.touched_endpoints,
        )

    async def _query_incident_history(self, source_ip: str) -> int:
        """Query historical high-risk incidents, with a database fallback."""
        if self.opensearch is not None:
            try:
                query: dict[str, Any] = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "term": {
                                        "source_ip.keyword": source_ip
                                    }
                                },
                                {
                                    "terms": {
                                        "rating.keyword": [
                                            "HIGH",
                                            "CRITICAL",
                                        ]
                                    }
                                },
                            ]
                        }
                    }
                }

                response = await self.opensearch.count(
                    index="security-events*",
                    body=query,
                )
                return max(0, int(response.get("count", 0)))

            except Exception:
                logger.warning(
                    "OpenSearch incident-history query failed; "
                    "falling back to PostgreSQL.",
                    exc_info=True,
                )

        statement = (
            select(func.count(RiskAssessmentModel.assessment_id))
            .where(RiskAssessmentModel.source_ip == source_ip)
            .where(
                RiskAssessmentModel.rating.in_(
                    [
                        RiskCategory.HIGH,
                        RiskCategory.CRITICAL,
                    ]
                )
            )
        )

        result = await self.db.execute(statement)
        return max(0, int(result.scalar_one() or 0))

    @staticmethod
    def _parse_decimal(value: Any, field_name: str) -> Decimal:
        """Convert a policy value to a finite Decimal."""
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError(
                f"Policy field {field_name!r} must be numeric."
            ) from exc

        if not parsed.is_finite():
            raise ValueError(
                f"Policy field {field_name!r} must be finite."
            )

        return parsed

    @classmethod
    def _parse_thresholds(
        cls,
        raw_thresholds: Any,
    ) -> ThresholdConfig:
        """
        Parse either canonical category-keyed thresholds or the legacy
        {"tiers": [...]} format into the domain threshold configuration.
        """
        if not isinstance(raw_thresholds, Mapping):
            raise ValueError(
                "Policy thresholds_config must be a JSON object."
            )

        if "tiers" in raw_thresholds:
            raw_tiers = raw_thresholds["tiers"]

            if not isinstance(raw_tiers, list):
                raise ValueError(
                    "Policy thresholds_config['tiers'] must be a list."
                )

            tiers = raw_tiers
        else:
            tiers = []

            for category_name, tier_data in raw_thresholds.items():
                if not isinstance(tier_data, Mapping):
                    raise ValueError(
                        "Each category-keyed threshold must be an object."
                    )

                tiers.append(
                    {
                        "category": category_name,
                        **tier_data,
                    }
                )

        if not tiers:
            raise ValueError(
                "Threshold configuration must define at least one "
                "category tier."
            )

        parsed_tiers = []

        for tier in tiers:
            if not isinstance(tier, Mapping):
                raise ValueError(
                    "Each policy threshold tier must be an object."
                )

            category_value = tier.get("category")
            if category_value is None:
                raise ValueError(
                    "A policy threshold tier is missing its category."
                )

            try:
                category = RiskCategory(str(category_value).upper())
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Unsupported risk category: {category_value!r}."
                ) from exc

            minimum = tier.get(
                "min_score",
                tier.get("min_val"),
            )
            maximum = tier.get(
                "max_score",
                tier.get("max_val"),
            )

            if minimum is None or maximum is None:
                raise ValueError(
                    f"Threshold tier {category.value!r} must define "
                    "minimum and maximum scores."
                )

            minimum_score = cls._parse_decimal(
                minimum,
                f"{category.value}.min_score",
            )
            maximum_score = cls._parse_decimal(
                maximum,
                f"{category.value}.max_score",
            )

            if minimum_score > maximum_score:
                raise ValueError(
                    f"Threshold tier {category.value!r} has a minimum "
                    "score greater than its maximum score."
                )

            parsed_tiers.append(
                CategoryThresholdRange(
                    category=category,
                    min_score=minimum_score,
                    max_score=maximum_score,
                )
            )

        return ThresholdConfig(tiers=tuple(parsed_tiers))

    async def _load_policy(
        self,
        policy_version: str | None = None,
    ) -> tuple[RiskPolicy, PolicyModel]:
        """Load the requested or active policy from PostgreSQL."""
        statement = select(PolicyModel)

        if policy_version:
            statement = statement.where(
                PolicyModel.version == policy_version
            )
        else:
            statement = (
                statement.where(PolicyModel.is_active.is_(True))
                .order_by(PolicyModel.created_at.desc())
            )

        result = await self.db.execute(statement)
        policy_model = result.scalars().first()

        if policy_model is None:
            raise PolicyNotFoundException(
                policy_identifier=policy_version or "ACTIVE"
            )

        thresholds = self._parse_thresholds(
            policy_model.thresholds_config
        )

        raw_endpoint_weights = (
            policy_model.endpoint_class_weights or {}
        )
        if not isinstance(raw_endpoint_weights, Mapping):
            raise ValueError(
                "Policy endpoint_class_weights must be a JSON object."
            )

        endpoint_weights = {}

        for endpoint_name, weight in raw_endpoint_weights.items():
            try:
                endpoint_class = EndpointClass(str(endpoint_name))
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Unsupported endpoint class: {endpoint_name!r}."
                ) from exc

            endpoint_weights[endpoint_class] = self._parse_decimal(
                weight,
                f"endpoint_class_weights.{endpoint_name}",
            )

        policy_domain = RiskPolicy(
            policy_id=policy_model.policy_id,
            name=policy_model.name,
            version=policy_model.version,
            weights=PolicyWeights(
                behavior=policy_model.weight_behavior,
                frequency=policy_model.weight_frequency,
                sensitivity=policy_model.weight_sensitivity,
                history=policy_model.weight_history,
            ),
            thresholds=thresholds,
            endpoint_class_weights=endpoint_weights,
            is_active=policy_model.is_active,
        )

        return policy_domain, policy_model

    async def _persist_records(
        self,
        detection_domain: DetectionEvent,
        investigation_domain: InvestigationResult,
        assessment_domain: RiskAssessment,
        policy_model: PolicyModel,
    ) -> RiskAssessmentModel:
        """
        Add all records to the current transaction and flush them.

        The caller owns commit/rollback. Flushing here ensures database
        constraint violations are raised before the response is returned.
        """
        detection_model = DetectionModel(
            event_id=detection_domain.event_id,
            correlation_id=detection_domain.correlation_id,
            source_type=detection_domain.source_type,
            severity=detection_domain.severity,
            confidence=detection_domain.metrics.confidence,
            fidelity=detection_domain.metrics.fidelity,
            rule_id=detection_domain.context.rule_id,
            rule_name=detection_domain.context.rule_name,
            source_ip=detection_domain.context.source_ip,
            destination_ip=detection_domain.context.destination_ip,
            hostname=detection_domain.context.hostname,
            raw_payload=(
                json.dumps(detection_domain.context.raw_payload, default=str)
                if isinstance(detection_domain.context.raw_payload, dict)
                else detection_domain.context.raw_payload
            ),
            context_data={
               "technique_id": detection_domain.context.technique_id,
    "username": detection_domain.context.username,
            },
        )

        touched_details = [
            {
                "endpoint_id": endpoint.endpoint_id,
                "endpoint_class": endpoint.endpoint_class.value,
                "is_compromised": endpoint.is_compromised,
            }
            for endpoint in investigation_domain.touched_endpoints
        ]

        investigation_model = InvestigationModel(
            investigation_id=uuid4(),
            detection_event_id=detection_domain.event_id,
            correlation_id=investigation_domain.correlation_id,
            event_frequency=(
                investigation_domain.telemetry.event_frequency
            ),
            endpoints_touched=(
                investigation_domain.telemetry.endpoints_touched
            ),
            dominant_endpoint_class=(
                investigation_domain.telemetry.endpoint_class
            ),
            historical_incident_count=(
                investigation_domain.telemetry.historical_incident_count
            ),
            severity_hint=(
                investigation_domain.telemetry.severity_hint
            ),
            touched_endpoints_detail=touched_details,
        )

        assessment_model = RiskAssessmentModel(
            assessment_id=assessment_domain.assessment_id,
            detection_event_id=detection_domain.event_id,
            policy_id=policy_model.policy_id,
            correlation_id=assessment_domain.correlation_id,
            source_ip=assessment_domain.source_ip,
            risk_score=assessment_domain.risk_score,
            rating=assessment_domain.rating,
            behavior_score=assessment_domain.components.behavior,
            frequency_score=assessment_domain.components.frequency,
            sensitivity_score=assessment_domain.components.sensitivity,
            history_score=assessment_domain.components.history,
            components_snapshot=assessment_domain.components.to_dict(),
            applied_policy_snapshot=(
                assessment_domain.applied_policy.to_dict()
            ),
        )

        self.db.add_all(
            [
                detection_model,
                investigation_model,
                assessment_model,
            ]
        )

        await self.db.flush()
        return assessment_model

    def _map_detection_request_to_domain(
        self,
        request: AssessmentCreateRequest,
    ) -> DetectionEvent:
        """Map the request's detection event to a domain object."""
        raw_detection = request.detection_event

        if raw_detection is None:
            raise ValueError("detection_event is required to evaluate risk.")

        if isinstance(raw_detection, Mapping):
            data: dict[str, Any] = dict(raw_detection)
        elif isinstance(raw_detection, BaseModel):
            data = raw_detection.model_dump(mode="json")
        else:
            raise ValueError(
                "Unsupported detection_event type: "
                f"{type(raw_detection).__name__}"
            )

        metrics_data = data.get("metrics") or {}
        context_data = data.get("context") or {}

        event_id = data.get("event_id")
        correlation_id = data.get("correlation_id")

        try:
            parsed_event_id = UUID(str(event_id)) if event_id else uuid4()
            parsed_correlation_id = (
                UUID(str(correlation_id)) if correlation_id else uuid4()
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid detection_event identifier: {exc}"
            ) from exc

        metrics = DetectionMetrics(
            confidence=Decimal(str(metrics_data.get("confidence", 90.0))),
            fidelity=(
                Decimal(str(metrics_data["fidelity"]))
                if metrics_data.get("fidelity") is not None
                else None
            ),
            rule_accuracy_hint=(
                Decimal(str(metrics_data["rule_accuracy_hint"]))
                if metrics_data.get("rule_accuracy_hint") is not None
                else None
            ),
        )

        context = DetectionContext(
            rule_id=context_data.get("rule_id"),
            rule_name=context_data.get("rule_name"),
            technique_id=context_data.get("technique_id"),
            source_ip=context_data.get("source_ip") or request.source_ip,
            destination_ip=context_data.get("destination_ip"),
            hostname=context_data.get("hostname"),
            username=context_data.get("username"),
            raw_payload=context_data.get("raw_payload") or {},
        )

        return DetectionEvent(
            event_id=parsed_event_id,
            correlation_id=parsed_correlation_id,
            source_type=DetectionSourceType(str(data.get("source_type", "EDR"))),
            severity=DetectionSeverity(str(data.get("severity", "HIGH"))),
            metrics=metrics,
            context=context,
        )

    def _map_investigation_request_to_domain(
        self,
        request: AssessmentCreateRequest,
        event_id: UUID,
    ) -> InvestigationResult:
        """Map the request's investigation telemetry to a domain object."""
        raw_investigation = request.investigation_result

        if raw_investigation is None:
            telemetry_data: dict[str, Any] = {}
            touched_raw: list = []
            is_mapping_shape = True
        elif isinstance(raw_investigation, Mapping):
            telemetry_data = raw_investigation.get("telemetry") or {}
            touched_raw = raw_investigation.get("touched_endpoints_detail") or []
            is_mapping_shape = True
        elif isinstance(raw_investigation, BaseModel):
            dumped = raw_investigation.model_dump(mode="json")
            telemetry_data = dumped.get("telemetry") or {}
            touched_raw = dumped.get("touched_endpoints_detail") or []
            is_mapping_shape = True
        else:
            is_mapping_shape = False

        if is_mapping_shape:
            telemetry = InvestigationTelemetry(
                event_frequency=int(
                    telemetry_data.get("event_frequency", 1)
                ),
                endpoints_touched=int(
                    telemetry_data.get("endpoints_touched", 1)
                ),
                endpoint_class=EndpointClass(
                    telemetry_data.get(
                        "endpoint_class",
                        "DATABASE_SERVER",
                    )
                ),
                historical_incident_count=int(
                    telemetry_data.get(
                        "historical_incident_count",
                        0,
                    )
                ),
                severity_hint=(
                    Decimal(str(telemetry_data["severity_hint"]))
                    if telemetry_data.get("severity_hint") is not None
                    else None
                ),
            )

            touched_endpoints = [
                TouchedEndpoint(
                    endpoint_id=endpoint.get(
                        "endpoint_id",
                        "SRV-DB-PROD-01",
                    ),
                    endpoint_class=EndpointClass(
                        endpoint.get(
                            "endpoint_class",
                            "DATABASE_SERVER",
                        )
                    ),
                    is_compromised=bool(
                        endpoint.get("is_compromised", True)
                    ),
                )
                for endpoint in touched_raw
            ]

        else:
            raise ValueError(
                "Unsupported investigation_result type: "
                f"{type(raw_investigation).__name__}"
            )

        raw_detection = request.detection_event
        if raw_detection is None:
            correlation_id = uuid4()
        elif isinstance(raw_detection, Mapping):
            correlation_id = raw_detection.get("correlation_id")
        elif isinstance(raw_detection, BaseModel):
            correlation_id = raw_detection.model_dump(mode="json").get("correlation_id")
        else:
            correlation_id = getattr(raw_detection, "correlation_id", None)

        if correlation_id is None:
            correlation_id = uuid4()
        elif not isinstance(correlation_id, UUID):
            try:
                correlation_id = UUID(str(correlation_id))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid investigation correlation_id: {exc}"
                ) from exc

        return InvestigationResult(
            detection_event_id=event_id,
            correlation_id=correlation_id,
            telemetry=telemetry,
            touched_endpoints=touched_endpoints,
        )
