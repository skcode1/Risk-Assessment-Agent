

import logging
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
from opensearchpy import AsyncOpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BaseAppException
from app.core.telemetry import get_tracer
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.detection import DetectionModel
from app.db.models.investigation import InvestigationModel
from app.domain.models.enums import EndpointClass

logger = logging.getLogger(__name__)
tracer = get_tracer()


class EnrichmentException(BaseAppException):
    """Raised when telemetry or threat context enrichment fails."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="ENRICHMENT_ERROR",
            status_code=500,
            context=context,
        )


@dataclass(frozen=True)
class EnrichedContextBundle:
    """Read-only bundle passed into Jinja2 narrative templates."""

    assessment: dict[str, Any]
    detection: dict[str, Any]
    investigation: dict[str, Any]
    analyst_override: dict[str, Any] | None
    threat_intel_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TelemetryEnrichmentAgent:
    """
    Coordinates asynchronous context resolution across PostgreSQL, Redis,
    and OpenSearch to build unified, read-only audit payloads for downstream LLMs.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        redis_client: aioredis.Redis | None = None,
        opensearch_client: AsyncOpenSearch | None = None,
    ) -> None:
        self.db = db_session
        self.redis = redis_client
        self.opensearch = opensearch_client

    async def build_context_bundle(
        self, assessment_id: UUID
    ) -> EnrichedContextBundle:
        """
        Gathers immutable assessment state, associated detection signals,
        investigation telemetry, and external indicator context.
        """
        with tracer.start_as_current_span("enrichment_agent.build_context_bundle") as span:
            span.set_attribute("assessment_id", str(assessment_id))

            # 1. Fetch Primary Assessment Record
            stmt = select(RiskAssessmentModel).where(
                RiskAssessmentModel.assessment_id == assessment_id
            )
            result = await self.db.execute(stmt)
            assessment: RiskAssessmentModel | None = result.scalars().first()

            if assessment is None:
                raise EnrichmentException(
                    message=f"Assessment with ID {assessment_id} does not exist.",
                    context={"assessment_id": str(assessment_id)},
                )

            # 2. Fetch Associated Detection Record
            det_stmt = select(DetectionModel).where(
                DetectionModel.event_id == assessment.detection_event_id
            )
            det_result = await self.db.execute(det_stmt)
            detection: DetectionModel | None = det_result.scalars().first()

            if detection is None:
                raise EnrichmentException(
                    message=f"Detection event {assessment.detection_event_id} missing for assessment.",
                    context={"assessment_id": str(assessment_id)},
                )

            # 3. Fetch Investigation Record
            inv_stmt = (
                select(InvestigationModel)
                .where(InvestigationModel.detection_event_id == detection.event_id)
                .order_by(InvestigationModel.created_at.desc())
            )
            inv_result = await self.db.execute(inv_stmt)
            investigation: InvestigationModel | None = inv_result.scalars().first()

            # 4. Gather Threat Intelligence and Temporal Signals
            threat_intel = await self._resolve_threat_intel(detection.source_ip)

            # 5. Assemble Structured Context
            assessment_data = {
                "assessment_id": str(assessment.assessment_id),
                "correlation_id": str(assessment.correlation_id),
                "source_ip": assessment.source_ip,
                "risk_score": float(assessment.risk_score),
                "rating": assessment.rating.value,
                "components": {
                    "behavior": float(assessment.behavior_score),
                    "frequency": float(assessment.frequency_score),
                    "sensitivity": float(assessment.sensitivity_score),
                    "history": float(assessment.history_score),
                },
                "applied_policy": {
                    "policy_id": str(assessment.policy_id),
                    "version": assessment.applied_policy_snapshot.get("version", "UNKNOWN"),
                    "weights": assessment.applied_policy_snapshot.get("weights", {}),
                },
            }

            detection_data = {
                "event_id": str(detection.event_id),
                "rule_name": detection.rule_name,
                "rule_id": detection.rule_id,
                "source_type": detection.source_type.value,
                "severity": detection.severity.value,
                "confidence": float(detection.confidence),
                "fidelity": float(detection.fidelity) if detection.fidelity is not None else None,
                "hostname": detection.hostname,
                "destination_ip": detection.destination_ip,
                "raw_payload": detection.raw_payload,
                "context_data": detection.context_data,
            }

            investigation_data = {
                "event_frequency": investigation.event_frequency if investigation else 1,
                "endpoints_touched": investigation.endpoints_touched if investigation else 1,
                "dominant_endpoint_class": (
                    investigation.dominant_endpoint_class.value
                    if investigation
                    else EndpointClass.WORKSTATION.value
                ),
                "historical_incident_count": (
                    investigation.historical_incident_count if investigation else 0
                ),
                "severity_hint": (
                    float(investigation.severity_hint)
                    if investigation and investigation.severity_hint is not None
                    else None
                ),
                "touched_endpoints_detail": (
                    investigation.touched_endpoints_detail if investigation else []
                ),
            }

            override_data = None
            if assessment.override_score is not None:
                override_data = {
                    "is_overridden": True,
                    "original_score": float(assessment.risk_score),
                    "original_rating": assessment.rating.value,
                    "override_score": float(assessment.override_score),
                    "override_rating": (
                        assessment.override_rating.value
                        if assessment.override_rating
                        else assessment.rating.value
                    ),
                    "justification": assessment.override_justification or "",
                    "analyst_identity": assessment.overridden_by or "SYSTEM",
                    "overridden_at": (
                        assessment.overridden_at.isoformat()
                        if assessment.overridden_at
                        else None
                    ),
                }

            return EnrichedContextBundle(
                assessment=assessment_data,
                detection=detection_data,
                investigation=investigation_data,
                analyst_override=override_data,
                threat_intel_summary=threat_intel,
            )

    async def _resolve_threat_intel(self, source_ip: str) -> dict[str, Any]:
        """
        Queries Redis cache and OpenSearch indices to obtain historical
        indicator classifications and reputation summaries for the target IP.
        """
        intel_payload: dict[str, Any] = {
            "source_ip": source_ip,
            "is_known_malicious": False,
            "reputation_tags": [],
            "autonomous_system": None,
        }

        # 1. Redis Cache Query
        if self.redis is not None:
            try:
                cache_key = f"ti:{source_ip}"
                cached = await self.redis.hgetall(cache_key)
                if cached:
                    intel_payload["is_known_malicious"] = cached.get("malicious") == "true"
                    if "tags" in cached:
                        intel_payload["reputation_tags"] = cached["tags"].split(",")
                    intel_payload["autonomous_system"] = cached.get("asn")
                    return intel_payload
            except Exception as redis_err:
                logger.warning("Threat intel Redis cache lookup failed: %s", redis_err)

        # 2. OpenSearch Threat Feed Query
        if self.opensearch is not None:
            try:
                query = {
                    "query": {
                        "term": {"indicator.keyword": source_ip}
                    },
                    "size": 1,
                }
                res = await self.opensearch.search(index="threat-intel-indicators*", body=query)
                hits = res.get("hits", {}).get("hits", [])
                if hits:
                    source = hits[0].get("_source", {})
                    intel_payload["is_known_malicious"] = source.get("malicious", False)
                    intel_payload["reputation_tags"] = source.get("tags", [])
                    intel_payload["autonomous_system"] = source.get("asn")
            except Exception as os_err:
                logger.warning("Threat intel OpenSearch search failed: %s", os_err)

        return intel_payload