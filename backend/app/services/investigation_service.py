import logging
import time
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as aioredis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from opensearchpy import AsyncOpenSearch
except ImportError:
    try:
        from opensearchpy._async.client import AsyncOpenSearch
    except ImportError:
        # Fallback stub for environments running without OpenSearch client installed
        AsyncOpenSearch = None

from app.core.exceptions import BaseAppException
from app.core.telemetry import get_tracer
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.detection import DetectionModel
from app.db.models.investigation import InvestigationModel
from app.domain.models.detection import DetectionEvent
from app.domain.models.enums import EndpointClass, RiskCategory
from app.domain.models.investigation import (
    InvestigationResult,
    InvestigationTelemetry,
    TouchedEndpoint,
)
from app.domain.models.policy import RiskPolicy
from app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationResponse,
    TouchedEndpointSchema,
)

logger = logging.getLogger(__name__)
tracer = get_tracer()


class InvestigationNotFoundException(BaseAppException):
    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Investigation telemetry for identifier '{identifier}' was not found.",
            error_code="INVESTIGATION_NOT_FOUND",
            status_code=404,
            context={"identifier": identifier},
        )


class InvestigationOrchestrationService:
    def __init__(
        self,
        db_session: AsyncSession,
        redis_client: aioredis.Redis | None = None,
        opensearch_client: AsyncOpenSearch | None = None,
        sliding_window_seconds: int = 3600,
    ) -> None:
        self.db = db_session
        self.redis = redis_client
        self.opensearch = opensearch_client
        self.sliding_window_seconds = sliding_window_seconds

    async def ingest_investigation(
        self,
        request: InvestigationCreateRequest,
        actor_identifier: str | None = None,
    ) -> InvestigationResponse:

        with tracer.start_as_current_span(
            "investigation_service.ingest_investigation"
        ) as span:
            span.set_attribute("correlation_id", str(request.correlation_id))
            span.set_attribute("detection_event_id", str(request.detection_event_id))

            # Verify associated detection event exists
            det_stmt = select(DetectionModel).where(
                DetectionModel.event_id == request.detection_event_id
            )
            det_result = await self.db.execute(det_stmt)
            detection_record = det_result.scalars().first()

            source_ip = detection_record.source_ip if detection_record else None

            # Calculate enriched real-time frequencies and historical counts
            enriched_frequency = request.telemetry.event_frequency
            if self.redis is not None and source_ip:
                redis_count = await self._get_sliding_window_count(source_ip)
                enriched_frequency = max(enriched_frequency, redis_count)

            enriched_history = request.telemetry.historical_incident_count
            if source_ip:
                historical_count = await self._query_historical_incident_count(
                    source_ip
                )
                enriched_history = max(enriched_history, historical_count)

            touched_serialized = [
                {
                    "endpoint_id": ep.endpoint_id,
                    "endpoint_class": ep.endpoint_class.value,
                    "is_compromised": ep.is_compromised,
                }
                for ep in request.touched_endpoints_detail
            ]

            investigation_id = uuid4()
            model = InvestigationModel(
                investigation_id=investigation_id,
                detection_event_id=request.detection_event_id,
                correlation_id=request.correlation_id,
                event_frequency=enriched_frequency,
                endpoints_touched=request.telemetry.endpoints_touched,
                dominant_endpoint_class=request.telemetry.endpoint_class,
                historical_incident_count=enriched_history,
                severity_hint=request.telemetry.severity_hint,
                touched_endpoints_detail=touched_serialized,
                telemetry_metadata=request.telemetry_metadata or {},
                investigated_by=actor_identifier,
            )

            self.db.add(model)
            await self.db.flush()

            logger.info(
                "Ingested investigation_id=%s correlation_id=%s (freq=%d, history=%d)",
                investigation_id,
                request.correlation_id,
                enriched_frequency,
                enriched_history,
            )

            return self._model_to_response(model)

    async def build_investigation_domain(
        self,
        detection: DetectionEvent,
        base_telemetry: InvestigationTelemetry | None = None,
        touched_endpoints: list[TouchedEndpoint] | None = None,
    ) -> InvestigationResult:
        """
        Assembles a fully hydrated, pure domain InvestigationResult for a detection event
        by reconciling provided metrics with Redis and OpenSearch/PostgreSQL telemetry.
        """
        with tracer.start_as_current_span(
            "investigation_service.build_investigation_domain"
        ):
            source_ip = detection.context.source_ip

            # 1. Resolve event frequency via Redis sliding window
            base_frequency = base_telemetry.event_frequency if base_telemetry else 1
            if self.redis is not None:
                realtime_freq = await self._get_sliding_window_count(source_ip)
                resolved_frequency = max(base_frequency, realtime_freq)
            else:
                resolved_frequency = base_frequency

            # 2. Resolve historical incidents across data tiers
            base_history = (
                base_telemetry.historical_incident_count if base_telemetry else 0
            )
            retrieved_history = await self._query_historical_incident_count(source_ip)
            resolved_history = max(base_history, retrieved_history)

            # 3. Determine dominant endpoint classification
            endpoints = touched_endpoints or []
            if base_telemetry and base_telemetry.endpoint_class:
                dominant_class = base_telemetry.endpoint_class
            elif endpoints:
                dominant_class = self._determine_dominant_endpoint_class(endpoints)
            else:
                dominant_class = EndpointClass.WORKSTATION

            # 4. Synthesize final investigation telemetry
            telemetry = InvestigationTelemetry(
                event_frequency=resolved_frequency,
                endpoints_touched=len(endpoints)
                if endpoints
                else (base_telemetry.endpoints_touched if base_telemetry else 1),
                endpoint_class=dominant_class,
                historical_incident_count=resolved_history,
                severity_hint=base_telemetry.severity_hint if base_telemetry else None,
            )

            return InvestigationResult(
                detection_event_id=detection.event_id,
                correlation_id=detection.correlation_id,
                telemetry=telemetry,
                touched_endpoints=endpoints,
            )

    async def get_investigation_by_id(
        self, investigation_id: UUID
    ) -> InvestigationResponse:
        """Retrieves investigation record by UUID."""
        with tracer.start_as_current_span("investigation_service.get_by_id"):
            stmt = select(InvestigationModel).where(
                InvestigationModel.investigation_id == investigation_id
            )
            result = await self.db.execute(stmt)
            model = result.scalars().first()

            if model is None:
                raise InvestigationNotFoundException(identifier=str(investigation_id))

            return self._model_to_response(model)

    async def get_investigation_by_correlation_id(
        self, correlation_id: UUID
    ) -> InvestigationResponse | None:
        """Retrieves investigation telemetry associated with a correlation identifier."""
        with tracer.start_as_current_span(
            "investigation_service.get_by_correlation_id"
        ):
            stmt = (
                select(InvestigationModel)
                .where(InvestigationModel.correlation_id == correlation_id)
                .order_by(InvestigationModel.created_at.desc())
            )
            result = await self.db.execute(stmt)
            model = result.scalars().first()

            if model is None:
                return None

            return self._model_to_response(model)

    # --- Internal Reconnaissance & Telemetry Queries ---

    async def _get_sliding_window_count(self, source_ip: str) -> int:
        """Queries Redis for events recorded within the active sliding window interval."""
        if self.redis is None:
            return 0

        try:
            key = f"counter:{source_ip}:events"
            now = time.time()
            cutoff = now - self.sliding_window_seconds

            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, "-inf", cutoff)
                pipe.zcard(key)
                results = await pipe.execute()

            return int(results[1])
        except Exception as exc:
            logger.warning(
                "Failed to retrieve sliding window counter from Redis: %s", exc
            )
            return 0

    async def _query_historical_incident_count(self, source_ip: str) -> int:
        """
        Executes an OpenSearch aggregation query to fetch confirmed previous incidents,
        falling back to PostgreSQL relational store if OpenSearch is unreachable.
        """
        if self.opensearch is not None:
            try:
                search_query: dict[str, Any] = {
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"source_ip.keyword": source_ip}},
                                {
                                    "terms": {
                                        "rating.keyword": [
                                            RiskCategory.HIGH.value,
                                            RiskCategory.CRITICAL.value,
                                        ]
                                    }
                                },
                            ]
                        }
                    }
                }
                response = await self.opensearch.count(
                    index="security-events*",
                    body=search_query,
                )
                return int(response.get("count", 0))
            except Exception as os_err:
                logger.warning(
                    "OpenSearch lookup for IP %s failed; executing database fallback: %s",
                    source_ip,
                    os_err,
                )

        # Fallback to PostgreSQL
        stmt = (
            select(func.count(RiskAssessmentModel.assessment_id))
            .where(RiskAssessmentModel.source_ip == source_ip)
            .where(
                RiskAssessmentModel.rating.in_(
                    [RiskCategory.HIGH, RiskCategory.CRITICAL]
                )
            )
        )
        result = await self.db.execute(stmt)
        return int(result.scalar_one() or 0)

    def _determine_dominant_endpoint_class(
        self,
        endpoints: list[TouchedEndpoint],
        policy: RiskPolicy | None = None,
    ) -> EndpointClass:
        """
        Evaluates the highest-priority endpoint class across touched infrastructure.
        Prioritizes confirmed compromises and critical asset categories.

        Endpoint weights are resolved authoritatively from the active RiskPolicy
        via RiskPolicy.get_endpoint_weight(), falling back to the EndpointClass
        seed-data default_base_weight when no policy is supplied.
        """
        # Check for confirmed compromised assets first
        compromised = [ep for ep in endpoints if ep.is_compromised]
        target_group = compromised if compromised else endpoints

        best_class = EndpointClass.WORKSTATION
        highest_weight = Decimal(-1)

        for ep in target_group:
            if policy is not None:
                weight = policy.get_endpoint_weight(ep.endpoint_class)
            else:
                weight = Decimal(str(ep.endpoint_class.default_base_weight)).quantize(
                    Decimal("0.1"), rounding=ROUND_HALF_UP
                )
            if weight > highest_weight:
                highest_weight = weight
                best_class = ep.endpoint_class

        return best_class

    def _model_to_response(self, model: InvestigationModel) -> InvestigationResponse:
        """Serializes ORM InvestigationModel to API InvestigationResponse schema."""
        detail_items = [
            TouchedEndpointSchema(
                endpoint_id=item["endpoint_id"],
                endpoint_class=EndpointClass(item["endpoint_class"]),
                is_compromised=item["is_compromised"],
            )
            for item in model.touched_endpoints_detail
        ]

        return InvestigationResponse(
            investigation_id=model.investigation_id,
            detection_event_id=model.detection_event_id,
            correlation_id=model.correlation_id,
            event_frequency=model.event_frequency,
            endpoints_touched=model.endpoints_touched,
            dominant_endpoint_class=model.dominant_endpoint_class,
            historical_incident_count=model.historical_incident_count,
            severity_hint=float(model.severity_hint)
            if model.severity_hint is not None
            else None,
            touched_endpoints_detail=detail_items,
            telemetry_metadata=model.telemetry_metadata,
            investigated_by=model.investigated_by,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )
