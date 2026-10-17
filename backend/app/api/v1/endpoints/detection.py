"""
Detection Ingestion and Query API Endpoints.
Implements POST /api/v1/detections for ingesting raw security detection events
and sliding-window counter updates, and GET /api/v1/detections/{event_id}
for event context lookups with strict RBAC scopes and OpenTelemetry tracing.
"""

from typing import Annotated, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, status
import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.exceptions import BaseAppException
from app.core.redis import get_redis_client
from app.core.security import TokenClaims, require_scopes
from app.core.telemetry import get_tracer
from app.db.models.detection import DetectionModel
from app.domain.models.enums import DetectionSeverity, DetectionSourceType
from app.schemas.detection import (
    DetectionCreateRequest,
    DetectionDetailResponse,
    DetectionResponse,
)

router = APIRouter()
tracer = get_tracer()


class DetectionNotFoundException(BaseAppException):
    """Raised when a specific detection event record cannot be retrieved."""

    def __init__(self, event_id: str) -> None:
        super().__init__(
            message=f"Detection event '{event_id}' could not be found.",
            error_code="DETECTION_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            context={"event_id": event_id},
        )


@router.post(
    "",
    response_model=DetectionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Security Detection Event",
    description=(
        "Ingests a raw detection signal, persists normalized detection context, "
        "and atomically updates Redis sliding-window event frequency counters."
    ),
)
async def ingest_detection_event(
    request: DetectionCreateRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[TokenClaims, Depends(require_scopes("detections:write"))],
) -> DetectionResponse:
    """
    Ingests and validates raw detection signals, maps normalized metadata,
    and increments Redis temporal counters for downstream sliding-window calculations.
    """
    with tracer.start_as_current_span("api.v1.endpoints.ingest_detection_event") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("correlation_id", str(request.correlation_id))
        span.set_attribute("source_ip", request.context.source_ip)
        span.set_attribute("rule_id", request.context.rule_id)

        event_id = request.event_id or uuid4()

        detection_record = DetectionModel(
            event_id=event_id,
            correlation_id=request.correlation_id,
            source_type=request.source_type,
            severity=request.severity,
            confidence=request.metrics.confidence,
            fidelity=request.metrics.fidelity,
            rule_id=request.context.rule_id,
            rule_name=request.context.rule_name,
            source_ip=request.context.source_ip,
            destination_ip=request.context.destination_ip,
            hostname=request.context.hostname,
            raw_payload=request.context.raw_payload,
            context_data=request.context.additional_attributes or {},
        )

        db.add(detection_record)
        await db.flush()

        # Update real-time sliding-window occurrence tracker in Redis
        try:
            window_seconds = 3600
            counter_key = f"counter:{request.context.source_ip}:events"
            now_ts = detection_record.detected_at.timestamp()

            async with redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(counter_key, "-inf", now_ts - window_seconds)
                pipe.zadd(counter_key, {str(event_id): now_ts})
                pipe.expire(counter_key, window_seconds * 2)
                await pipe.execute()
        except Exception as redis_err:
            span.record_exception(redis_err)

        return DetectionResponse.model_validate(detection_record)


@router.get(
    "/{event_id}",
    response_model=DetectionDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Detection Event by ID",
    description="Fetches a security detection record and its related contextual metadata.",
)
async def get_detection_by_id(
    event_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("detections:read"))],
) -> DetectionDetailResponse:
    """Retrieves full detection context and technical attributes by event UUID."""
    with tracer.start_as_current_span("api.v1.endpoints.get_detection_by_id") as span:
        span.set_attribute("event_id", str(event_id))
        span.set_attribute("actor_sub", claims.sub)

        stmt = select(DetectionModel).where(DetectionModel.event_id == event_id)
        result = await db.execute(stmt)
        record = result.scalars().first()

        if record is None:
            raise DetectionNotFoundException(event_id=str(event_id))

        return DetectionDetailResponse.model_validate(record)


@router.get(
    "",
    response_model=List[DetectionResponse],
    status_code=status.HTTP_200_OK,
    summary="List Detection Events",
    description="Queries detection events filtered dynamically by source IP, correlation ID, or severity.",
)
async def list_detections(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("detections:read"))],
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP address"),
    correlation_id: Optional[UUID] = Query(default=None, description="Filter by correlation ID"),
    severity: Optional[DetectionSeverity] = Query(default=None, description="Filter by detection severity"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> List[DetectionResponse]:
    """Queries paginated detection records based on dynamic search filters."""
    with tracer.start_as_current_span("api.v1.endpoints.list_detections") as span:
        span.set_attribute("actor_sub", claims.sub)

        stmt = select(DetectionModel)

        if source_ip is not None:
            stmt = stmt.where(DetectionModel.source_ip == source_ip)
        if correlation_id is not None:
            stmt = stmt.where(DetectionModel.correlation_id == correlation_id)
        if severity is not None:
            stmt = stmt.where(DetectionModel.severity == severity)

        stmt = stmt.order_by(DetectionModel.detected_at.desc()).limit(limit).offset(offset)
        result = await db.execute(stmt)
        records = result.scalars().all()

        return [DetectionResponse.model_validate(r) for r in records]