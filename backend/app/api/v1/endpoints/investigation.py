"""
Security Investigation and Asset Reconnaissance API Endpoints.
Implements POST /api/v1/investigations for ingesting correlated investigation telemetry,
GET /api/v1/investigations/{investigation_id} for investigation forensic lookups,
and GET /api/v1/investigations/correlation/{correlation_id} with strict RBAC enforcement,
OpenTelemetry distributed tracing, and transactional DB persistence.
"""

from typing import Annotated
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Header, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.exceptions import IdempotencyConflictException
from app.core.redis import get_redis_client
from app.core.security import TokenClaims, require_scopes
from app.core.telemetry import get_tracer
from app.db.models.investigation import InvestigationModel
from app.domain.models.enums import EndpointClass
from app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationDetailResponse,
    InvestigationResponse,
)
from app.services.investigation_service import (
    InvestigationNotFoundException,
    InvestigationOrchestrationService,
)

router = APIRouter()
tracer = get_tracer()


@router.post(
    "",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Investigation Telemetry",
    description=(
        "Persists forensic investigation telemetry, reconciles multi-host spread, "
        "and enriches event metrics against Redis sliding windows and threat records."
    ),
)
async def ingest_investigation_telemetry(
    request: InvestigationCreateRequest,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[TokenClaims, Depends(require_scopes("investigations:write"))],
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            description="Unique token preventing duplicate ingestion of identical investigation",
        ),
    ] = None,
) -> InvestigationResponse:
    """
    Ingests correlated investigation telemetry, updates asset footprint parameters,
    and returns the normalized investigation record with idempotency protection.
    """
    with tracer.start_as_current_span("api.v1.endpoints.ingest_investigation_telemetry") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("correlation_id", str(request.correlation_id))
        span.set_attribute("detection_event_id", str(request.detection_event_id))

        # Idempotency check
        redis_lock_key = f"idemp:inv:{idempotency_key}" if idempotency_key else None
        lock_acquired = False

        if redis_lock_key:
            span.set_attribute("idempotency_key", idempotency_key)
            acquired = await redis.set(redis_lock_key, "PROCESSING", ex=60, nx=True)
            if not acquired:
                cached_payload = await redis.get(redis_lock_key)
                if cached_payload and cached_payload != "PROCESSING":
                    response.status_code = status.HTTP_200_OK
                    return InvestigationResponse.model_validate_json(cached_payload)
                raise IdempotencyConflictException(idempotency_key=str(idempotency_key))
            lock_acquired = True

        try:
            investigation_service = InvestigationOrchestrationService(
                db_session=db,
                redis_client=redis,
            )

            result: InvestigationResponse = await investigation_service.ingest_investigation(
                request=request,
                actor_identifier=claims.preferred_username or claims.sub,
            )

            if redis_lock_key and lock_acquired:
                await redis.set(redis_lock_key, result.model_dump_json(), ex=3600)

            return result

        except Exception:
            if redis_lock_key and lock_acquired:
                await redis.delete(redis_lock_key)
            raise


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Investigation by ID",
    description="Fetches an investigation record, detailed touched endpoints, and metadata context by UUID.",
)
async def get_investigation_by_id(
    investigation_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("investigations:read"))],
) -> InvestigationDetailResponse:
    """Retrieves full investigation telemetry context by primary key."""
    with tracer.start_as_current_span("api.v1.endpoints.get_investigation_by_id") as span:
        span.set_attribute("investigation_id", str(investigation_id))
        span.set_attribute("actor_sub", claims.sub)

        stmt = select(InvestigationModel).where(
            InvestigationModel.investigation_id == investigation_id
        )
        result = await db.execute(stmt)
        record = result.scalars().first()

        if record is None:
            raise InvestigationNotFoundException(identifier=str(investigation_id))

        return InvestigationDetailResponse.model_validate(record)


@router.get(
    "/correlation/{correlation_id}",
    response_model=InvestigationDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Investigation by Correlation ID",
    description="Fetches the most recent correlated investigation telemetry associated with an incident correlation UUID.",
)
async def get_investigation_by_correlation_id(
    correlation_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("investigations:read"))],
) -> InvestigationDetailResponse:
    """Retrieves correlated investigation telemetry by correlation tracking UUID."""
    with tracer.start_as_current_span("api.v1.endpoints.get_investigation_by_correlation_id") as span:
        span.set_attribute("correlation_id", str(correlation_id))
        span.set_attribute("actor_sub", claims.sub)

        stmt = (
            select(InvestigationModel)
            .where(InvestigationModel.correlation_id == correlation_id)
            .order_by(InvestigationModel.created_at.desc())
        )
        result = await db.execute(stmt)
        record = result.scalars().first()

        if record is None:
            raise InvestigationNotFoundException(identifier=str(correlation_id))

        return InvestigationDetailResponse.model_validate(record)


@router.get(
    "",
    response_model=list[InvestigationResponse],
    status_code=status.HTTP_200_OK,
    summary="List Investigations",
    description="Queries paginated investigation records filtered by dominant asset class or compromise status.",
)
async def list_investigations(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("investigations:read"))],
    dominant_class: EndpointClass | None = Query(
        default=None, description="Filter by dominant touched endpoint classification"
    ),
    min_frequency: int | None = Query(
        default=None, ge=0, description="Filter by minimum event recurrence threshold"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[InvestigationResponse]:
    """Queries paginated investigation records based on dynamic search criteria."""
    with tracer.start_as_current_span("api.v1.endpoints.list_investigations") as span:
        span.set_attribute("actor_sub", claims.sub)

        stmt = select(InvestigationModel)

        if dominant_class is not None:
            stmt = stmt.where(InvestigationModel.dominant_endpoint_class == dominant_class)
        if min_frequency is not None:
            stmt = stmt.where(InvestigationModel.event_frequency >= min_frequency)

        stmt = stmt.order_by(InvestigationModel.created_at.desc()).limit(limit).offset(offset)
        result = await db.execute(stmt)
        records = result.scalars().all()

        return [InvestigationResponse.model_validate(r) for r in records]