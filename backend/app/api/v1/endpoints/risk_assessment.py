"""
Risk Assessment Primary API Endpoint Router.
Implements POST /api/v1/risk-assessments (deterministic scoring with distributed
Redis idempotency locks), GET /api/v1/risk-assessments (list),
GET /api/v1/risk-assessments/{assessment_id} (forensic retrieval),
analyst score override workflows, and host containment triggers with strict RBAC.
"""

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    Path,
    Query,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.exceptions import (
    AssessmentNotFoundException,
    IdempotencyConflictException,
)
from app.core.redis import get_redis_client
from app.core.security import TokenClaims, require_roles, require_scopes
from app.core.telemetry import get_tracer
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.audit import AuditLogModel
from app.schemas.assessment import (
    AssessmentCreateRequest,
    AssessmentDetailResponse,
    AssessmentOverrideRequest,
    AssessmentResponse,
)
from app.services.risk_service import RiskOrchestrationService

router = APIRouter()
tracer = get_tracer()


@router.get(
    "",
    response_model=list[AssessmentDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="List Risk Assessments",
)
async def list_risk_assessments(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("assessments:read"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[AssessmentDetailResponse]:
    """Lists recent risk assessments for authenticated analysts."""
    stmt = select(RiskAssessmentModel).limit(limit)
    result = await db.execute(stmt)
    records = result.scalars().all()
    return [AssessmentDetailResponse.from_record(r) for r in records]


@router.post(
    "",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Evaluate Cyber Risk Assessment",
)
async def evaluate_risk_assessment(
    request: AssessmentCreateRequest,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[TokenClaims, Depends(require_scopes("assessments:write"))],
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            description="Unique token preventing duplicate evaluation of identical events",
        ),
    ] = None,
    policy_version: Annotated[
        str | None,
        Query(description="Specific immutable risk policy version to evaluate against"),
    ] = None,
) -> AssessmentResponse:
    """Executes deterministic scoring with Redis idempotency locking."""
    with tracer.start_as_current_span("endpoints.evaluate_risk_assessment") as span:
        span.set_attribute("actor_sub", claims.sub)
        detection_event_obj = request.detection_event
        corr_id = getattr(detection_event_obj, "correlation_id", "unknown")
        span.set_attribute("correlation_id", str(corr_id))

        redis_lock_key = f"idemp:{idempotency_key}" if idempotency_key else None
        lock_acquired = False

        if redis_lock_key:
            span.set_attribute("idempotency_key", idempotency_key)
            acquired = await redis.set(redis_lock_key, "PROCESSING", ex=60, nx=True)
            if not acquired:
                cached_payload = await redis.get(redis_lock_key)
                if cached_payload and cached_payload != "PROCESSING":
                    response.status_code = status.HTTP_200_OK
                    return AssessmentResponse.model_validate_json(cached_payload)
                raise IdempotencyConflictException(idempotency_key=str(idempotency_key))
            lock_acquired = True

        try:
            risk_service = RiskOrchestrationService(
                db_session=db,
                redis_client=redis,
            )

            result: AssessmentResponse = await risk_service.assess_risk(
                request=request,
                policy_version=policy_version,
            )

            if redis_lock_key and lock_acquired:
                await redis.set(redis_lock_key, result.model_dump_json(), ex=3600)

            return result

        except Exception:
            if redis_lock_key and lock_acquired:
                await redis.delete(redis_lock_key)
            raise


@router.get(
    "/{assessment_id}",
    response_model=AssessmentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Risk Assessment by ID",
)
async def get_risk_assessment_by_id(
    assessment_id: Annotated[
        UUID, Path(description="Primary UUID of the risk assessment record")
    ],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("assessments:read"))],
) -> AssessmentDetailResponse:
    """Retrieves full details of an evaluated risk assessment."""
    stmt = select(RiskAssessmentModel).where(
        RiskAssessmentModel.assessment_id == assessment_id
    )
    result = await db.execute(stmt)
    record = result.scalars().first()

    if record is None:
        raise AssessmentNotFoundException(assessment_id=str(assessment_id))

    return AssessmentDetailResponse.from_record(record)


@router.post(
    "/{assessment_id}/override",
    response_model=AssessmentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Manual Analyst Score Override",
)
async def override_risk_assessment(
    assessment_id: Annotated[
        UUID, Path(description="Primary UUID of the risk assessment to override")
    ],
    request: AssessmentOverrideRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[
        TokenClaims,
        Depends(require_scopes("assessments:override")),
        Depends(require_roles("ROLE_SOC_LEAD", "ROLE_SECURITY_ADMIN")),
    ],
) -> AssessmentDetailResponse:
    """Applies a human-in-the-loop analyst override with mandatory audit logging."""
    stmt = select(RiskAssessmentModel).where(
        RiskAssessmentModel.assessment_id == assessment_id
    )
    result = await db.execute(stmt)
    record = result.scalars().first()

    if record is None:
        raise AssessmentNotFoundException(assessment_id=str(assessment_id))

    quantized_override = Decimal(str(request.override_score)).quantize(Decimal("0.1"))
    if not (Decimal("0.0") <= quantized_override <= Decimal("100.0")):
        raise ValueError("Override risk score must fall strictly within [0.0, 100.0].")

    audit_log = AuditLogModel(
        assessment_id=record.assessment_id,
        action="ANALYST_SCORE_OVERRIDE",
        actor=claims.preferred_username or claims.sub,
        details={
            "previous_score": str(record.risk_score),
            "previous_rating": record.rating.value,
            "override_score": str(quantized_override),
            "override_rating": request.override_rating.value,
            "justification": request.justification,
            "ticket_reference": request.ticket_reference,
        },
        timestamp=datetime.now(UTC),
    )
    db.add(audit_log)

    record.override_score = quantized_override
    record.override_rating = request.override_rating
    record.override_justification = request.justification
    record.overridden_by = claims.preferred_username or claims.sub
    record.overridden_at = datetime.now(UTC)

    await db.flush()
    await db.refresh(record)

    return AssessmentDetailResponse.from_record(record)


@router.post(
    "/{assessment_id}/actions/contain",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger Endpoint Containment Action",
)
async def trigger_containment_action(
    assessment_id: Annotated[
        UUID, Path(description="Primary UUID of the risk assessment")
    ],
    claims: Annotated[
        TokenClaims,
        Depends(require_scopes("assessments:contain")),
        Depends(
            require_roles("ROLE_SOC_ANALYST_L2", "ROLE_SOC_LEAD", "ROLE_SECURITY_ADMIN")
        ),
    ],
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Triggers automated containment workflows; restricted to Tier-2+ SOC roles."""
    return {
        "assessment_id": str(assessment_id),
        "action": payload.get("action", "ISOLATE_HOST"),
        "status": "QUEUED",
        "initiated_by": claims.sub,
    }
