"""
Risk Policy Management API Endpoints.
Implements policy lifecycle routes including active policy resolution, version lookups,
policy registration with mathematical weight validation, activation state toggles,
and non-invariance policy updates with strict RBAC enforcement.
"""

from typing import Annotated
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.redis import get_redis_client
from app.core.security import TokenClaims, require_roles, require_scopes
from app.core.telemetry import get_tracer
from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyResponse,
    PolicyUpdateRequest,
)
from app.services.policy_service import PolicyManagementService

router = APIRouter()
tracer = get_tracer()


@router.get(
    "/active",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Active Risk Policy",
    description="Fetches the currently authoritative and active risk policy configuration.",
)
async def get_active_policy(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[TokenClaims, Depends(require_scopes("policies:read"))],
) -> PolicyResponse:
    """Returns the current active risk calculation policy."""
    with tracer.start_as_current_span("api.v1.endpoints.get_active_policy") as span:
        span.set_attribute("actor_sub", claims.sub)
        service = PolicyManagementService(db_session=db, redis_client=redis)
        return await service.get_active_policy()


@router.get(
    "/version/{version}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Policy by Version",
    description="Fetches a specific immutable risk policy snapshot by its version string.",
)
async def get_policy_by_version(
    version: str,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("policies:read"))],
) -> PolicyResponse:
    """Retrieves a policy definition by version tag."""
    with tracer.start_as_current_span("api.v1.endpoints.get_policy_by_version") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("policy_version", version)
        service = PolicyManagementService(db_session=db)
        return await service.get_policy_by_version(version=version)


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Policy by ID",
    description="Fetches a specific risk policy record by its unique identifier.",
)
async def get_policy_by_id(
    policy_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("policies:read"))],
) -> PolicyResponse:
    """Retrieves a policy definition by primary UUID."""
    with tracer.start_as_current_span("api.v1.endpoints.get_policy_by_id") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("policy_id", str(policy_id))
        service = PolicyManagementService(db_session=db)
        return await service.get_policy_by_id(policy_id=policy_id)


@router.get(
    "",
    response_model=list[PolicyResponse],
    status_code=status.HTTP_200_OK,
    summary="List Risk Policies",
    description="Queries paginated risk policies with optional filtering for inactive entries.",
)
async def list_policies(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    claims: Annotated[TokenClaims, Depends(require_scopes("policies:read"))],
    include_inactive: bool = Query(
        default=False, description="Whether to include deactivated historical policies"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[PolicyResponse]:
    """Lists registered risk policies in descending chronological order."""
    with tracer.start_as_current_span("api.v1.endpoints.list_policies") as span:
        span.set_attribute("actor_sub", claims.sub)
        service = PolicyManagementService(db_session=db)
        return await service.list_policies(
            include_inactive=include_inactive,
            limit=limit,
            offset=offset,
        )


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Risk Policy",
    description=(
        "Registers a new risk policy configuration. Validates continuous boundary tiers "
        "and ensures weights sum to exactly 1.00. Restricted to security administrators."
    ),
)
async def create_policy(
    request: PolicyCreateRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[
        TokenClaims,
        Depends(require_scopes("policies:admin")),
        Depends(require_roles("ROLE_SECURITY_ADMIN")),
    ],
) -> PolicyResponse:
    """Registers and validates a new versioned risk scoring policy."""
    with tracer.start_as_current_span("api.v1.endpoints.create_policy") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("new_policy_version", request.version)
        service = PolicyManagementService(db_session=db, redis_client=redis)
        return await service.create_policy(
            request=request,
            actor_identifier=claims.preferred_username or claims.sub,
        )


@router.post(
    "/{version}/activate",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Activate Risk Policy Version",
    description="Promotes a specific policy version to active status and deactivates any existing active policy.",
)
async def activate_policy(
    version: str,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[
        TokenClaims,
        Depends(require_scopes("policies:admin")),
        Depends(require_roles("ROLE_SECURITY_ADMIN")),
    ],
) -> PolicyResponse:
    """Activates the specified policy version atomically within a transaction."""
    with tracer.start_as_current_span("api.v1.endpoints.activate_policy") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("target_policy_version", version)
        service = PolicyManagementService(db_session=db, redis_client=redis)
        return await service.activate_policy(version=version)


@router.patch(
    "/{version}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Risk Policy Metadata",
    description="Modifies non-scoring metadata attributes (such as description and custom tags) of a policy.",
)
async def update_policy(
    version: str,
    request: PolicyUpdateRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    claims: Annotated[
        TokenClaims,
        Depends(require_scopes("policies:admin")),
        Depends(require_roles("ROLE_SECURITY_ADMIN")),
    ],
) -> PolicyResponse:
    """Updates mutable metadata elements of a registered policy version."""
    with tracer.start_as_current_span("api.v1.endpoints.update_policy") as span:
        span.set_attribute("actor_sub", claims.sub)
        span.set_attribute("target_policy_version", version)
        service = PolicyManagementService(db_session=db, redis_client=redis)
        return await service.update_policy(version=version, request=request)
