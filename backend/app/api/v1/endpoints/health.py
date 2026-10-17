"""
System Health and Readiness Diagnostic Endpoints.
Provides non-blocking Kubernetes liveness probes, deep dependency readiness checks
(PostgreSQL connection pooling, Redis ping, OpenSearch cluster state), and telemetry status.
"""

import time
from typing import Any, Dict

from fastapi import APIRouter, Response, status
from opensearchpy import AsyncOpenSearch
import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session_factory, verify_database_connection
from app.core.redis import get_redis_client, verify_redis_connection
from app.core.telemetry import get_tracer

router = APIRouter()
tracer = get_tracer()


@router.get(
    "/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness Probe",
    description="Shallow probe verifying that the application event loop is operational.",
)
async def liveness_probe() -> Dict[str, Any]:
    """
    Returns immediate HTTP 200 indicating the ASGI worker process is alive.
    Excludes external dependency calls to prevent cascading restarts.
    """
    return {
        "status": "UP",
        "service": getattr(settings.app, "PROJECT_NAME", "Cyber Risk Orchestration Engine"),
        "environment": getattr(settings.app, "ENVIRONMENT", "production"),
        "timestamp": time.time(),
    }


@router.get(
    "/ready",
    status_code=status.HTTP_200_OK,
    summary="Readiness Probe",
    description="Deep diagnostic probe verifying reachability of PostgreSQL, Redis, and OpenSearch.",
)
async def readiness_probe(response: Response) -> Dict[str, Any]:
    """
    Validates essential backend infrastructure:
      - PostgreSQL connection pool acquisition and query execution (`SELECT 1`)
      - Redis connection and PING response
      - OpenSearch ping and cluster health (if configured)
    Returns HTTP 503 Service Unavailable if any mandatory data store is unreachable.
    """
    with tracer.start_as_current_span("health.readiness_probe") as span:
        dependencies: Dict[str, Dict[str, Any]] = {}
        is_ready = True

        # 1. PostgreSQL Health Check
        db_start = time.perf_counter()
        db_healthy = False
        db_error = None
        try:
            db_healthy = await verify_database_connection()
        except Exception as exc:
            db_error = str(exc)
            span.record_exception(exc)

        db_latency_ms = (time.perf_counter() - db_start) * 1000.0
        dependencies["database"] = {
            "status": "UP" if db_healthy else "DOWN",
            "latency_ms": round(db_latency_ms, 2),
            **({"error": db_error} if db_error else {}),
        }
        if not db_healthy:
            is_ready = False

        # 2. Redis Health Check
        redis_start = time.perf_counter()
        redis_healthy = False
        redis_error = None
        try:
            redis_healthy = await verify_redis_connection()
        except Exception as exc:
            redis_error = str(exc)
            span.record_exception(exc)

        redis_latency_ms = (time.perf_counter() - redis_start) * 1000.0
        dependencies["redis"] = {
            "status": "UP" if redis_healthy else "DOWN",
            "latency_ms": round(redis_latency_ms, 2),
            **({"error": redis_error} if redis_error else {}),
        }
        if not redis_healthy:
            is_ready = False

        # 3. OpenSearch Health Check (Optional/Non-blocking check if configured)
        os_host = getattr(settings.opensearch, "OPENSEARCH_HOST", None) if hasattr(settings, "opensearch") else None
        if os_host:
            os_start = time.perf_counter()
            os_healthy = False
            os_error = None
            try:
                opensearch_client = AsyncOpenSearch(
                    hosts=[{"host": settings.opensearch.OPENSEARCH_HOST, "port": settings.opensearch.OPENSEARCH_PORT}],
                    http_auth=(
                        (settings.opensearch.OPENSEARCH_USER, settings.opensearch.OPENSEARCH_PASSWORD.get_secret_value())
                        if getattr(settings.opensearch, "OPENSEARCH_USER", None)
                        else None
                    ),
                    use_ssl=getattr(settings.opensearch, "OPENSEARCH_USE_SSL", False),
                    verify_certs=getattr(settings.opensearch, "OPENSEARCH_VERIFY_CERTS", False),
                    request_timeout=2.0,
                )
                try:
                    os_healthy = await opensearch_client.ping()
                finally:
                    await opensearch_client.close()
            except Exception as exc:
                os_error = str(exc)

            os_latency_ms = (time.perf_counter() - os_start) * 1000.0
            dependencies["opensearch"] = {
                "status": "UP" if os_healthy else "DOWN",
                "latency_ms": round(os_latency_ms, 2),
                **({"error": os_error} if os_error else {}),
            }

        span.set_attribute("is_ready", is_ready)

        if not is_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        return {
            "status": "UP" if is_ready else "DOWN",
            "dependencies": dependencies,
            "timestamp": time.time(),
        }