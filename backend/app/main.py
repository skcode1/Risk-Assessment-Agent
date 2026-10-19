"""
Application entrypoint and factory module.
Configures FastAPI lifecycle, connection pools, Prometheus metrics,
CORS security policies, distributed tracing, rate limiting, and system health probes.
"""

import logging
import os
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import (
    close_db_engine,
    init_db_engine,
    verify_database_connection,
)
from app.core.exceptions import register_exception_handlers
from app.core.redis import (
    close_redis_client,
    init_redis_client,
    verify_redis_connection,
)
from app.core.telemetry import setup_telemetry

logger = logging.getLogger(__name__)

# Rate limiter instance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
)


def _parse_allowed_origins() -> list[str]:
    """
    Parses allowed CORS origins dynamically from the ALLOWED_ORIGINS
    environment variable or application settings.
    """
    raw_origins = os.getenv("ALLOWED_ORIGINS", "")
    if raw_origins:
        return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

    configured = getattr(settings.app, "ALLOWED_ORIGINS", None)
    if isinstance(configured, list):
        return configured
    if isinstance(configured, str) and configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]

    return ["*"]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application startup and teardown lifecycles.
    Initializes PostgreSQL and Redis connection pools and cleanly disposes
    of resources on termination.
    """
    logger.info("Initializing cyber risk engine application dependencies...")

    await init_db_engine()
    await init_redis_client()

    logger.info(
        "Application dependencies and network connection pools successfully established."
    )

    yield

    logger.info("Commencing application graceful shutdown...")

    await close_redis_client()
    await close_db_engine()

    logger.info("All connection pools cleanly closed. Shutdown complete.")


def create_app() -> FastAPI:
    """
    Constructs, configures, and returns a production-grade FastAPI instance.
    """
    is_debug = getattr(settings.app, "DEBUG", False) or os.getenv(
        "ENVIRONMENT", ""
    ).lower() in ("dev", "development")

    app = FastAPI(
        title=getattr(settings.app, "PROJECT_NAME", "Cyber Risk Orchestration Engine"),
        version=getattr(settings.app, "VERSION", "1.0.0"),
        docs_url="/docs" if is_debug else None,
        redoc_url="/redoc" if is_debug else None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = (time.perf_counter() - start_time) * 1000.0

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = f"{process_time:.2f}"
        return response

    allowed_origins = _parse_allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time-MS"],
    )

    # Always initialize telemetry; OTEL_EXPORTER_OTLP_ENDPOINT configures the exporter
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    try:
        setup_telemetry(app=app, otlp_endpoint=otlp_endpoint)
        if otlp_endpoint:
            logger.info(
                "OpenTelemetry tracing registered for endpoint: %s", otlp_endpoint
            )
        else:
            logger.info(
                "OpenTelemetry tracing initialized (no OTLP exporter configured)"
            )
    except Exception as exc:
        logger.warning("Telemetry setup deferred or skipped: %s", exc)

    register_exception_handlers(app)

    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=[
            "/health/live",
            "/health/ready",
            "/api/v1/health/liveness",
            "/api/v1/health/readiness",
            "/metrics",
        ],
    )
    instrumentator.instrument(app).expose(
        app, endpoint="/metrics", include_in_schema=False
    )

    @app.get(
        "/health/live",
        tags=["System Diagnostics & Readiness"],
        summary="Liveness Probe",
    )
    @app.get("/api/v1/health/liveness", include_in_schema=False)
    @limiter.limit("100/minute")
    async def health_live(request: Request) -> dict:
        return {
            "status": "UP",
            "timestamp": time.time(),
        }

    @app.get(
        "/health/ready",
        tags=["System Diagnostics & Readiness"],
        summary="Readiness Probe",
    )
    @app.get("/api/v1/health/readiness", include_in_schema=False)
    @limiter.limit("30/minute")
    async def health_ready(request: Request) -> JSONResponse:
        db_healthy = await verify_database_connection()
        redis_healthy = await verify_redis_connection()

        is_ready = db_healthy and redis_healthy
        response_payload = {
            "status": "UP" if is_ready else "DOWN",
            "dependencies": {
                "database": "UP" if db_healthy else "DOWN",
                "redis": "UP" if redis_healthy else "DOWN",
            },
            "timestamp": time.time(),
        }

        return JSONResponse(
            status_code=status.HTTP_200_OK
            if is_ready
            else status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response_payload,
        )

    # Mount API under /v1 prefix (standard API & Test Suite)
    app.include_router(api_router, prefix="/v1")

    return app


app = create_app()
