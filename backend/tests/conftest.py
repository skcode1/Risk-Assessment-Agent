"""
Pytest Configuration and Shared Fixtures.
Provides async database session, Redis client, and dependency overrides for integration tests.
"""

import os
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

# Import ORM models so all tables and relationships are registered
import app.db.models.assessment
import app.db.models.audit
import app.db.models.detection
import app.db.models.explanation
import app.db.models.investigation
import app.db.models.policy  # noqa: F401

# Import ORM models so all tables and relationships are registered
from app.core.config import settings
from app.core.database import Base, get_db_session
from app.core.redis import get_redis_client

# ---------------------------------------------------------------------------
# Container fixtures (module-scoped for performance)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def postgres_container() -> PostgresContainer:
    """Provide a PostgreSQL container for integration tests."""
    container = PostgresContainer("postgres:16-alpine")
    container.start()
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="module")
def redis_container() -> RedisContainer:
    """Provide a Redis container for integration tests."""
    container = RedisContainer("redis:7.2-alpine")
    container.start()
    try:
        yield container
    finally:
        container.stop()


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


def _async_database_url(container: PostgresContainer) -> str:
    """Convert the Testcontainers PostgreSQL URL to the asyncpg driver URL."""
    url = container.get_connection_url()

    if url.startswith("postgresql+psycopg2://"):
        return url.replace(
            "postgresql+psycopg2://",
            "postgresql+asyncpg://",
            1,
        )

    if url.startswith("postgresql://"):
        return url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    if url.startswith("postgres://"):
        return url.replace(
            "postgres://",
            "postgresql+asyncpg://",
            1,
        )

    if not url.startswith("postgresql+asyncpg://"):
        raise ValueError(
            f"Unsupported PostgreSQL test URL scheme: {url.split('://')[0]}"
        )

    return url


@pytest_asyncio.fixture
async def async_db_session(
    postgres_container: PostgresContainer,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Create an isolated schema and seed an active policy for each test.
    """
    database_url = _async_database_url(postgres_container)
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
    )

    try:
        # Create the complete schema.
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

            # Create append-only trigger for audit_logs
            await connection.execute(
                text("""
                CREATE OR REPLACE FUNCTION trg_enforce_audit_logs_append_only()
                RETURNS TRIGGER LANGUAGE plpgsql AS $func$
                BEGIN
                    RAISE EXCEPTION 'audit_logs is an append-only ledger: % operations are prohibited', TG_OP
                    USING ERRCODE = '55000';
                END;
                $func$;
            """)
            )

            await connection.execute(
                text("""
                CREATE TRIGGER trg_audit_logs_append_only
                BEFORE UPDATE OR DELETE ON audit_logs
                FOR EACH ROW
                EXECUTE FUNCTION trg_enforce_audit_logs_append_only();
            """)
            )

        session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async with session_factory() as session:
            # Seed baseline policy
            from app.db.models.policy import PolicyModel
            from app.domain.models.policy import RiskPolicy

            domain_policy = RiskPolicy.create_spec_default(
                version="risk-policy-2026-01"
            )
            weights = domain_policy.weights
            thresholds = domain_policy.thresholds

            endpoint_class_weights = {
                endpoint_class.value: float(weight)
                for endpoint_class, weight in domain_policy.endpoint_class_weights.items()
            }

            policy_model = PolicyModel(
                name=domain_policy.name,
                version=domain_policy.version,
                description=domain_policy.description,
                is_active=True,
                weight_behavior=weights.behavior,
                weight_frequency=weights.frequency,
                weight_sensitivity=weights.sensitivity,
                weight_history=weights.history,
                thresholds_config=thresholds.to_dict(),
                endpoint_class_weights=endpoint_class_weights,
                metadata_info={
                    "seeded_by": "tests.conftest",
                    "authoritative_spec": True,
                },
                created_by="system:test",
                created_at=domain_policy.created_at,
                updated_at=domain_policy.updated_at,
            )

            session.add(policy_model)
            await session.commit()

            yield session

    finally:
        # Drop the schema and dispose of the engine even when a test fails.
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.drop_all)
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# Redis fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def async_redis(
    redis_container: RedisContainer,
) -> AsyncGenerator[aioredis.Redis, None]:
    """Provide a clean Redis client for each test."""
    client = aioredis.Redis(
        host=redis_container.get_container_host_ip(),
        port=int(redis_container.get_exposed_port(6379)),
        decode_responses=True,
    )

    try:
        await client.flushdb()
        yield client
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Dependency override fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def override_get_db_session(async_db_session: AsyncSession):
    """Override get_db_session dependency with test session."""

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        yield async_db_session

    return _override


@pytest.fixture
def override_get_redis_client(async_redis: aioredis.Redis):
    """Override get_redis_client dependency with test Redis client."""

    async def _override() -> AsyncGenerator[aioredis.Redis, None]:
        yield async_redis

    return _override


# ---------------------------------------------------------------------------
# Authenticated API client fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def api_client(
    override_get_db_session,
    override_get_redis_client,
):
    """
    Create an authenticated ASGI test client with isolated dependencies.
    """
    from datetime import UTC, datetime

    from httpx import ASGITransport, AsyncClient
    from jose import jwt

    from app.main import app

    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_redis_client] = override_get_redis_client

    now = datetime.now(UTC)

    # Use the secret from settings to ensure token validation works
    test_secret = settings.security.JWT_SECRET_KEY.get_secret_value()

    token = jwt.encode(
        {
            "sub": "00000000-0000-0000-0000-000000000001",
            "preferred_username": "integration_tester",
            "roles": [
                "ROLE_SECURITY_ADMIN",
                "ROLE_SOC_LEAD",
            ],
            "scope": (
                "assessments:read "
                "assessments:write "
                "assessments:override "
                "policies:read "
                "policies:admin"
            ),
            "iat": int(now.timestamp()),
            "exp": int(now.timestamp()) + 3600,
        },
        test_secret,
        algorithm=settings.security.JWT_ALGORITHM,
    )

    transport = ASGITransport(app=app)

    try:
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_env():
    """Ensure clean environment for each test."""
    # Clear test-specific env vars
    test_vars = [k for k in os.environ if k.startswith("TEST_")]
    old_values = {k: os.environ[k] for k in test_vars}
    for k in test_vars:
        del os.environ[k]

    yield

    # Restore
    for k, v in old_values.items():
        os.environ[k] = v


# ---------------------------------------------------------------------------
# Canonical test payload
# ---------------------------------------------------------------------------


@pytest.fixture
def canonical_spec_payload() -> dict[str, Any]:
    """Build the canonical risk-assessment request matching 6.3 spec."""
    from uuid import uuid4

    from app.domain.models.enums import (
        DetectionSeverity,
        DetectionSourceType,
        EndpointClass,
    )

    correlation_id = str(uuid4())
    event_id = str(uuid4())

    return {
        "detection_event": {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "source_type": DetectionSourceType.EDR.value,
            "severity": DetectionSeverity.HIGH.value,
            "metrics": {
                "confidence": 90.0,
                "fidelity": 1.0,
                "rule_accuracy_hint": 95.0,
            },
            "context": {
                "rule_id": "RULE-INTEG-001",
                "rule_name": "Credential Dumping Activity",
                "source_ip": "1.2.3.4",
            },
        },
        "investigation_result": {
            "detection_event_id": event_id,
            "correlation_id": correlation_id,
            "telemetry": {
                "event_frequency": 17,
                "endpoints_touched": 4,
                "endpoint_class": EndpointClass.DATABASE_SERVER.value,
                "historical_incident_count": 3,
                "severity_hint": 80.0,
            },
            "touched_endpoints_detail": [
                {
                    "endpoint_id": "SRV-DB-PROD-01",
                    "endpoint_class": EndpointClass.DATABASE_SERVER.value,
                    "is_compromised": True,
                }
            ],
        },
    }
