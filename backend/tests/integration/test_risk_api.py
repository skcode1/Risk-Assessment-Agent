
"""
Integration tests for the Risk Assessment API.

Covers:
- Canonical deterministic risk scoring
- Idempotent assessment creation
- Assessment persistence and retrieval
- Request validation
- Isolated PostgreSQL and Redis test dependencies

Run:
    OTEL_SDK_DISABLED=true pytest -v tests/integration/test_risk_api.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from fastapi.encoders import jsonable_encoder
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

# Import ORM models so all tables and relationships are registered
# before Base.metadata.create_all() is executed.
import app.db.models.assessment  # noqa: F401
import app.db.models.detection  # noqa: F401
import app.db.models.investigation  # noqa: F401

from app.core.config import settings
from app.core.database import Base, get_db_session
from app.core.redis import get_redis_client
from app.db.models.policy import PolicyModel
from app.domain.models.enums import (
    DetectionSeverity,
    DetectionSourceType,
    EndpointClass,
    RiskCategory,
)
from app.domain.models.policy import RiskPolicy
from app.main import app


BASELINE_POLICY_VERSION = "risk-policy-2026-01"


# ---------------------------------------------------------------------------
# Container fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def postgres_container() -> AsyncGenerator[PostgresContainer, None]:
    """Provide a PostgreSQL container for integration tests."""
    container = PostgresContainer("postgres:16-alpine")
    container.start()

    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="module")
def redis_container() -> AsyncGenerator[RedisContainer, None]:
    """Provide a Redis container for idempotency tests."""
    container = RedisContainer("redis:7.2-alpine")
    container.start()

    try:
        yield container
    finally:
        container.stop()


# ---------------------------------------------------------------------------
# Database fixture and baseline policy
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


def _build_baseline_policy_model() -> PolicyModel:
    """
    Convert the canonical domain policy into the SQLAlchemy persistence model.

    This creates the same baseline policy expected by the risk orchestration
    service without relying on the application's development database.
    """
    domain_policy = RiskPolicy.create_spec_default(
        version=BASELINE_POLICY_VERSION,
    )

    weights = domain_policy.weights
    thresholds = domain_policy.thresholds

    endpoint_class_weights = {
        endpoint_class.value: float(weight)
        for endpoint_class, weight in domain_policy.endpoint_class_weights.items()
    }

    return PolicyModel(
        name=domain_policy.name,
        version=domain_policy.version,
        description=domain_policy.description,
        is_active=True,
        weight_behavior=weights.behavior,
        weight_frequency=weights.frequency,
        weight_sensitivity=weights.sensitivity,
        weight_history=weights.history,
        thresholds_config=jsonable_encoder(thresholds.to_dict()),
        endpoint_class_weights=endpoint_class_weights,
        metadata_info={
            "seeded_by": "tests.integration.test_risk_api",
            "authoritative_spec": True,
        },
        created_by="system:test",
        created_at=domain_policy.created_at,
        updated_at=domain_policy.updated_at,
    )


@pytest_asyncio.fixture
async def async_db_session(
    postgres_container: PostgresContainer,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Create an isolated schema and seed an active policy for each test.

    The schema, policy, and API requests all use the same test engine.
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

        session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async with session_factory() as session:
            # Critical fix: the assessment service searches for an active
            # policy, so create one in THIS test database before each test.
            baseline_policy = _build_baseline_policy_model()
            session.add(baseline_policy)
            await session.commit()

            # Verify that the fixture established the required state.
            active_policy = await session.get(
                PolicyModel,
                baseline_policy.policy_id,
            )
            assert active_policy is not None, (
                "The baseline risk policy was not persisted."
            )
            assert active_policy.is_active is True
            assert active_policy.version == BASELINE_POLICY_VERSION

            yield session

    finally:
        # Drop the schema and dispose of the engine even when a test fails.
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.drop_all)
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# Redis fixture
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
# Authenticated API client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def api_client(
    async_db_session: AsyncSession,
    async_redis: aioredis.Redis,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Create an authenticated ASGI test client with isolated dependencies.

    Existing application dependency overrides are restored after each test
    instead of clearing unrelated overrides globally.
    """
    previous_overrides = app.dependency_overrides.copy()

    async def override_db_session() -> AsyncGenerator[AsyncSession, None]:
        yield async_db_session

    async def override_redis_client() -> AsyncGenerator[aioredis.Redis, None]:
        yield async_redis

    app.dependency_overrides[get_db_session] = override_db_session
    app.dependency_overrides[get_redis_client] = override_redis_client

    now = datetime.now(timezone.utc)

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
        settings.security.JWT_SECRET_KEY.get_secret_value(),
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
# Canonical request fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def canonical_spec_payload() -> dict[str, Any]:
    """
    Build the canonical risk-assessment request.

    Expected scoring inputs:
        behavior    = 90.0
        frequency   = 85.0
        sensitivity = 80.0
        history     = 60.0

    Expected result under the canonical scoring specification:
        risk_score = 83.5
        rating     = HIGH
    """
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


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRiskAssessmentApiEndpoints:
    """End-to-end tests for assessment creation, idempotency, and retrieval."""

    async def test_assess_risk_endpoint_canonical_score(
        self,
        api_client: AsyncClient,
        canonical_spec_payload: dict[str, Any],
    ) -> None:
        """Create an assessment and verify its canonical response."""
        response = await api_client.post(
            "/v1/risk-assessments",
            json=canonical_spec_payload,
            headers={"Idempotency-Key": f"idemp-{uuid4()}"},
        )

        assert response.status_code == 201, (
            f"Expected HTTP 201 when creating an assessment; "
            f"received HTTP {response.status_code}: {response.text}"
        )

        data = response.json()

        assert data["source_ip"] == "1.2.3.4"
        assert data["risk_score"] == 83.5
        assert data["rating"] == RiskCategory.HIGH.value

        components = data["components"]
        assert Decimal(str(components["behavior"])) == Decimal("90.0")
        assert Decimal(str(components["frequency"])) == Decimal("85.0")
        assert Decimal(str(components["sensitivity"])) == Decimal("80.0")
        assert Decimal(str(components["history"])) == Decimal("60.0")

        assert data.get("assessment_id"), (
            f"Response is missing assessment_id: {data}"
        )
        assert data.get("applied_policy"), (
            f"Response is missing applied_policy: {data}"
        )
        assert (
            data["applied_policy"]["version"] == BASELINE_POLICY_VERSION
        )

    async def test_idempotent_repeated_requests(
        self,
        api_client: AsyncClient,
        canonical_spec_payload: dict[str, Any],
    ) -> None:
        """
        Verify that the same idempotency key does not create a duplicate.

        The initial request should return 201. Replaying it should return 200
        and the same assessment identity and scoring result.
        """
        headers = {"Idempotency-Key": f"idemp-fixed-{uuid4()}"}

        response_one = await api_client.post(
            "/v1/risk-assessments",
            json=canonical_spec_payload,
            headers=headers,
        )

        assert response_one.status_code == 201, (
            f"Initial assessment failed: "
            f"HTTP {response_one.status_code}: {response_one.text}"
        )

        data_one = response_one.json()
        assert data_one.get("assessment_id"), (
            f"Initial response is missing assessment_id: {data_one}"
        )

        response_two = await api_client.post(
            "/v1/risk-assessments",
            json=canonical_spec_payload,
            headers=headers,
        )

        assert response_two.status_code == 200, (
            f"Idempotent replay failed: "
            f"HTTP {response_two.status_code}: {response_two.text}"
        )

        data_two = response_two.json()

        assert data_one["assessment_id"] == data_two["assessment_id"]
        assert data_one["risk_score"] == data_two["risk_score"]
        assert data_one["rating"] == data_two["rating"]

    async def test_get_assessment_by_id(
        self,
        api_client: AsyncClient,
        canonical_spec_payload: dict[str, Any],
    ) -> None:
        """Verify that a persisted assessment can be retrieved by ID."""
        create_response = await api_client.post(
            "/v1/risk-assessments",
            json=canonical_spec_payload,
            headers={"Idempotency-Key": f"idemp-{uuid4()}"},
        )

        assert create_response.status_code == 201, (
            f"Assessment creation failed: "
            f"HTTP {create_response.status_code}: {create_response.text}"
        )

        create_data = create_response.json()
        assessment_id = create_data.get("assessment_id")

        assert assessment_id, (
            f"Creation response is missing assessment_id: {create_data}"
        )

        get_response = await api_client.get(
            f"/v1/risk-assessments/{assessment_id}"
        )

        assert get_response.status_code == 200, (
            f"Assessment retrieval failed: "
            f"HTTP {get_response.status_code}: {get_response.text}"
        )

        retrieved_data = get_response.json()

        assert retrieved_data["assessment_id"] == assessment_id
        assert retrieved_data["risk_score"] == 83.5
        assert retrieved_data["rating"] == RiskCategory.HIGH.value

    async def test_reject_missing_correlation_id(
        self,
        api_client: AsyncClient,
        canonical_spec_payload: dict[str, Any],
    ) -> None:
        """Reject a malformed correlation UUID with HTTP 422."""
        canonical_spec_payload["detection_event"]["correlation_id"] = (
            "not-a-valid-uuid"
        )

        response = await api_client.post(
            "/v1/risk-assessments",
            json=canonical_spec_payload,
            headers={"Idempotency-Key": f"idemp-{uuid4()}"},
        )

        assert response.status_code == 422, (
            f"Expected HTTP 422 for an invalid correlation ID; "
            f"received HTTP {response.status_code}: {response.text}"
        )
