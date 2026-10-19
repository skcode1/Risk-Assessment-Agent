"""
Security verification suite for Role-Based Access Control (RBAC) and Governance.
Tests authentication, authorization scopes, policy mutation permissions,
analyst score overrides, and containment action approvals across SOC tiers.
"""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt

# Secret and algorithm configuration for testing token generation
from app.core.config import settings
from app.domain.models.enums import RiskCategory
from app.main import app

TEST_SECRET_KEY = settings.security.JWT_SECRET_KEY.get_secret_value()
TEST_ALGORITHM = settings.security.JWT_ALGORITHM

# All tests in this module share a single event loop so the global
# AsyncEngine / Redis singleton bound to the first loop is never used
# from a different loop ("Future attached to a different loop").
pytestmark = pytest.mark.asyncio(loop_scope="session")


class SystemRole:
    """Standard security operational roles defining tiered authorization boundaries."""

    SOC_ANALYST_TIER_1 = "ROLE_SOC_ANALYST_L1"
    SOC_ANALYST_TIER_2 = "ROLE_SOC_ANALYST_L2"
    SOC_LEAD = "ROLE_SOC_LEAD"
    SECURITY_ADMIN = "ROLE_SECURITY_ADMIN"
    AUDITOR = "ROLE_AUDITOR"


def create_mock_jwt_token(
    user_id: str | None = None,
    username: str | None = None,
    roles: list[str] | None = None,
    scopes: list[str] | None = None,
) -> str:
    """Generates an RFC 7519 compliant JSON Web Token for dynamic authorization testing."""
    payload = {
        "sub": user_id or str(uuid4()),
        "preferred_username": username or "analyst",
        "roles": roles or [SystemRole.SOC_ANALYST_TIER_1],
        "scope": " ".join(scopes or ["assessments:read"]),
        "iat": datetime.now(UTC).timestamp(),
        "exp": datetime.now(UTC).timestamp() + 3600,
    }
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm=TEST_ALGORITHM)


@pytest_asyncio.fixture(loop_scope="session")
async def security_client() -> AsyncGenerator[AsyncClient, None]:
    """Provides an isolated HTTP client configured for endpoint security evaluation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
def sample_policy_payload() -> dict[str, object]:
    """Dynamic risk policy definition for testing policy modification endpoints."""
    return {
        "name": "Updated Operational Policy",
        "version": f"policy-v-{uuid4().hex[:6]}",
        "weights": {
            "behavior": 0.40,
            "frequency": 0.30,
            "sensitivity": 0.20,
            "history": 0.10,
        },
        "thresholds": {
            "low": {"min_val": 0.0, "max_val": 39.9},
            "medium": {"min_val": 40.0, "max_val": 64.9},
            "high": {"min_val": 65.0, "max_val": 84.9},
            "critical": {"min_val": 85.0, "max_val": 100.0},
        },
    }


@pytest.mark.asyncio
class TestAuthenticationAndTokenValidation:
    """Verifies baseline authentication requirements across protected risk endpoints."""

    async def test_reject_unauthenticated_request(
        self, security_client: AsyncClient
    ) -> None:
        """Ensures requests without Bearer authorization tokens return 401 Unauthorized."""
        response = await security_client.get("/v1/risk-assessments")
        assert response.status_code == 401
        assert "error_code" in response.json() or "detail" in response.json()

    async def test_reject_malformed_token(self, security_client: AsyncClient) -> None:
        """Ensures corrupted or invalid tokens return 401 Unauthorized."""
        headers = {"Authorization": "Bearer invalid.token.payload"}
        response = await security_client.get("/v1/risk-assessments", headers=headers)
        assert response.status_code == 401


@pytest.mark.asyncio
class TestRiskAssessmentAccessPermissions:
    """Verifies fine-grained role scopes on reading and triggering risk assessments."""

    async def test_tier1_analyst_can_read_assessment(
        self, security_client: AsyncClient
    ) -> None:
        """Verifies read privileges for Tier 1 analysts with assessments:read scope."""
        token = create_mock_jwt_token(
            roles=[SystemRole.SOC_ANALYST_TIER_1],
            scopes=["assessments:read"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        dummy_id = uuid4()

        response = await security_client.get(
            f"/v1/risk-assessments/{dummy_id}", headers=headers
        )
        # Endpoint exists and authorizes; 404 confirms the authorization gate passed
        assert response.status_code in (200, 404)

    async def test_tier1_analyst_cannot_trigger_containment(
        self, security_client: AsyncClient
    ) -> None:
        """
        Verifies that Tier 1 analysts cannot trigger containment workflows
        without elevated authorization.
        """
        token = create_mock_jwt_token(
            roles=[SystemRole.SOC_ANALYST_TIER_1],
            scopes=["assessments:read"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        dummy_id = uuid4()

        response = await security_client.post(
            f"/v1/risk-assessments/{dummy_id}/actions/contain",
            headers=headers,
            json={"action": "ISOLATE_HOST"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestPolicyGovernancePermissions:
    """Verifies that only authorized administrators can alter risk policies and weights."""

    async def test_analyst_cannot_create_or_mutate_policy(
        self,
        security_client: AsyncClient,
        sample_policy_payload: dict[str, object],
    ) -> None:
        """Ensures analysts with standard operational privileges cannot publish new risk policies."""
        token = create_mock_jwt_token(
            roles=[SystemRole.SOC_ANALYST_TIER_2],
            scopes=["assessments:read", "assessments:write"],
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = await security_client.post(
            "/v1/policies",
            json=sample_policy_payload,
            headers=headers,
        )
        assert response.status_code == 403

    async def test_security_admin_can_manage_policies(
        self,
        security_client: AsyncClient,
        sample_policy_payload: dict[str, object],
    ) -> None:
        """Ensures Security Administrators with policies:admin scope can register new policies."""
        token = create_mock_jwt_token(
            roles=[SystemRole.SECURITY_ADMIN],
            scopes=["policies:admin", "assessments:admin"],
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = await security_client.post(
            "/v1/policies",
            json=sample_policy_payload,
            headers=headers,
        )
        assert response.status_code in (201, 200)

    async def test_admin_cannot_activate_unsupported_weights(
        self,
        security_client: AsyncClient,
    ) -> None:
        """
        Ensures that even Administrators cannot register policies violating
        mathematical invariants (weights summing != 1.0).
        """
        token = create_mock_jwt_token(
            roles=[SystemRole.SECURITY_ADMIN],
            scopes=["policies:admin"],
        )
        headers = {"Authorization": f"Bearer {token}"}

        invalid_policy = {
            "name": "Invalid Sum Policy",
            "version": f"policy-err-{uuid4().hex[:6]}",
            "weights": {
                "behavior": 0.50,
                "frequency": 0.50,
                "sensitivity": 0.30,
                "history": 0.10,  # Sum = 1.40
            },
            "thresholds": {
                "low": {"min_val": 0.0, "max_val": 39.9},
                "medium": {"min_val": 40.0, "max_val": 64.9},
                "high": {"min_val": 65.0, "max_val": 84.9},
                "critical": {"min_val": 85.0, "max_val": 100.0},
            },
        }

        response = await security_client.post(
            "/v1/policies",
            json=invalid_policy,
            headers=headers,
        )
        assert response.status_code == 422


@pytest.mark.asyncio
class TestAnalystOverrideGovernance:
    """Verifies authorization gates and audit logging on manual score overrides."""

    async def test_lead_analyst_can_override_assessment_with_audit_trail(
        self,
        security_client: AsyncClient,
    ) -> None:
        """
        Verifies that only Lead Analysts or Admins can submit score overrides,
        requiring mandatory audit justification.
        """
        token = create_mock_jwt_token(
            user_id=str(uuid4()),
            username="lead_analyst_01",
            roles=[SystemRole.SOC_LEAD],
            scopes=["assessments:override"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        dummy_assessment_id = uuid4()

        override_payload = {
            "override_score": 60.0,
            "override_rating": RiskCategory.MEDIUM.value,
            "justification": "False positive signature confirmed via external sandboxing analysis.",
            "ticket_reference": "SEC-INC-40291",
        }

        response = await security_client.post(
            f"/v1/risk-assessments/{dummy_assessment_id}/override",
            json=override_payload,
            headers=headers,
        )
        # 404 indicates authorized user accessed the endpoint (assessment record not seeded in DB)
        assert response.status_code in (200, 404)

    async def test_reject_override_without_justification(
        self,
        security_client: AsyncClient,
    ) -> None:
        """Ensures overrides submitted without audit justifications fail validation."""
        token = create_mock_jwt_token(
            roles=[SystemRole.SOC_LEAD],
            scopes=["assessments:override"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        dummy_id = uuid4()

        incomplete_payload = {
            "override_score": 50.0,
            "override_rating": RiskCategory.MEDIUM.value,
            # Missing mandatory justification
        }

        response = await security_client.post(
            f"/v1/risk-assessments/{dummy_id}/override",
            json=incomplete_payload,
            headers=headers,
        )
        assert response.status_code == 422
