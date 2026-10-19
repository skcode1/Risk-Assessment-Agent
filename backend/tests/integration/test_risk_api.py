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

from decimal import Decimal
from uuid import uuid4

import pytest

from app.domain.models.enums import RiskCategory

BASELINE_POLICY_VERSION = "risk-policy-2026-01"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRiskAssessmentApiEndpoints:
    """End-to-end tests for assessment creation, idempotency, and retrieval."""

    async def test_assess_risk_endpoint_canonical_score(
        self,
        api_client,
        canonical_spec_payload,
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
        api_client,
        canonical_spec_payload,
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
        api_client,
        canonical_spec_payload,
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
        api_client,
        canonical_spec_payload,
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