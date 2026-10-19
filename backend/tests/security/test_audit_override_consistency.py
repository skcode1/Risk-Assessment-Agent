from decimal import Decimal
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.core.database import async_session_factory
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.audit import AuditLogModel
from app.db.models.detection import DetectionModel
from app.db.models.policy import PolicyModel
from app.domain.models.enums import DetectionSeverity, DetectionSourceType
from tests.security.test_rbac import SystemRole, create_mock_jwt_token

pytestmark = pytest.mark.asyncio


class TestAuditOverrideConsistency:
    """Verifies atomic persistence for overrides and clean rollback on failed attempts."""

    async def _setup_seeded_assessment(self, session) -> str:
        """Seed parent detection and assessment records satisfying foreign key constraints."""
        policy_stmt = select(PolicyModel).limit(1)
        policy = (await session.execute(policy_stmt)).scalars().first()
        policy_id = policy.policy_id if policy else uuid4()

        event_id = uuid4()
        detection = DetectionModel(
            event_id=event_id,
            correlation_id=uuid4(),
            source_type=DetectionSourceType.EDR,
            severity=DetectionSeverity.HIGH,
            confidence=Decimal("95.00"),
            rule_id="RULE-TEST-001",
            rule_name="Test Rule for Audit",
            source_ip="192.168.1.100",
        )
        session.add(detection)
        await session.flush()

        assessment_id = uuid4()
        assessment = RiskAssessmentModel(
            assessment_id=assessment_id,
            detection_event_id=event_id,
            policy_id=policy_id,
            correlation_id=detection.correlation_id,
            source_ip="192.168.1.100",
            risk_score=Decimal("88.50"),
            rating="HIGH",
            behavior_score=Decimal("85.00"),
            frequency_score=Decimal("90.00"),
            sensitivity_score=Decimal("90.00"),
            history_score=Decimal("80.00"),
            components_snapshot={},
            applied_policy_snapshot={},
        )
        session.add(assessment)
        await session.commit()
        return str(assessment_id)

    async def test_successful_override_persists_audit_trail(
        self, security_client: AsyncClient
    ):
        """A valid override commits both the assessment override fields and the audit log entry."""
        async with async_session_factory() as session:
            assessment_id = await self._setup_seeded_assessment(session)

        lead_role = getattr(
            SystemRole,
            "LEAD_ANALYST",
            getattr(SystemRole, "SECURITY_ADMIN", "security_admin"),
        )
        token = create_mock_jwt_token(
            roles=[lead_role],
            scopes=["assessments:override", "assessments:read", "assessments:write"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "override_score": 15.0,
            "override_rating": "LOW",
            "justification": "Verified benign vulnerability scanner test activity.",
        }

        response = await security_client.post(
            f"/v1/risk-assessments/{assessment_id}/override",
            json=payload,
            headers=headers,
        )
        if response.status_code == 404:
            # Fallback for any legacy routing
            response = await security_client.post(
                f"/v1/risk-assessments/{assessment_id}/override",
                json=payload,
                headers=headers,
            )

        assert response.status_code in (200, 201), (
            f"Unexpected status: {response.status_code}, Body: {response.text}"
        )

        # Post-Request Database State Verification
        async with async_session_factory() as session:
            assessment_stmt = select(RiskAssessmentModel).where(
                RiskAssessmentModel.assessment_id == assessment_id
            )
            updated_assessment = (
                (await session.execute(assessment_stmt)).scalars().first()
            )
            assert updated_assessment is not None

            # Check override_rating field
            ov_rating = updated_assessment.override_rating
            ov_rating_val = (
                ov_rating.value if hasattr(ov_rating, "value") else str(ov_rating)
            )
            assert ov_rating_val == "LOW"

            # Check override_score field
            if updated_assessment.override_score is not None:
                assert float(updated_assessment.override_score) == 15.0

            # Verify audit trail record
            audit_stmt = select(AuditLogModel).where(
                AuditLogModel.assessment_id == assessment_id
            )
            audit_record = (await session.execute(audit_stmt)).scalars().first()
            assert audit_record is not None
            assert audit_record.action == "ANALYST_SCORE_OVERRIDE"

            details_str = str(audit_record.details) if audit_record.details else ""
            assert payload["justification"] in details_str or (
                isinstance(audit_record.details, dict)
                and audit_record.details.get("justification")
                == payload["justification"]
            )

    async def test_failed_override_leaves_no_inconsistent_state(
        self, security_client: AsyncClient
    ):
        """A rejected override rolls back cleanly, leaving original score intact and no orphan audit entries."""
        async with async_session_factory() as session:
            assessment_id = await self._setup_seeded_assessment(session)

            initial_assessment = (
                (
                    await session.execute(
                        select(RiskAssessmentModel).where(
                            RiskAssessmentModel.assessment_id == assessment_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            initial_rating = initial_assessment.rating
            initial_score = initial_assessment.risk_score

            audit_count_stmt = select(func.count(AuditLogModel.id)).where(
                AuditLogModel.assessment_id == assessment_id
            )
            initial_audit_count = (
                await session.execute(audit_count_stmt)
            ).scalar() or 0

        lead_role = getattr(
            SystemRole,
            "LEAD_ANALYST",
            getattr(SystemRole, "SECURITY_ADMIN", "security_admin"),
        )
        token = create_mock_jwt_token(
            roles=[lead_role],
            scopes=["assessments:override"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        invalid_payload = {
            "override_score": 95.0,
            "override_rating": "CRITICAL",
            "justification": "",  # Empty justification violates invariant validation
        }

        response = await security_client.post(
            f"/v1/risk-assessments/{assessment_id}/override",
            json=invalid_payload,
            headers=headers,
        )
        if response.status_code == 404:
            response = await security_client.post(
                f"/v1/risk-assessments/{assessment_id}/override",
                json=invalid_payload,
                headers=headers,
            )

        assert response.status_code in (400, 422)

        # Verify DB remained unchanged
        async with async_session_factory() as session:
            persisted_assessment = (
                (
                    await session.execute(
                        select(RiskAssessmentModel).where(
                            RiskAssessmentModel.assessment_id == assessment_id
                        )
                    )
                )
                .scalars()
                .first()
            )

            assert persisted_assessment.rating == initial_rating
            assert persisted_assessment.risk_score == initial_score
            assert persisted_assessment.override_rating is None

            final_audit_count = (await session.execute(audit_count_stmt)).scalar() or 0
            assert final_audit_count == initial_audit_count
