"""
Audit Log Immutability Tests.
Verifies that the append-only trigger rejects UPDATE and DELETE operations on audit_logs.
"""

import pytest
import pytest_asyncio
from uuid import uuid4
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from app.db.models.audit import AuditLogModel
from app.db.models.assessment import RiskAssessmentModel
from app.db.models.detection import DetectionModel
from app.db.models.policy import PolicyModel
from app.domain.models.enums import RiskCategory, DetectionSeverity, DetectionSourceType
from decimal import Decimal


@pytest.mark.asyncio
class TestAuditLogImmutability:
    """Tests confirming audit_logs table is append-only."""

    @pytest_asyncio.fixture
    async def sample_detection(self, async_db_session):
        """Create a sample detection for foreign key reference."""
        detection = DetectionModel(
            event_id=uuid4(),
            correlation_id=uuid4(),
            source_type=DetectionSourceType.EDR,
            severity=DetectionSeverity.HIGH,
            confidence=Decimal("90.0"),
            fidelity=Decimal("1.0"),
            rule_id="RULE-TEST-001",
            rule_name="Test Rule",
            source_ip="1.2.3.4",
            context_data={"hostname": "test-host"},
            raw_payload='{"test": "data"}',
            detected_at=datetime.now(UTC),
        )
        async_db_session.add(detection)
        await async_db_session.commit()
        await async_db_session.refresh(detection)
        return detection

    @pytest_asyncio.fixture
    async def sample_policy(self, async_db_session):
        """Create a sample policy for foreign key reference."""
        policy = PolicyModel(
            policy_id=uuid4(),
            name="Test Policy",
            version="test-policy-001",
            description="Test policy for audit immutability",
            is_active=True,
            weight_behavior=Decimal("0.40"),
            weight_frequency=Decimal("0.30"),
            weight_sensitivity=Decimal("0.20"),
            weight_history=Decimal("0.10"),
            thresholds_config={
                "tiers": [
                    {"category": "LOW", "min_score": "0.0", "max_score": "39.9"},
                    {"category": "MEDIUM", "min_score": "40.0", "max_score": "64.9"},
                    {"category": "HIGH", "min_score": "65.0", "max_score": "84.9"},
                    {"category": "CRITICAL", "min_score": "85.0", "max_score": "100.0"},
                ]
            },
            endpoint_class_weights={"DATABASE_SERVER": 80.0},
            metadata_info={},
            created_by="system:test",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        async_db_session.add(policy)
        await async_db_session.commit()
        await async_db_session.refresh(policy)
        return policy

    @pytest_asyncio.fixture
    async def sample_assessment(self, async_db_session, sample_detection, sample_policy):
        """Create a sample risk assessment for foreign key reference."""
        assessment = RiskAssessmentModel(
            assessment_id=uuid4(),
            detection_event_id=sample_detection.event_id,
            policy_id=sample_policy.policy_id,
            correlation_id=uuid4(),
            source_ip="1.2.3.4",
            risk_score=Decimal("83.5"),
            rating=RiskCategory.HIGH,
            behavior_score=Decimal("90.0"),
            frequency_score=Decimal("85.0"),
            sensitivity_score=Decimal("80.0"),
            history_score=Decimal("60.0"),
            components_snapshot={"behavior": 90.0, "frequency": 85.0, "sensitivity": 80.0, "history": 60.0},
            applied_policy_snapshot={"version": "risk-policy-2026-01", "weights": {"behavior": 0.4, "frequency": 0.3, "sensitivity": 0.2, "history": 0.1}},
            created_at=datetime.now(UTC),
        )
        async_db_session.add(assessment)
        await async_db_session.commit()
        await async_db_session.refresh(assessment)
        return assessment

    @pytest_asyncio.fixture
    async def sample_audit_log(self, async_db_session, sample_assessment):
        """Create a sample audit log entry for testing."""
        audit_log = AuditLogModel(
            actor="test-user",
            action="TEST_ACTION",
            assessment_id=sample_assessment.assessment_id,
            correlation_id=uuid4(),
            before_snapshot={"rating": "MEDIUM", "risk_score": 55.0},
            after_snapshot={"rating": "HIGH", "risk_score": 83.5},
            details={"source_ip": "1.2.3.4", "endpoint": "/v1/risk-assessments"},
            created_at=datetime.now(UTC),
        )
        async_db_session.add(audit_log)
        await async_db_session.commit()
        await async_db_session.refresh(audit_log)
        return audit_log

    async def test_insert_audit_log_succeeds(self, async_db_session, sample_assessment):
        """INSERT operations should succeed on audit_logs."""
        audit_log = AuditLogModel(
            actor="test-user",
            action="TEST_INSERT",
            assessment_id=sample_assessment.assessment_id,
            correlation_id=uuid4(),
            before_snapshot={},
            after_snapshot={"test": "data"},
            details={},
            created_at=datetime.now(UTC),
        )
        async_db_session.add(audit_log)
        await async_db_session.commit()

        # Verify it was inserted
        result = await async_db_session.execute(
            text("SELECT COUNT(*) FROM audit_logs WHERE action = 'TEST_INSERT'")
        )
        assert result.scalar() == 1

    async def test_update_audit_log_rejected(self, async_db_session, sample_audit_log):
        """UPDATE operations should be rejected by the trigger."""
        audit_id = sample_audit_log.id

        # Attempt UPDATE
        with pytest.raises((DBAPIError, OperationalError, ProgrammingError)) as exc_info:
            await async_db_session.execute(
                text("UPDATE audit_logs SET action = 'MODIFIED' WHERE id = :audit_id"),
                {"audit_id": str(audit_id)},
            )

        # Verify the error is from the trigger
        error_msg = str(exc_info.value).lower()
        assert "append-only" in error_msg or "trigger" in error_msg or "55000" in error_msg

        # Rollback the aborted transaction
        await async_db_session.rollback()

        # Verify original data unchanged
        result = await async_db_session.execute(
            text("SELECT action FROM audit_logs WHERE id = :audit_id"),
            {"audit_id": str(audit_id)},
        )
        assert result.scalar() == "TEST_ACTION"

    async def test_delete_audit_log_rejected(self, async_db_session, sample_audit_log):
        """DELETE operations should be rejected by the trigger."""
        audit_id = sample_audit_log.id

        # Attempt DELETE
        with pytest.raises((DBAPIError, OperationalError, ProgrammingError)) as exc_info:
            await async_db_session.execute(
                text("DELETE FROM audit_logs WHERE id = :audit_id"),
                {"audit_id": str(audit_id)},
            )

        # Verify the error is from the trigger
        error_msg = str(exc_info.value).lower()
        assert "append-only" in error_msg or "trigger" in error_msg or "55000" in error_msg

        # Rollback the aborted transaction
        await async_db_session.rollback()

        # Verify record still exists
        result = await async_db_session.execute(
            text("SELECT COUNT(*) FROM audit_logs WHERE id = :audit_id"),
            {"audit_id": str(audit_id)},
        )
        assert result.scalar() == 1

    async def test_orm_update_rejected(self, async_db_session, sample_audit_log):
        """ORM UPDATE should also be rejected."""
        # Try to modify via ORM
        sample_audit_log.action = "ORM_MODIFIED"

        # The flush will trigger the trigger
        with pytest.raises((DBAPIError, OperationalError, ProgrammingError)) as exc_info:
            await async_db_session.flush()

        error_msg = str(exc_info.value).lower()
        assert "append-only" in error_msg or "trigger" in error_msg or "55000" in error_msg
        # If we get here, the trigger worked - no need to verify state after

    async def test_orm_delete_rejected(self, async_db_session, sample_audit_log):
        """ORM DELETE should also be rejected."""
        await async_db_session.delete(sample_audit_log)

        with pytest.raises((DBAPIError, OperationalError, ProgrammingError)) as exc_info:
            await async_db_session.flush()

        error_msg = str(exc_info.value).lower()
        assert "append-only" in error_msg or "trigger" in error_msg or "55000" in error_msg
        # If we get here, the trigger worked - no need to verify state after

    async def test_multiple_inserts_allowed(self, async_db_session, sample_assessment):
        """Multiple INSERT operations should all succeed."""
        for i in range(5):
            audit_log = AuditLogModel(
                actor="test-user",
                action=f"MULTI_INSERT_{i}",
                assessment_id=sample_assessment.assessment_id,
                correlation_id=uuid4(),
                before_snapshot={},
                after_snapshot={"index": i},
                details={},
                created_at=datetime.now(UTC),
            )
            async_db_session.add(audit_log)

        await async_db_session.commit()

        result = await async_db_session.execute(
            text("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'MULTI_INSERT_%'")
        )
        assert result.scalar() == 5