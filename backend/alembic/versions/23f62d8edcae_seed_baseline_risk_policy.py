"""seed_baseline_risk_policy

Revision ID: 23f62d8edcae
Revises: b7c12f8901de
Create Date: 2026-10-19 01:28:14.488331

"""
from datetime import datetime, UTC
from decimal import Decimal
import json
from typing import Sequence, Union
from uuid import UUID

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '23f62d8edcae'
down_revision: Union[str, None] = 'b7c12f8901de'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BASELINE_POLICY_UUID = UUID("00000000-0000-4000-8000-000000000001")
BASELINE_POLICY_VERSION = "risk-policy-2026-01"


def upgrade() -> None:
    """Insert the baseline risk policy."""
    # Check if policy already exists
    conn = op.get_bind()
    existing = conn.execute(
        sa.text("SELECT policy_id FROM policies WHERE version = :version"),
        {"version": BASELINE_POLICY_VERSION}
    ).fetchone()
    
    if existing:
        return  # Already seeded
    
    # Insert baseline policy
    conn = op.get_bind()
    conn.execute(
        sa.text("""
            INSERT INTO policies (
                policy_id, name, version, description, is_active,
                weight_behavior, weight_frequency, weight_sensitivity, weight_history,
                thresholds_config, endpoint_class_weights, metadata_info,
                created_by, created_at, updated_at
            ) VALUES (
                :policy_id, :name, :version, :description, :is_active,
                :weight_behavior, :weight_frequency, :weight_sensitivity, :weight_history,
                :thresholds_config, :endpoint_class_weights, :metadata_info,
                :created_by, :created_at, :updated_at
            )
        """),
        {
            "policy_id": BASELINE_POLICY_UUID,
            "name": "Authoritative Spec Risk Policy",
            "version": BASELINE_POLICY_VERSION,
            "description": "Default versioned policy baseline matching 6.3 spec weights and category boundaries",
            "is_active": True,
            "weight_behavior": Decimal("0.40"),
            "weight_frequency": Decimal("0.30"),
            "weight_sensitivity": Decimal("0.20"),
            "weight_history": Decimal("0.10"),
            "thresholds_config": json.dumps({
                "tiers": [
                    {"category": "LOW", "min_score": "0.0", "max_score": "39.9"},
                    {"category": "MEDIUM", "min_score": "40.0", "max_score": "64.9"},
                    {"category": "HIGH", "min_score": "65.0", "max_score": "84.9"},
                    {"category": "CRITICAL", "min_score": "85.0", "max_score": "100.0"},
                ]
            }),
            "endpoint_class_weights": json.dumps({"DATABASE_SERVER": 80.0}),
            "metadata_info": json.dumps({
                "seeded_by": "alembic.seed_baseline_risk_policy",
                "authoritative_spec": True,
            }),
            "created_by": "system:alembic",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
        }
    )


def downgrade() -> None:
    """Remove the baseline risk policy and any dependent assessments/audit logs."""
    conn = op.get_bind()
    # Reverse dependency order: audit_logs -> risk_assessments -> policies
    conn.execute(
        sa.text(
            "DELETE FROM audit_logs WHERE assessment_id IN "
            "(SELECT assessment_id FROM risk_assessments WHERE policy_id = :policy_id)"
        ),
        {"policy_id": BASELINE_POLICY_UUID},
    )
    conn.execute(
        sa.text("DELETE FROM risk_assessments WHERE policy_id = :policy_id"),
        {"policy_id": BASELINE_POLICY_UUID},
    )
    conn.execute(
        sa.text("DELETE FROM policies WHERE version = :version"),
        {"version": BASELINE_POLICY_VERSION}
    )