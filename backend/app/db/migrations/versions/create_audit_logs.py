"""create_audit_logs_append_only_trigger

Revision ID: b7c12f8901de
Revises: 93bc12a820cb
Create Date: 2026-10-12 04:13:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "b7c12f8901de"
down_revision: str | None = "93bc12a820cb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create Append-Only Trigger Function and Trigger
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trg_enforce_audit_logs_append_only()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is an append-only ledger: % operations are prohibited', TG_OP
            USING ERRCODE = '55000'; -- object_not_in_prerequisite_state
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW
        EXECUTE FUNCTION trg_enforce_audit_logs_append_only();
        """
    )


def downgrade() -> None:
    # Drop trigger and trigger function
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_append_only ON audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS trg_enforce_audit_logs_append_only();")
