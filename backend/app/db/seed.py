"""
Idempotent Database Seeding Module for CI/CD and Container Bootstrap.
Seeds the authoritative baseline RiskPolicy into PostgreSQL using the domain
factory (`RiskPolicy.create_spec_default`) without hardcoded magic numbers
or manual HTTP/curl requests.
"""

import asyncio
import logging
import sys
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Table, insert, select
from sqlalchemy.exc import SQLAlchemyError

# Preload all ORM models so Base.metadata is populated
import app.db.models.assessment
import app.db.models.detection
import app.db.models.investigation
import app.db.models.policy  # noqa: F401
from app.core.database import Base, async_session_factory, close_db_engine

try:
    from app.domain.models.policy import RiskPolicy
except ImportError:
    from app.db.models.policy import RiskPolicy  # type: ignore[no-redef]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.db.seed")

# Deterministic UUID for the baseline spec policy to guarantee idempotency across runs
BASELINE_POLICY_UUID = UUID("00000000-0000-4000-8000-000000000001")
BASELINE_POLICY_VERSION = "risk-policy-2026-01"


def _resolve_policy_table() -> Table:
    """Locates the policy table registered in SQLAlchemy Base.metadata."""
    for table_name, table in Base.metadata.tables.items():
        if "polic" in table_name.lower():
            return table
    raise RuntimeError(
        f"Could not locate a policy table in Base.metadata. "
        f"Registered tables: {list(Base.metadata.tables.keys())}"
    )


def _build_row_payload(table: Table, domain_policy: RiskPolicy) -> dict[str, Any]:
    """
    Maps the authoritative RiskPolicy domain entity onto the exact column schema
    of the target SQLAlchemy PostgreSQL table.
    """
    cols = table.columns.keys()
    payload: dict[str, Any] = {}

    # 1. Primary Key / Identifier
    if "policy_id" in cols:
        payload["policy_id"] = BASELINE_POLICY_UUID
    elif "id" in cols:
        payload["id"] = BASELINE_POLICY_UUID

    # 2. Core Metadata
    if "name" in cols:
        payload["name"] = domain_policy.name
    if "description" in cols:
        payload["description"] = domain_policy.description
    if "is_active" in cols:
        payload["is_active"] = domain_policy.is_active

    # 3. Version column (handles either String or Integer column types)
    if "version" in cols:
        version_col = table.columns["version"]
        try:
            py_type = version_col.type.python_type
        except NotImplementedError:
            py_type = str
        payload["version"] = 1 if py_type is int else domain_policy.version

    # 4. Component Weights (supports JSONB dict and/or flat numeric columns)
    weights_dict = domain_policy.weights.to_dict()
    for w_col in ("weights", "weights_config", "weight_config"):
        if w_col in cols:
            payload[w_col] = weights_dict

    flat_weight_mappings = {
        "behavior_weight": domain_policy.weights.behavior,
        "frequency_weight": domain_policy.weights.frequency,
        "sensitivity_weight": domain_policy.weights.sensitivity,
        "history_weight": domain_policy.weights.history,
        "weight_behavior": domain_policy.weights.behavior,
        "weight_frequency": domain_policy.weights.frequency,
        "weight_sensitivity": domain_policy.weights.sensitivity,
        "weight_history": domain_policy.weights.history,
    }
    for col_name, dec_val in flat_weight_mappings.items():
        if col_name in cols:
            col_type = getattr(table.columns[col_name].type, "python_type", float)
            payload[col_name] = dec_val if col_type is Decimal else float(dec_val)

    # 5. Category Thresholds (supports thresholds_config, threshold_config, thresholds, or flat columns)
    thresholds_dict = domain_policy.thresholds.to_dict()
    for t_col in ("thresholds_config", "threshold_config", "thresholds"):
        if t_col in cols:
            payload[t_col] = thresholds_dict

    tier_map = {t.category.value.lower(): t for t in domain_policy.thresholds.tiers}
    flat_threshold_mappings = {
        "low_min": tier_map["low"].min_score,
        "low_max": tier_map["low"].max_score,
        "medium_min": tier_map["medium"].min_score,
        "medium_max": tier_map["medium"].max_score,
        "high_min": tier_map["high"].min_score,
        "high_max": tier_map["high"].max_score,
        "critical_min": tier_map["critical"].min_score,
        "critical_max": tier_map["critical"].max_score,
    }
    for col_name, dec_val in flat_threshold_mappings.items():
        if col_name in cols:
            col_type = getattr(table.columns[col_name].type, "python_type", float)
            payload[col_name] = dec_val if col_type is Decimal else float(dec_val)

    # 6. Optional JSONB extensions & audit fields
    if "endpoint_class_weights" in cols:
        payload["endpoint_class_weights"] = {
            ep.value: float(wt) for ep, wt in domain_policy.endpoint_class_weights.items()
        }

    for meta_col in ("metadata_info", "metadata", "policy_metadata", "extra_metadata"):
        if meta_col in cols:
            payload[meta_col] = {
                "seeded_by": "app.db.seed",
                "authoritative_spec": True,
            }

    if "created_by" in cols:
        payload["created_by"] = "system:seed"
    if "created_at" in cols:
        payload["created_at"] = domain_policy.created_at
    if "updated_at" in cols:
        payload["updated_at"] = domain_policy.updated_at

    return payload


async def seed_baseline_policy() -> UUID | None:
    """
    Idempotently seeds the default RiskPolicy into PostgreSQL.
    If an active policy or matching baseline policy already exists, skips insertion.
    """
    domain_policy = RiskPolicy.create_spec_default(version=BASELINE_POLICY_VERSION)
    policy_table = _resolve_policy_table()
    pk_col_name = "policy_id" if "policy_id" in policy_table.columns else "id"
    pk_col = policy_table.columns[pk_col_name]

    async with async_session_factory() as session:
        async with session.begin():
            if "version" in policy_table.columns:
                check_stmt = select(pk_col).where(
                    policy_table.columns["version"] == domain_policy.version
                )
            elif "name" in policy_table.columns:
                check_stmt = select(pk_col).where(
                    policy_table.columns["name"] == domain_policy.name
                )
            else:
                check_stmt = select(pk_col).where(pk_col == BASELINE_POLICY_UUID)

            existing_id = (await session.execute(check_stmt)).scalar_one_or_none()
            if existing_id is not None:
                logger.info(
                    "Baseline policy '%s' (version=%s, id=%s) already exists. Skipping seed.",
                    domain_policy.name,
                    domain_policy.version,
                    existing_id,
                )
                return UUID(str(existing_id))

            row_payload = _build_row_payload(policy_table, domain_policy)
            insert_stmt = insert(policy_table).values(**row_payload)
            await session.execute(insert_stmt)

            logger.info(
                "Successfully seeded baseline policy '%s' (version=%s, id=%s).",
                domain_policy.name,
                domain_policy.version,
                BASELINE_POLICY_UUID,
            )
            return BASELINE_POLICY_UUID


async def main() -> None:
    try:
        await seed_baseline_policy()
    except SQLAlchemyError as db_err:
        logger.critical("Database error during policy seeding: %s", db_err, exc_info=True)
        sys.exit(1)
    except Exception as exc:
        logger.critical("Unexpected failure during policy seeding: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        await close_db_engine()


if __name__ == "__main__":
    asyncio.run(main())
