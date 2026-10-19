"""
Nightly Calibration Job Worker.
Computes p90/p99 for event counts and history distributions.
Proposes new policy versions with updated saturation_count, cap_threshold, incident_ceiling.
Stores proposals as status=PENDING_APPROVAL - never auto-activates.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import redis.asyncio as aioredis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.models.policy import PolicyModel
from app.domain.models.enums import EndpointClass
from app.domain.models.policy import (
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.workers.calibration_job")


@dataclass
class CalibrationResult:
    """Results of statistical analysis for policy calibration."""

    frequency_p90: float
    frequency_p99: float
    history_p90: float
    history_p99: float
    sample_size: int
    analysis_window_days: int


class CalibrationJob:
    """
    Analyzes historical assessment data to propose policy parameter updates.

    Computes:
    - p90/p99 of event_frequency -> suggests saturation_count for frequency calculator
    - p90/p99 of historical_incident_count -> suggests incident_ceiling for history calculator

    Creates proposal policy with status=PENDING_APPROVAL.
    Never auto-activates - requires human approval.
    """

    def __init__(
        self,
        db_session_factory: async_sessionmaker[AsyncSession],
        redis_client: aioredis.Redis | None = None,
        analysis_window_days: int = 30,
        min_sample_size: int = 100,
    ) -> None:
        self.db_factory = db_session_factory
        self.redis = redis_client
        self.analysis_window_days = analysis_window_days
        self.min_sample_size = min_sample_size

    async def collect_frequency_samples(self, session: AsyncSession) -> list[int]:
        """Collect event_frequency samples from recent assessments."""
        cutoff = datetime.now(UTC) - timedelta(days=self.analysis_window_days)

        # Query investigation telemetry for event frequencies
        stmt = text("""
            SELECT event_frequency 
            FROM investigations 
            WHERE created_at >= :cutoff 
            AND event_frequency > 0
            LIMIT 10000
        """)
        result = await session.execute(stmt, {"cutoff": cutoff})
        return [row[0] for row in result.fetchall()]

    async def collect_history_samples(self, session: AsyncSession) -> list[int]:
        """Collect historical_incident_count samples from recent assessments."""
        cutoff = datetime.now(UTC) - timedelta(days=self.analysis_window_days)

        stmt = text("""
            SELECT historical_incident_count 
            FROM investigations 
            WHERE created_at >= :cutoff
            LIMIT 10000
        """)
        result = await session.execute(stmt, {"cutoff": cutoff})
        return [row[0] for row in result.fetchall()]

    def calculate_percentiles(
        self, samples: list[int], percentiles: list[float]
    ) -> dict[float, float]:
        """Calculate percentiles from samples."""
        if not samples or len(samples) < self.min_sample_size:
            return {p: 0.0 for p in percentiles}

        sorted_samples = sorted(samples)
        results = {}
        for p in percentiles:
            idx = int(len(sorted_samples) * p / 100)
            idx = min(idx, len(sorted_samples) - 1)
            results[p] = float(sorted_samples[idx])
        return results

    def compute_calibration(
        self, freq_samples: list[int], hist_samples: list[int]
    ) -> CalibrationResult:
        """Compute calibration parameters from samples."""
        freq_percentiles = self.calculate_percentiles(freq_samples, [90.0, 99.0])
        hist_percentiles = self.calculate_percentiles(hist_samples, [90.0, 99.0])

        return CalibrationResult(
            frequency_p90=freq_percentiles.get(90.0, 0.0),
            frequency_p99=freq_percentiles.get(99.0, 0.0),
            history_p90=hist_percentiles.get(90.0, 0.0),
            history_p99=hist_percentiles.get(99.0, 0.0),
            sample_size=min(len(freq_samples), len(hist_samples)),
            analysis_window_days=self.analysis_window_days,
        )

    def create_proposal_policy(
        self, current_policy: RiskPolicy, calibration: CalibrationResult
    ) -> RiskPolicy:
        """
        Create a new policy proposal based on calibration results.

        Adjusts:
        - frequency_config.saturation_count: set to frequency_p99 (cap at p99)
        - history_config.incident_saturation_ceiling: set to history_p99
        """
        # Get current metadata configs
        freq_config = current_policy.metadata.get("frequency_config", {})
        hist_config = current_policy.metadata.get("history_config", {})
        sens_config = current_policy.metadata.get("sensitivity_config", {})
        beh_config = current_policy.metadata.get("behavior_config", {})

        # Update saturation_count based on frequency p99
        new_saturation = max(10, int(calibration.frequency_p99))
        freq_config["saturation_count"] = new_saturation

        # Update incident ceiling based on history p99
        new_ceiling = max(1, int(calibration.history_p99))
        hist_config["incident_saturation_ceiling"] = new_ceiling

        # Create new metadata with updated configs
        new_metadata = {
            **current_policy.metadata,
            "frequency_config": freq_config,
            "history_config": hist_config,
            "sensitivity_config": sens_config,
            "behavior_config": beh_config,
            "calibration_proposal": {
                "based_on_analysis_window_days": self.analysis_window_days,
                "sample_size": calibration.sample_size,
                "frequency_p90": calibration.frequency_p90,
                "frequency_p99": calibration.frequency_p99,
                "history_p90": calibration.history_p90,
                "history_p99": calibration.history_p99,
                "proposed_at": datetime.now(UTC).isoformat(),
                "previous_frequency_saturation": freq_config.get("saturation_count"),
                "previous_history_ceiling": hist_config.get(
                    "incident_saturation_ceiling"
                ),
                "new_frequency_saturation": new_saturation,
                "new_history_ceiling": new_ceiling,
            },
        }

        # Generate new version string
        from uuid import uuid4

        version_suffix = uuid4().hex[:8]
        new_version = f"{current_policy.version}-calibration-{version_suffix}"

        return RiskPolicy(
            name=f"Calibration Proposal - {new_version}",
            version=new_version,
            description=f"Auto-generated calibration proposal based on {self.analysis_window_days}d analysis "
            f"(n={calibration.sample_size}). "
            f"Freq p99={calibration.frequency_p99:.1f} -> saturation_count={new_saturation}, "
            f"Hist p99={calibration.history_p99:.1f} -> ceiling={new_ceiling}",
            weights=current_policy.weights,
            thresholds=current_policy.thresholds,
            endpoint_class_weights=current_policy.endpoint_class_weights,
            metadata=new_metadata,
            is_active=False,  # Never auto-activate!
        )

    async def persist_proposal(self, proposal: RiskPolicy) -> bool:
        """Persist proposal policy to database with PENDING_APPROVAL status."""
        # Store in metadata that this is a pending proposal
        proposal.metadata["proposal_status"] = "PENDING_APPROVAL"

        async with self.db_factory() as session:
            async with session.begin():
                # Check if version already exists
                existing = await session.execute(
                    select(PolicyModel.policy_id).where(
                        PolicyModel.version == proposal.version
                    )
                )
                if existing.scalar_one_or_none():
                    logger.warning(
                        "Proposal version %s already exists, skipping", proposal.version
                    )
                    return False

                # Create policy model
                policy_model = PolicyModel(
                    policy_id=proposal.policy_id,
                    name=proposal.name,
                    version=proposal.version,
                    description=proposal.description,
                    is_active=proposal.is_active,
                    weight_behavior=proposal.weights.behavior,
                    weight_frequency=proposal.weights.frequency,
                    weight_sensitivity=proposal.weights.sensitivity,
                    weight_history=proposal.weights.history,
                    thresholds_config=proposal.thresholds.to_dict(),
                    endpoint_class_weights={
                        ep.value: float(wt)
                        for ep, wt in proposal.endpoint_class_weights.items()
                    },
                    metadata_info=proposal.metadata,
                    created_by="system:calibration-job",
                    created_at=proposal.created_at,
                    updated_at=proposal.updated_at,
                )

                session.add(policy_model)
                await session.flush()

                logger.info(
                    "Created calibration proposal policy: %s (id=%s)",
                    proposal.version,
                    proposal.policy_id,
                )
                return True

    async def run(self) -> bool:
        """Execute the full calibration job."""
        logger.info("Starting calibration job (window=%dd)", self.analysis_window_days)

        try:
            async with self.db_factory() as session:
                # Get current active policy
                stmt = (
                    select(PolicyModel)
                    .where(PolicyModel.is_active.is_(True))
                    .order_by(PolicyModel.created_at.desc())
                )
                result = await session.execute(stmt)
                active_model = result.scalars().first()

                if not active_model:
                    logger.error(
                        "No active policy found, cannot create calibration proposal"
                    )
                    return False

                # Convert to domain policy
                current_policy = RiskPolicy(
                    policy_id=active_model.policy_id,
                    name=active_model.name,
                    version=active_model.version,
                    weights=PolicyWeights(
                        behavior=active_model.weight_behavior,
                        frequency=active_model.weight_frequency,
                        sensitivity=active_model.weight_sensitivity,
                        history=active_model.weight_history,
                    ),
                    thresholds=ThresholdConfig.from_dict(
                        active_model.thresholds_config
                    ),
                    endpoint_class_weights={
                        EndpointClass(ep): Decimal(str(wt))
                        for ep, wt in (
                            active_model.endpoint_class_weights or {}
                        ).items()
                    },
                    metadata=active_model.metadata_info or {},
                    is_active=active_model.is_active,
                    created_at=active_model.created_at,
                    updated_at=active_model.updated_at,
                )

            # Collect samples
            freq_samples = await self.collect_frequency_samples(session)
            hist_samples = await self.collect_history_samples(session)

            logger.info(
                "Collected %d frequency samples, %d history samples",
                len(freq_samples),
                len(hist_samples),
            )

            if (
                len(freq_samples) < self.min_sample_size
                or len(hist_samples) < self.min_sample_size
            ):
                logger.warning(
                    "Insufficient samples for calibration (need %d, got freq=%d, hist=%d)",
                    self.min_sample_size,
                    len(freq_samples),
                    len(hist_samples),
                )
                return False

            # Compute calibration
            calibration = self.compute_calibration(freq_samples, hist_samples)
            logger.info(
                "Calibration results: freq_p90=%.1f, freq_p99=%.1f, hist_p90=%.1f, hist_p99=%.1f",
                calibration.frequency_p90,
                calibration.frequency_p99,
                calibration.history_p90,
                calibration.history_p99,
            )

            # Create proposal
            proposal = self.create_proposal_policy(current_policy, calibration)

            # Persist proposal
            success = await self.persist_proposal(proposal)

            if success:
                logger.info("Calibration proposal created: %s", proposal.version)
            else:
                logger.warning("Failed to create calibration proposal")

            return success

        except Exception:
            logger.exception("Calibration job failed")
            return False


async def main() -> None:
    """Entry point for calibration job."""
    # Create database engine
    db_url = settings.db.ASYNC_DATABASE_URI
    engine = create_async_engine(db_url, pool_pre_ping=True)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    # Redis client (optional)
    redis_client = None
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        redis_client = aioredis.from_url(redis_url, decode_responses=True)
        try:
            await redis_client.ping()
        except Exception:
            redis_client = None

    job = CalibrationJob(
        db_session_factory=session_factory,
        redis_client=redis_client,
        analysis_window_days=int(os.getenv("CALIBRATION_WINDOW_DAYS", "30")),
        min_sample_size=int(os.getenv("CALIBRATION_MIN_SAMPLES", "100")),
    )

    try:
        await job.run()
    finally:
        await engine.dispose()
        if redis_client:
            await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
