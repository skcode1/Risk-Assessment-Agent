"""
CMDB Synchronization Job Worker.
Pulls asset-class mappings from configured inventory API.
Creates draft policy with updated endpoint_class_weights.
Invalidates policy:active cache.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

import httpx
import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.models.policy import PolicyModel
from app.domain.models.enums import EndpointClass
from app.domain.models.policy import PolicyWeights, RiskPolicy, ThresholdConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("app.workers.cmdb_sync")


@dataclass
class CMDBAsset:
    """Asset record from CMDB/inventory API."""

    asset_id: str
    hostname: str
    ip_address: str
    asset_class: str  # Maps to EndpointClass
    criticality: str  # "critical", "high", "medium", "low"
    tags: list[str]


class CMDBsyncJob:
    """
    Synchronizes asset-class mappings from CMDB/inventory API.

    Flow:
    1. Pull assets from configured inventory API
    2. Aggregate counts by EndpointClass
    3. Calculate sensitivity weights based on asset criticality distribution
    4. Create draft policy with updated endpoint_class_weights
    5. Invalidate policy:active Redis cache
    """

    def __init__(
        self,
        db_session_factory: async_sessionmaker[AsyncSession],
        redis_client: aioredis.Redis | None = None,
        cmdb_api_url: str | None = None,
        cmdb_api_key: str | None = None,
        cmdb_page_size: int = 1000,
    ) -> None:
        self.db_factory = db_session_factory
        self.redis = redis_client
        self.cmdb_api_url = cmdb_api_url or os.getenv("CMDB_API_URL")
        self.cmdb_api_key = cmdb_api_key or os.getenv("CMDB_API_KEY")
        self.cmdb_page_size = cmdb_page_size

        # Default weight mapping from criticality to sensitivity score
        self.criticality_weights = {
            "critical": Decimal("100.0"),
            "high": Decimal("85.0"),
            "medium": Decimal("60.0"),
            "low": Decimal("40.0"),
        }

    async def fetch_assets(self) -> list[CMDBAsset]:
        """Fetch assets from CMDB API with pagination."""
        if not self.cmdb_api_url:
            logger.warning("CMDB_API_URL not configured, using mock data")
            return self._get_mock_assets()

        assets = []
        page = 1

        headers = (
            {"Authorization": f"Bearer {self.cmdb_api_key}"}
            if self.cmdb_api_key
            else {}
        )

        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                try:
                    response = await client.get(
                        self.cmdb_api_url,
                        params={"page": page, "page_size": self.cmdb_page_size},
                        headers=headers,
                    )
                    response.raise_for_status()
                    data = response.json()

                    page_assets = data.get("assets", data.get("results", data))
                    if not page_assets:
                        break

                    for item in page_assets:
                        asset = CMDBAsset(
                            asset_id=item.get("asset_id", item.get("id", "")),
                            hostname=item.get("hostname", ""),
                            ip_address=item.get("ip_address", item.get("ip", "")),
                            asset_class=item.get(
                                "asset_class", item.get("class", "UNKNOWN")
                            ),
                            criticality=item.get(
                                "criticality", item.get("tier", "medium")
                            ).lower(),
                            tags=item.get("tags", [])
                            if isinstance(item.get("tags"), list)
                            else [],
                        )
                        assets.append(asset)

                    # Check for pagination
                    if len(page_assets) < self.cmdb_page_size:
                        break
                    page += 1

                except httpx.HTTPStatusError as e:
                    logger.error("CMDB API error (page %d): %s", page, e)
                    break
                except Exception:
                    logger.exception("Failed to fetch CMDB assets (page %d)", page)
                    break

        logger.info("Fetched %d assets from CMDB", len(assets))
        return assets

    def _get_mock_assets(self) -> list[CMDBAsset]:
        """Return mock assets for testing when CMDB API not configured."""
        return [
            CMDBAsset(
                "srv-001",
                "db-prod-01",
                "10.0.1.10",
                "DATABASE_SERVER",
                "critical",
                ["production", "pci"],
            ),
            CMDBAsset(
                "srv-002",
                "db-prod-02",
                "10.0.1.11",
                "DATABASE_SERVER",
                "high",
                ["production"],
            ),
            CMDBAsset(
                "dc-001",
                "dc-corp-01",
                "10.0.2.10",
                "DOMAIN_CONTROLLER",
                "critical",
                ["production", "identity"],
            ),
            CMDBAsset(
                "dc-002",
                "dc-corp-02",
                "10.0.2.11",
                "DOMAIN_CONTROLLER",
                "high",
                ["production", "identity"],
            ),
            CMDBAsset(
                "srv-003",
                "app-prod-01",
                "10.0.3.10",
                "INTERNAL_SERVER",
                "high",
                ["production"],
            ),
            CMDBAsset(
                "srv-004",
                "app-prod-02",
                "10.0.3.11",
                "INTERNAL_SERVER",
                "medium",
                ["production"],
            ),
            CMDBAsset(
                "wks-001",
                "wks-admin-01",
                "10.0.10.10",
                "WORKSTATION",
                "medium",
                ["admin"],
            ),
            CMDBAsset(
                "wks-002",
                "wks-user-01",
                "10.0.10.11",
                "WORKSTATION",
                "low",
                ["standard"],
            ),
            CMDBAsset(
                "gst-001",
                "guest-wifi-01",
                "10.0.20.10",
                "GUEST_DEVICE",
                "low",
                ["guest"],
            ),
        ]

    def calculate_endpoint_weights(
        self, assets: list[CMDBAsset]
    ) -> dict[EndpointClass, Decimal]:
        """
        Calculate sensitivity weights per endpoint class based on asset distribution.

        Strategy:
        - For each EndpointClass, compute weighted average of criticality
        - Weight by asset count in that class
        """
        class_criticalities: dict[EndpointClass, list[str]] = {}

        for asset in assets:
            try:
                ep_class = EndpointClass(asset.asset_class)
            except ValueError:
                ep_class = EndpointClass.UNKNOWN

            if ep_class not in class_criticalities:
                class_criticalities[ep_class] = []
            class_criticalities[ep_class].append(asset.criticality)

        weights: dict[EndpointClass, Decimal] = {}

        for ep_class, criticalities in class_criticalities.items():
            # Compute average criticality weight
            total_weight = sum(
                self.criticality_weights.get(c, Decimal("50.0")) for c in criticalities
            )
            avg_weight = total_weight / len(criticalities)

            # Apply minimum floor based on class default
            default_weight = Decimal(str(ep_class.default_base_weight))
            final_weight = max(avg_weight, default_weight)

            # Cap at 100
            weights[ep_class] = min(final_weight, Decimal("100.0"))

        return weights

    async def get_current_active_policy(self) -> RiskPolicy | None:
        """Get the current active policy from database."""
        async with self.db_factory() as session:
            stmt = (
                select(PolicyModel)
                .where(PolicyModel.is_active.is_(True))
                .order_by(PolicyModel.created_at.desc())
            )
            result = await session.execute(stmt)
            active_model = result.scalars().first()

            if not active_model:
                return None

            return RiskPolicy(
                policy_id=active_model.policy_id,
                name=active_model.name,
                version=active_model.version,
                weights=PolicyWeights(
                    behavior=active_model.weight_behavior,
                    frequency=active_model.weight_frequency,
                    sensitivity=active_model.weight_sensitivity,
                    history=active_model.weight_history,
                ),
                thresholds=ThresholdConfig.from_dict(active_model.thresholds_config),
                endpoint_class_weights={
                    EndpointClass(ep): Decimal(str(wt))
                    for ep, wt in (active_model.endpoint_class_weights or {}).items()
                },
                metadata=active_model.metadata_info or {},
                is_active=active_model.is_active,
                created_at=active_model.created_at,
                updated_at=active_model.updated_at,
            )

    def create_sync_policy(
        self, current_policy: RiskPolicy, new_weights: dict[EndpointClass, Decimal]
    ) -> RiskPolicy:
        """Create a new draft policy with updated endpoint class weights."""

        # Merge with existing weights (CMDB weights take precedence for known classes)
        merged_weights = {**current_policy.endpoint_class_weights, **new_weights}

        # Generate version string
        version_suffix = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        new_version = f"{current_policy.version}-cmdb-sync-{version_suffix}"

        new_metadata = {
            **current_policy.metadata,
            "cmdb_sync": {
                "synced_at": datetime.now(UTC).isoformat(),
                "asset_count_by_class": {
                    ep.value: str(wt) for ep, wt in new_weights.items()
                },
                "previous_weights": {
                    ep.value: str(wt)
                    for ep, wt in current_policy.endpoint_class_weights.items()
                },
            },
        }

        return RiskPolicy(
            name=f"CMDB Sync - {new_version}",
            version=new_version,
            description=f"Auto-generated policy from CMDB synchronization at {datetime.now(UTC).isoformat()}. "
            f"Updated endpoint class weights based on {len(new_weights)} asset classes.",
            weights=current_policy.weights,
            thresholds=current_policy.thresholds,
            endpoint_class_weights=merged_weights,
            metadata=new_metadata,
            is_active=False,  # Draft only - requires approval
        )

    async def persist_draft_policy(self, policy: RiskPolicy) -> bool:
        """Persist draft policy to database."""
        async with self.db_factory() as session:
            async with session.begin():
                # Check if version exists
                existing = await session.execute(
                    select(PolicyModel.policy_id).where(
                        PolicyModel.version == policy.version
                    )
                )
                if existing.scalar_one_or_none():
                    logger.warning(
                        "Draft policy version %s already exists", policy.version
                    )
                    return False

                policy_model = PolicyModel(
                    policy_id=policy.policy_id,
                    name=policy.name,
                    version=policy.version,
                    description=policy.description,
                    is_active=policy.is_active,
                    weight_behavior=policy.weights.behavior,
                    weight_frequency=policy.weights.frequency,
                    weight_sensitivity=policy.weights.sensitivity,
                    weight_history=policy.weights.history,
                    thresholds_config=policy.thresholds.to_dict(),
                    endpoint_class_weights={
                        ep.value: float(wt)
                        for ep, wt in policy.endpoint_class_weights.items()
                    },
                    metadata_info=policy.metadata,
                    created_by="system:cmdb-sync",
                    created_at=policy.created_at,
                    updated_at=policy.updated_at,
                )

                session.add(policy_model)
                await session.flush()

                logger.info(
                    "Created CMDB sync draft policy: %s (id=%s)",
                    policy.version,
                    policy.policy_id,
                )
                return True

    async def invalidate_active_policy_cache(self) -> bool:
        """Invalidate the policy:active Redis cache."""
        if self.redis is None:
            return True

        try:
            await self.redis.delete("policy:active")
            logger.info("Invalidated policy:active Redis cache")
            return True
        except Exception as e:
            logger.warning("Failed to invalidate policy cache: %s", e)
            return False

    async def run(self) -> bool:
        """Execute the full CMDB sync job."""
        logger.info("Starting CMDB synchronization job")

        if not self.cmdb_api_url:
            logger.warning("CMDB_API_URL not configured, using mock data")

        try:
            # 1. Fetch assets from CMDB
            assets = await self.fetch_assets()
            if not assets:
                logger.warning("No assets retrieved from CMDB, skipping sync")
                return False

            # 2. Calculate endpoint class weights
            new_weights = self.calculate_endpoint_weights(assets)
            logger.info(
                "Calculated weights for %d endpoint classes: %s",
                len(new_weights),
                {k.value: str(v) for k, v in new_weights.items()},
            )

            # 3. Get current active policy
            current_policy = await self.get_current_active_policy()
            if not current_policy:
                logger.error("No active policy found, cannot create sync draft")
                return False

            # 4. Create draft policy with new weights
            draft_policy = self.create_sync_policy(current_policy, new_weights)

            # 5. Persist draft policy
            success = await self.persist_draft_policy(draft_policy)
            if not success:
                return False

            # 6. Invalidate active policy cache
            await self.invalidate_active_policy_cache()

            logger.info(
                "CMDB synchronization completed successfully: %s", draft_policy.version
            )
            return True

        except Exception:
            logger.exception("CMDB sync job failed")
            return False


async def main() -> None:
    """Entry point for CMDB sync job."""
    db_url = settings.db.ASYNC_DATABASE_URI
    engine = create_async_engine(db_url, pool_pre_ping=True)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    redis_client = None
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        redis_client = aioredis.from_url(redis_url, decode_responses=True)
        try:
            await redis_client.ping()
        except Exception:
            redis_client = None

    job = CMDBsyncJob(
        db_session_factory=session_factory,
        redis_client=redis_client,
        cmdb_api_url=os.getenv("CMDB_API_URL"),
        cmdb_api_key=os.getenv("CMDB_API_KEY"),
        cmdb_page_size=int(os.getenv("CMDB_PAGE_SIZE", "1000")),
    )

    try:
        await job.run()
    finally:
        await engine.dispose()
        if redis_client:
            await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
