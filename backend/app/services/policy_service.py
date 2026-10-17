"""
Policy Management Orchestration Service.
Handles lifecycle operations for RiskPolicy configurations including creation,
versioning, continuous threshold invariant validation, weight normalization checks,
and atomic activation/deactivation within PostgreSQL transactions.
"""

from decimal import Decimal
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    BaseAppException,
    InvariantViolationException,
    PolicyNotFoundException,
)
from app.core.telemetry import get_tracer
from app.db.models.policy import PolicyModel
from app.domain.engine.invariants import (
    InvariantViolationError,
    ScoringInvariantVerifier,
)
from app.domain.models.enums import EndpointClass, RiskCategory
from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)
from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyResponse,
    PolicyUpdateRequest,
)

logger = logging.getLogger(__name__)
tracer = get_tracer()


class PolicyConflictException(BaseAppException):
    """Raised when an operation attempts to register a duplicate policy version."""

    def __init__(self, version: str) -> None:
        super().__init__(
            message=f"A policy with version '{version}' already exists.",
            error_code="POLICY_VERSION_EXISTS",
            status_code=409,
            context={"version": version},
        )


class PolicyManagementService:
    """
    Orchestrates the governance, validation, and lifecycle transitions
    of versioned risk policies.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        verifier: Optional[ScoringInvariantVerifier] = None,
    ) -> None:
        self.db = db_session
        self.verifier = verifier or ScoringInvariantVerifier()

    async def get_active_policy(self) -> PolicyResponse:
        """Retrieves the authoritative active risk policy, ordered by creation time."""
        with tracer.start_as_current_span("policy_service.get_active_policy"):
            stmt = (
                select(PolicyModel)
                .where(PolicyModel.is_active.is_(True))
                .order_by(PolicyModel.created_at.desc())
            )
            result = await self.db.execute(stmt)
            policy_model = result.scalars().first()

            if policy_model is None:
                raise PolicyNotFoundException(policy_identifier="ACTIVE")

            return self._model_to_response(policy_model)

    async def get_policy_by_version(self, version: str) -> PolicyResponse:
        """Retrieves a specific policy by its immutable version identifier."""
        with tracer.start_as_current_span("policy_service.get_policy_by_version") as span:
            span.set_attribute("policy_version", version)
            policy_model = await self._find_model_by_version(version)
            return self._model_to_response(policy_model)

    async def get_policy_by_id(self, policy_id: UUID) -> PolicyResponse:
        """Retrieves a specific policy by its UUID primary key."""
        with tracer.start_as_current_span("policy_service.get_policy_by_id"):
            stmt = select(PolicyModel).where(PolicyModel.policy_id == policy_id)
            result = await self.db.execute(stmt)
            policy_model = result.scalars().first()

            if policy_model is None:
                raise PolicyNotFoundException(policy_identifier=str(policy_id))

            return self._model_to_response(policy_model)

    async def list_policies(
        self,
        include_inactive: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[PolicyResponse]:
        """Lists registered risk policies ordered chronologically."""
        with tracer.start_as_current_span("policy_service.list_policies"):
            stmt = select(PolicyModel)
            if not include_inactive:
                stmt = stmt.where(PolicyModel.is_active.is_(True))

            stmt = stmt.order_by(PolicyModel.created_at.desc()).limit(limit).offset(offset)
            result = await self.db.execute(stmt)
            records = result.scalars().all()

            return [self._model_to_response(model) for model in records]

    async def create_policy(
        self,
        request: PolicyCreateRequest,
        actor_identifier: Optional[str] = None,
    ) -> PolicyResponse:
        """
        Creates and registers a new Risk Policy.
        Validates mathematical unity of weights (sum = 1.00) and threshold boundary continuity
        before persisting to PostgreSQL.
        """
        with tracer.start_as_current_span("policy_service.create_policy") as span:
            span.set_attribute("policy_version", request.version)

            # Check if version already exists
            existing_stmt = select(PolicyModel.policy_id).where(PolicyModel.version == request.version)
            existing = await self.db.execute(existing_stmt)
            if existing.scalar_one_or_none() is not None:
                raise PolicyConflictException(version=request.version)

            # Validate domain policy models & mathematical invariants
            policy_domain = self._construct_domain_policy(request)
            self._validate_policy_invariants(policy_domain)

            # If the new policy is marked active, deactivate existing active policies
            if request.is_active:
                await self._deactivate_all_policies()

            # Construct and persist ORM model
            policy_model = PolicyModel(
                policy_id=policy_domain.policy_id,
                name=policy_domain.name,
                version=policy_domain.version,
                description=request.description,
                is_active=request.is_active,
                weight_behavior=policy_domain.weights.behavior,
                weight_frequency=policy_domain.weights.frequency,
                weight_sensitivity=policy_domain.weights.sensitivity,
                weight_history=policy_domain.weights.history,
                thresholds_config=self._serialize_thresholds(policy_domain.thresholds),
                endpoint_class_weights={
                    k.value: str(v) for k, v in policy_domain.endpoint_class_weights.items()
                },
                metadata_info=request.metadata or {},
                created_by=actor_identifier,
            )

            self.db.add(policy_model)
            await self.db.flush()

            logger.info(
                "Created risk policy version=%s (id=%s, active=%s)",
                policy_model.version,
                policy_model.policy_id,
                policy_model.is_active,
            )
            return self._model_to_response(policy_model)

    async def activate_policy(self, version: str) -> PolicyResponse:
        """
        Activates a specific policy version and deactivates any other active policy atomically.
        """
        with tracer.start_as_current_span("policy_service.activate_policy") as span:
            span.set_attribute("target_policy_version", version)
            policy_model = await self._find_model_by_version(version)

            if not policy_model.is_active:
                await self._deactivate_all_policies()
                policy_model.is_active = True
                await self.db.flush()
                logger.info("Activated policy version=%s", version)

            return self._model_to_response(policy_model)

    async def update_policy(
        self,
        version: str,
        request: PolicyUpdateRequest,
    ) -> PolicyResponse:
        """
        Updates non-invariance mutable fields (e.g., description, metadata tags) of a policy.
        """
        with tracer.start_as_current_span("policy_service.update_policy"):
            policy_model = await self._find_model_by_version(version)

            if request.description is not None:
                policy_model.description = request.description
            if request.metadata is not None:
                policy_model.metadata_info = request.metadata

            await self.db.flush()
            return self._model_to_response(policy_model)

    # --- Private Utility and Mapping Methods ---

    async def _find_model_by_version(self, version: str) -> PolicyModel:
        stmt = select(PolicyModel).where(PolicyModel.version == version)
        result = await self.db.execute(stmt)
        model = result.scalars().first()
        if model is None:
            raise PolicyNotFoundException(policy_identifier=version)
        return model

    async def _deactivate_all_policies(self) -> None:
        stmt = update(PolicyModel).where(PolicyModel.is_active.is_(True)).values(is_active=False)
        await self.db.execute(stmt)

    def _validate_policy_invariants(self, policy: RiskPolicy) -> None:
        """Enforces weight sum unity ($1.00$) and threshold continuity."""
        try:
            self.verifier.verify_policy_invariants(policy)
        except InvariantViolationError as inv_err:
            logger.error("Policy invariant check failed: %s", inv_err, exc_info=True)
            raise InvariantViolationException(
                message=inv_err.message,
                rule_name=inv_err.rule_name,
                context=inv_err.details,
            ) from inv_err

    def _construct_domain_policy(self, request: PolicyCreateRequest) -> RiskPolicy:
        """
        Translate the API schema into the domain policy entity.

        The API schema stores flat cumulative boundaries (low_max,
        medium_max, high_max, critical_min); the domain requires explicit
        contiguous tiers covering [0.0, 100.0]. Tier starts are derived as
        previous_max + 0.1, matching the canonical 0.1 quantization step.
        """
        low_max = Decimal(str(request.thresholds.low_max))
        medium_max = Decimal(str(request.thresholds.medium_max))
        high_max = Decimal(str(request.thresholds.high_max))
        critical_min = Decimal(str(request.thresholds.critical_min))

        tiers = (
            CategoryThresholdRange(
                category=RiskCategory.LOW,
                min_score=Decimal("0.0"),
                max_score=low_max,
            ),
            CategoryThresholdRange(
                category=RiskCategory.MEDIUM,
                min_score=low_max + Decimal("0.1"),
                max_score=medium_max,
            ),
            CategoryThresholdRange(
                category=RiskCategory.HIGH,
                min_score=medium_max + Decimal("0.1"),
                max_score=high_max,
            ),
            CategoryThresholdRange(
                category=RiskCategory.CRITICAL,
                min_score=critical_min,
                max_score=Decimal("100.0"),
            ),
        )

        endpoint_weights = {
            EndpointClass(k): Decimal(str(v))
            for k, v in (request.endpoint_class_weights or {}).items()
        }

        return RiskPolicy(
            policy_id=uuid4(),
            name=request.name,
            version=str(request.version),
            weights=PolicyWeights(
                behavior=Decimal(str(request.weights.behavior_weight)),
                frequency=Decimal(str(request.weights.frequency_weight)),
                sensitivity=Decimal(str(request.weights.sensitivity_weight)),
                history=Decimal(str(request.weights.history_weight)),
            ),
            thresholds=ThresholdConfig(tiers=tiers),
            endpoint_class_weights=endpoint_weights,
            is_active=request.is_active,
        )

    def _serialize_thresholds(self, thresholds: ThresholdConfig) -> Dict[str, Any]:
        return {
            "tiers": [
                {
                    "category": tier.category.value,
                    "min_score": str(tier.min_score),
                    "max_score": str(tier.max_score),
                }
                for tier in thresholds.tiers
            ]
        }

    def _model_to_response(self, model: PolicyModel) -> PolicyResponse:
        return PolicyResponse(
            policy_id=model.policy_id,
            name=model.name,
            version=model.version,
            description=model.description,
            is_active=model.is_active,
            weights={
                "behavior": float(model.weight_behavior),
                "frequency": float(model.weight_frequency),
                "sensitivity": float(model.weight_sensitivity),
                "history": float(model.weight_history),
            },
            thresholds_config=model.thresholds_config,
            endpoint_class_weights=model.endpoint_class_weights,
            metadata_info=model.metadata_info,
            created_by=model.created_by,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )