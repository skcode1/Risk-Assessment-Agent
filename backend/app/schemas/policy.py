"""
Pydantic v2 Schema Definitions for Risk Policy and Weight Configurations.
Enforces weights invariants (B + F + S + H = 1.0) and threshold mappings.
Supports both flat API payloads and nested Domain/ORM representations.
"""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


class PolicyWeights(BaseModel):
    """Normalized risk component weights summing to 1.0."""
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    behavior_weight: Annotated[
        float,
        Field(default=0.4, ge=0.0, le=1.0, description="Weight multiplier for behavior sub-score."),
    ]
    frequency_weight: Annotated[
        float,
        Field(default=0.3, ge=0.0, le=1.0, description="Weight multiplier for event frequency sub-score."),
    ]
    sensitivity_weight: Annotated[
        float,
        Field(default=0.2, ge=0.0, le=1.0, description="Weight multiplier for endpoint sensitivity sub-score."),
    ]
    history_weight: Annotated[
        float,
        Field(default=0.1, ge=0.0, le=1.0, description="Weight multiplier for historical incident sub-score."),
    ]

    @model_validator(mode="before")
    @classmethod
    def normalize_domain_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            normalized = dict(data)
            key_map = {
                "behavior": "behavior_weight",
                "frequency": "frequency_weight",
                "sensitivity": "sensitivity_weight",
                "history": "history_weight",
            }
            for short_k, full_k in key_map.items():
                if short_k in normalized and full_k not in normalized:
                    normalized[full_k] = normalized.pop(short_k)
                elif short_k in normalized and full_k in normalized:
                    normalized.pop(short_k)
            return normalized
        return data

    @model_validator(mode="after")
    def validate_weights_sum(self) -> "PolicyWeights":
        total = round(
            self.behavior_weight + self.frequency_weight + self.sensitivity_weight + self.history_weight,
            4,
        )
        if total != 1.0:
            raise ValueError(f"Weights must sum exactly to 1.0. Current sum: {total}")
        return self


class PolicyThresholds(BaseModel):
    """Categorical boundary cutoffs for risk scores [0 - 100]."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    low_max: Annotated[float, Field(default=39.9, ge=0.0, le=100.0, description="Upper bound for LOW category.")]
    medium_max: Annotated[float, Field(default=64.9, ge=0.0, le=100.0, description="Upper bound for MEDIUM category.")]
    high_max: Annotated[float, Field(default=84.9, ge=0.0, le=100.0, description="Upper bound for HIGH category.")]
    critical_min: Annotated[float, Field(default=85.0, ge=0.0, le=100.0, description="Lower bound for CRITICAL category.")]

    @model_validator(mode="before")
    @classmethod
    def normalize_tier_dict(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Convert nested domain/test tier format: {"low": {"min_score": 0, "max_score": 39.9}, ...}
            lower_keys = {k.lower(): v for k, v in data.items()}
            if {"low", "medium", "high", "critical"}.issubset(lower_keys.keys()):
                def _extract_bound(tier_obj: Any, bound_type: str) -> float:
                    if isinstance(tier_obj, (list, tuple)) and len(tier_obj) == 2:
                        return float(tier_obj[0] if bound_type == "min" else tier_obj[1])
                    if isinstance(tier_obj, dict):
                        for k in (f"{bound_type}_score", f"{bound_type}_val", bound_type):
                            if k in tier_obj and tier_obj[k] is not None:
                                return float(tier_obj[k])
                    raise ValueError(f"Invalid threshold tier structure: {tier_obj}")

                return {
                    "low_max": _extract_bound(lower_keys["low"], "max"),
                    "medium_max": _extract_bound(lower_keys["medium"], "max"),
                    "high_max": _extract_bound(lower_keys["high"], "max"),
                    "critical_min": _extract_bound(lower_keys["critical"], "min"),
                }
        return data

    @model_validator(mode="after")
    def validate_monotonic_thresholds(self) -> "PolicyThresholds":
        if not (self.low_max < self.medium_max < self.high_max <= self.critical_min):
            raise ValueError("Threshold bounds must be monotonically strictly increasing: low < medium < high <= critical")
        return self


class PolicyBase(BaseModel):
    """Base definition attributes for a scoring policy configuration."""
    model_config = ConfigDict(str_strip_whitespace=True, populate_by_name=True)

    name: Annotated[
        str,
        Field(..., min_length=2, max_length=128, description="Human-readable policy name."),
    ]
    description: Annotated[
        Optional[str],
        Field(default=None, max_length=512, description="Operational scope or governance description."),
    ]
    weights: Annotated[
        PolicyWeights,
        Field(default_factory=PolicyWeights, description="Mathematical sub-score weight configuration."),
    ]
    thresholds: Annotated[
        PolicyThresholds,
        Field(default_factory=PolicyThresholds, description="Score to categorical rating thresholds."),
    ]
    is_active: Annotated[
        bool,
        Field(default=True, description="Indicates if this policy version is active for scoring."),
    ]


class PolicyCreateRequest(PolicyBase):
    """Ingestion schema expected by POST /api/v1/policies."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    policy_id: Annotated[Optional[UUID], Field(default=None)]
    version: Annotated[Optional[Union[str, int]], Field(default="risk-policy-2026-01")]
    endpoint_class_weights: Annotated[Dict[str, float], Field(default_factory=dict)]
    metadata: Annotated[Dict[str, Any], Field(default_factory=dict)]


class PolicyUpdateRequest(BaseModel):
    """Schema for updating or patching an existing policy."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    weights: Optional[PolicyWeights] = None
    thresholds: Optional[PolicyThresholds] = None
    is_active: Optional[bool] = None
    endpoint_class_weights: Optional[Dict[str, float]] = None
    metadata: Optional[Dict[str, Any]] = None


class PolicyResponse(PolicyBase):
    """Canonical output schema for a persisted risk policy."""
    model_config = ConfigDict(from_attributes=True, extra="ignore", populate_by_name=True)

    policy_id: UUID = Field(default_factory=uuid4)
    version: Union[str, int] = Field(default="risk-policy-2026-01")
    endpoint_class_weights: Dict[str, float] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyListResponse(BaseModel):
    """Paginated or list wrapper for multiple risk policies."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    items: List[PolicyResponse] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
