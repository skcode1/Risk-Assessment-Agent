"""
Compatibility shim for app.models.policy -> app.domain.models.policy
"""

from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)

__all__ = [
    "CategoryThresholdRange",
    "PolicyWeights",
    "RiskPolicy",
    "ThresholdConfig",
]
