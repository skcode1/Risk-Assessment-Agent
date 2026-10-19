"""
Compatibility shim for app.models.assessment -> app.domain.models.assessment
"""

from app.domain.models.assessment import (
    AppliedPolicySnapshot,
    RiskAssessment,
    RiskComponents,
)

__all__ = [
    "AppliedPolicySnapshot",
    "RiskAssessment",
    "RiskComponents",
]