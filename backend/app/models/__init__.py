"""
Compatibility shim for app.models -> app.domain.models
Provides backwards compatibility for imports expecting app.models.* modules.
"""

from app.domain.models import assessment, detection, enums, investigation, policy

__all__ = [
    "assessment",
    "detection",
    "enums",
    "investigation",
    "policy",
]

# Re-export key classes for direct imports
from app.domain.models.assessment import (
    AppliedPolicySnapshot,
    RiskAssessment,
    RiskComponents,
)
from app.domain.models.detection import (
    DetectionContext,
    DetectionEvent,
    DetectionMetrics,
)
from app.domain.models.enums import (
    AssessmentStatus,
    ComponentDriver,
    DetectionSeverity,
    DetectionSourceType,
    EndpointClass,
    ExplanationSource,
    RiskCategory,
)
from app.domain.models.investigation import (
    InvestigationResult,
    InvestigationTelemetry,
    TouchedEndpoint,
)
from app.domain.models.policy import (
    CategoryThresholdRange,
    PolicyWeights,
    RiskPolicy,
    ThresholdConfig,
)

__all__.extend([
    "AppliedPolicySnapshot",
    "AssessmentStatus",
    "CategoryThresholdRange",
    "ComponentDriver",
    "DetectionContext",
    "DetectionEvent",
    "DetectionMetrics",
    "DetectionSeverity",
    "DetectionSourceType",
    "EndpointClass",
    "ExplanationSource",
    "InvestigationResult",
    "InvestigationTelemetry",
    "PolicyWeights",
    "RiskAssessment",
    "RiskCategory",
    "RiskComponents",
    "RiskPolicy",
    "ThresholdConfig",
    "TouchedEndpoint",
])