"""
Compatibility shim for app.models.investigation -> app.domain.models.investigation
"""

from app.domain.models.investigation import (
    InvestigationResult,
    InvestigationTelemetry,
    TouchedEndpoint,
)

__all__ = [
    "InvestigationResult",
    "InvestigationTelemetry",
    "TouchedEndpoint",
]
