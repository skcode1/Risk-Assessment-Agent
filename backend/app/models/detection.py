"""
Compatibility shim for app.models.detection -> app.domain.models.detection
"""

from app.domain.models.detection import (
    DetectionContext,
    DetectionEvent,
    DetectionMetrics,
)

__all__ = [
    "DetectionContext",
    "DetectionEvent",
    "DetectionMetrics",
]