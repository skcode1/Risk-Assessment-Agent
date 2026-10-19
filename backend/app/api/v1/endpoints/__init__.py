"""
API v1 Endpoints Package Initialization.
Exports route modules for router registration.
"""

# Core health checks
from app.api.v1.endpoints import health

# Detections
try:
    from app.api.v1.endpoints import detections
except ImportError:
    from app.api.v1.endpoints import detection as detections

# Investigations
try:
    from app.api.v1.endpoints import investigations
except ImportError:
    from app.api.v1.endpoints import investigation as investigations

# Policies
try:
    from app.api.v1.endpoints import policies
except ImportError:
    from app.api.v1.endpoints import policy as policies

# Risk Assessments
from app.api.v1.endpoints import risk_assessment as risk_assessments

__all__ = [
    "detections",
    "health",
    "investigations",
    "policies",
    "risk_assessments",
]
