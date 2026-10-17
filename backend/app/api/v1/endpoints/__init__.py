"""
API v1 Endpoints Package Initialization.
Exports route modules for router registration with backwards-compatible aliases.
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
try:
    from app.api.v1.endpoints import risk_assessments
except ImportError:
    try:
        from app.api.v1.endpoints import risk_assessment as risk_assessments
    except ImportError:
        from app.api.v1.endpoints import assessment as risk_assessments

__all__ = [
    "health",
    "detections",
    "investigations",
    "policies",
    "risk_assessments",
]