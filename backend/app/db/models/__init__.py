"""
Database Models Registry.
Exports all SQLAlchemy 2.0 entities for clean imports and Alembic discovery.
"""

from app.db.models.assessment import RiskAssessmentModel
from app.db.models.audit import AuditLogModel
from app.db.models.detection import DetectionModel
from app.db.models.explanation import RiskExplanationModel
from app.db.models.investigation import InvestigationModel
from app.db.models.policy import PolicyModel

__all__ = [
    "AuditLogModel",
    "DetectionModel",
    "InvestigationModel",
    "PolicyModel",
    "RiskAssessmentModel",
    "RiskExplanationModel",
]