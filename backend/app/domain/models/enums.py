"""
Domain enumeration definitions for the Cyber Risk Assessment Platform.
Provides type-safe, validated categorical risk tiers, severities, asset classifications,
and lifecycle states used across scoring, policy governance, and database persistence.
"""

from enum import Enum, unique


class StringValuedEnum(str, Enum):
    """Base enumeration ensuring clean string serialization across JSON APIs and ORMs."""

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def has_value(cls, value: str) -> bool:
        """Utility method to safely verify membership without raising exceptions."""
        return value in cls._value2member_map_


@unique
class RiskCategory(StringValuedEnum):
    """
    Authoritative categorical risk ratings mapped directly to deterministic scoring thresholds.
    Documented Spec Boundaries:
      - LOW:      0.0  to 39.9
      - MEDIUM:  40.0  to 64.9
      - HIGH:    65.0  to 84.9
      - CRITICAL: 85.0 to 100.0
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def requires_containment_approval(self) -> bool:
        """Determines if the rating warrants elevated human-in-the-loop approval workflows."""
        return self is RiskCategory.CRITICAL

    @property
    def requires_soc_case(self) -> bool:
        """Determines if an automated SOC case/ticket must be dispatched."""
        return self in (RiskCategory.HIGH, RiskCategory.CRITICAL)

    @property
    def priority_level(self) -> int:
        """Numerical ordering for priority queues, sorting, and alerting."""
        priority_map = {
            RiskCategory.LOW: 1,
            RiskCategory.MEDIUM: 2,
            RiskCategory.HIGH: 3,
            RiskCategory.CRITICAL: 4,
        }
        return priority_map[self]


@unique
class DetectionSeverity(StringValuedEnum):
    """Initial reported alert severity from sensors, rules, and telemetry sources."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@unique
class DetectionSourceType(StringValuedEnum):
    """Origin telemetry categories feeding the ingestion pipeline."""

    EDR = "EDR"
    SIEM = "SIEM"
    IDS_IPS = "IDS_IPS"
    CLOUD_TRAIL = "CLOUD_TRAIL"
    APP_LOG = "APP_LOG"
    WAZUH = "WAZUH"
    UNKNOWN = "UNKNOWN"


@unique
class EndpointClass(StringValuedEnum):
    """
    Sensitivity classification tiers for network assets and endpoints.
    Used by the static sensitivity weighting calculator.
    """

    CRITICAL_INFRASTRUCTURE = "CRITICAL_INFRASTRUCTURE"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE_SERVER = "DATABASE_SERVER"
    INTERNAL_SERVER = "INTERNAL_SERVER"
    WORKSTATION = "WORKSTATION"
    GUEST_DEVICE = "GUEST_DEVICE"
    UNKNOWN = "UNKNOWN"

    @property
    def default_base_weight(self) -> float:
        """
        Baseline 0-100 normalization factor for asset sensitivity calculations.
        Used as fallback defaults before policy-specific asset profile overrides.
        """
        weight_map = {
            EndpointClass.CRITICAL_INFRASTRUCTURE: 100.0,
            EndpointClass.DOMAIN_CONTROLLER: 95.0,
            EndpointClass.DATABASE_SERVER: 85.0,
            EndpointClass.INTERNAL_SERVER: 65.0,
            EndpointClass.WORKSTATION: 40.0,
            EndpointClass.GUEST_DEVICE: 20.0,
            EndpointClass.UNKNOWN: 50.0,
        }
        return weight_map[self]


@unique
class ComponentDriver(StringValuedEnum):
    """Identifies the dominant sub-score driving the final weighted risk score."""

    BEHAVIOR = "BEHAVIOR"
    FREQUENCY = "FREQUENCY"
    SENSITIVITY = "SENSITIVITY"
    HISTORY = "HISTORY"


@unique
class ExplanationSource(StringValuedEnum):
    """Origin generator of human-readable explainability narratives."""

    DETERMINISTIC_TEMPLATE = "DETERMINISTIC_TEMPLATE"
    CONSTRAINED_LLM = "CONSTRAINED_LLM"
    ANALYST_OVERRIDE = "ANALYST_OVERRIDE"


@unique
class AssessmentStatus(StringValuedEnum):
    """Lifecycle status of a computed risk evaluation record."""

    PENDING = "PENDING"
    COMPUTED = "COMPUTED"
    OVERRIDDEN = "OVERRIDDEN"
    DISMISSED = "DISMISSED"
