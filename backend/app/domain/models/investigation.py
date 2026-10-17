"""
Domain entity models for InvestigationResult.
Defines immutable representations of investigative telemetry, asset sensitivity context,
correlated endpoints, and historical incident tracking consumed by the scoring kernel.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from app.domain.models.enums import EndpointClass


@dataclass(frozen=True, slots=True)
class TouchedEndpoint:
    """
    Detailed metadata for an individual asset or node observed during investigation.
    Supports granular asset sensitivity attribution and audit verification.
    """
    endpoint_id: str
    endpoint_class: EndpointClass = EndpointClass.UNKNOWN
    ip_address: Optional[str] = None
    is_compromised: bool = False

    def __post_init__(self) -> None:
        if not self.endpoint_id or not self.endpoint_id.strip():
            raise ValueError("Endpoint ID cannot be empty or whitespace.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "endpoint_class": self.endpoint_class.value,
            "ip_address": self.ip_address,
            "is_compromised": self.is_compromised,
        }


@dataclass(frozen=True, slots=True)
class InvestigationTelemetry:
    """
    Raw numerical and categorical metrics captured during telemetry correlation.
    Feeds directly into Frequency, Sensitivity, and History component calculators.
    """
    event_frequency: int
    endpoints_touched: int
    endpoint_class: EndpointClass
    historical_incident_count: int
    severity_hint: Optional[Decimal] = None

    def __post_init__(self) -> None:
        if self.event_frequency < 0:
            raise ValueError(f"event_frequency must be non-negative, got {self.event_frequency}")
        if self.endpoints_touched < 0:
            raise ValueError(f"endpoints_touched must be non-negative, got {self.endpoints_touched}")
        if self.historical_incident_count < 0:
            raise ValueError(
                f"historical_incident_count must be non-negative, got {self.historical_incident_count}"
            )

        if self.severity_hint is not None:
            sev = self.severity_hint
            if not isinstance(sev, Decimal):
                sev = Decimal(str(sev))
                object.__setattr__(self, "severity_hint", sev)
            q_sev = sev.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            object.__setattr__(self, "severity_hint", q_sev)
            if not (Decimal("0.0") <= q_sev <= Decimal("100.0")):
                raise ValueError(f"severity_hint must be bounded between [0.0, 100.0], got {q_sev}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_frequency": self.event_frequency,
            "endpoints_touched": self.endpoints_touched,
            "endpoint_class": self.endpoint_class.value,
            "historical_incident_count": self.historical_incident_count,
            "severity_hint": float(self.severity_hint) if self.severity_hint is not None else None,
        }


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    """
    Authoritative domain model for completed investigations.
    Preserves immutable investigation findings, correlation tracking, and evidence digests.
    """
    detection_event_id: UUID
    correlation_id: UUID
    telemetry: InvestigationTelemetry
    investigation_id: UUID = field(default_factory=uuid4)
    touched_endpoints: List[TouchedEndpoint] = field(default_factory=list)
    mitre_attack_techniques: List[str] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    investigated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate UTC timezone bounds for all timestamps."""
        for ts_field in ("investigated_at", "created_at"):
            ts_val: datetime = getattr(self, ts_field)
            if ts_val.tzinfo is None:
                object.__setattr__(self, ts_field, ts_val.replace(tzinfo=timezone.utc))
            else:
                object.__setattr__(self, ts_field, ts_val.astimezone(timezone.utc))

    @property
    def event_frequency(self) -> int:
        """Accessor for total occurrences observed across the correlation window."""
        return self.telemetry.event_frequency

    @property
    def endpoints_touched(self) -> int:
        """Accessor for count of endpoints touched in lateral activity."""
        return self.telemetry.endpoints_touched

    @property
    def endpoint_class(self) -> EndpointClass:
        """Accessor for primary asset sensitivity tier."""
        return self.telemetry.endpoint_class

    @property
    def historical_incident_count(self) -> int:
        """Accessor for source's previous confirmed incidents."""
        return self.telemetry.historical_incident_count

    @property
    def severity_hint(self) -> Optional[Decimal]:
        """Accessor for optional pre-computed investigation severity hint."""
        return self.telemetry.severity_hint

    def resolve_dominant_endpoint_class(self) -> EndpointClass:
        """
        Dynamically derives the highest-risk endpoint classification from touched endpoints
        if itemized endpoint records are present, falling back to telemetry.endpoint_class.
        """
        if not self.touched_endpoints:
            return self.telemetry.endpoint_class

        # Rank order by highest base weight
        sorted_endpoints = sorted(
            self.touched_endpoints,
            key=lambda ep: ep.endpoint_class.default_base_weight,
            reverse=True,
        )
        return sorted_endpoints[0].endpoint_class

    def to_dict(self) -> Dict[str, Any]:
        """Serializes investigation results into a clean dictionary contract."""
        return {
            "investigation_id": str(self.investigation_id),
            "detection_event_id": str(self.detection_event_id),
            "correlation_id": str(self.correlation_id),
            "telemetry": self.telemetry.to_dict(),
            "touched_endpoints": [ep.to_dict() for ep in self.touched_endpoints],
            "mitre_attack_techniques": self.mitre_attack_techniques,
            "evidence_summary": self.evidence_summary,
            "investigated_at": self.investigated_at.isoformat(),
            "created_at": self.created_at.isoformat(),
        }