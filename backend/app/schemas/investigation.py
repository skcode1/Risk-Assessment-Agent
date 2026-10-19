"""
Pydantic v2 Schema Definitions for InvestigationResult Payloads.
Fully aligned with canonical schemas/investigation/investigation-result-v1.json.
Provides full support for investigation ingestion, audit detail, query parameters,
and risk kernel contracts.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


class EndpointClass(str, Enum):
    """Asset sensitivity tier classification."""
    CRITICAL_INFRASTRUCTURE = "CRITICAL_INFRASTRUCTURE"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE_SERVER = "DATABASE_SERVER"
    INTERNAL_SERVER = "INTERNAL_SERVER"
    WORKSTATION = "WORKSTATION"
    GUEST_DEVICE = "GUEST_DEVICE"
    UNKNOWN = "UNKNOWN"


class TouchedEndpointDetail(BaseModel):
    """Metadata regarding an individual asset touched during the incident window."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoint_id: Annotated[
        str,
        Field(..., min_length=1, max_length=128, description="Asset tag, hostname, or hardware UUID."),
    ]
    endpoint_class: Annotated[
        EndpointClass,
        Field(default=EndpointClass.UNKNOWN, description="Sensitivity classification of this asset."),
    ]
    ip_address: Annotated[
        str | None,
        Field(default=None, description="IP address observed on this asset during the event window."),
    ]
    is_compromised: Annotated[
        bool,
        Field(default=False, description="Flag indicating active exploitation vs benign telemetry contact."),
    ]


# Alias expected by app.services.investigation_service
TouchedEndpointSchema = TouchedEndpointDetail


class InvestigationTelemetryMetrics(BaseModel):
    """
    Core numerical metrics captured by the Investigation Layer.
    These fields feed directly into the Frequency, Sensitivity, and History calculators.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_frequency: Annotated[
        int,
        Field(
            ...,
            ge=0,
            description="Count of similar detection events observed across the correlation window.",
            examples=[17],
        ),
    ]
    endpoints_touched: Annotated[
        int,
        Field(
            ...,
            ge=0,
            description="Total number of unique endpoints or nodes involved in the lateral chain.",
            examples=[4],
        ),
    ]
    endpoint_class: Annotated[
        EndpointClass,
        Field(
            ...,
            description="Dominant or highest-severity endpoint sensitivity tier involved.",
            examples=[EndpointClass.CRITICAL_INFRASTRUCTURE],
        ),
    ]
    historical_incident_count: Annotated[
        int,
        Field(
            ...,
            ge=0,
            description="Total prior confirmed security incidents associated with this source identity/entity.",
            examples=[3],
        ),
    ]
    severity_hint: Annotated[
        float | None,
        Field(
            default=None,
            ge=0.0,
            le=100.0,
            description="Statistical or behavioral severity indicator synthesized by investigation services.",
            examples=[80.0],
        ),
    ]


class InvestigationResultBase(BaseModel):
    """Base fields representing core investigation findings."""
    detection_event_id: Annotated[
        UUID,
        Field(..., description="ID of the originating DetectionEvent triggering this investigation."),
    ]
    correlation_id: Annotated[
        UUID,
        Field(..., description="Distributed correlation ID spanning detection through risk assessment."),
    ]
    telemetry: Annotated[
        InvestigationTelemetryMetrics,
        Field(..., description="Correlated counts, touched endpoints, and historical metrics."),
    ]
    touched_endpoints_detail: Annotated[
        list[TouchedEndpointDetail],
        Field(
            default_factory=list,
            description="Itemized list of all assets touched, supporting multi-endpoint sensitivity audits.",
        ),
    ]
    mitre_attack_techniques: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="List of MITRE ATT&CK technique IDs correlated during investigation.",
            examples=[["T1059.001", "T1078"]],
        ),
    ]
    evidence_summary: Annotated[
        dict[str, Any],
        Field(
            default_factory=dict,
            description="Structured investigation evidence key-value store.",
        ),
    ]


class InvestigationResultCreate(InvestigationResultBase):
    """Ingestion/generation payload model submitted by the Investigation Layer."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    investigation_id: Annotated[
        UUID | None,
        Field(
            default=None,
            description="Client-supplied or worker-generated investigation ID. Generated if omitted.",
        ),
    ]
    investigated_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp when the investigation analysis completed.",
        ),
    ]

    @field_validator("investigated_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


# Endpoint request alias expected by app.api.v1.endpoints.investigation
InvestigationCreateRequest = InvestigationResultCreate


class InvestigationResult(InvestigationResultBase):
    """Authoritative InvestigationResult contract consumed by the Risk Scoring Engine."""
    model_config = ConfigDict(
        from_attributes=True,
        frozen=True,
        extra="ignore",
        json_schema_serialization_defaults_required=True,
    )

    investigation_id: Annotated[
        UUID,
        Field(
            default_factory=uuid4,
            description="Unique immutable identifier for this investigation record.",
        ),
    ]
    investigated_at: Annotated[
        datetime,
        Field(..., description="Normalized UTC timestamp representing investigation completion."),
    ]
    created_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp when the investigation record was persisted.",
        ),
    ]

    @property
    def event_frequency(self) -> int:
        return self.telemetry.event_frequency

    @property
    def endpoints_touched(self) -> int:
        return self.telemetry.endpoints_touched

    @property
    def endpoint_class(self) -> EndpointClass:
        return self.telemetry.endpoint_class

    @property
    def historical_incident_count(self) -> int:
        return self.telemetry.historical_incident_count

    @classmethod
    def from_create(cls, payload: InvestigationResultCreate) -> "InvestigationResult":
        return cls(
            investigation_id=payload.investigation_id or uuid4(),
            detection_event_id=payload.detection_event_id,
            correlation_id=payload.correlation_id,
            telemetry=payload.telemetry,
            touched_endpoints_detail=payload.touched_endpoints_detail,
            mitre_attack_techniques=payload.mitre_attack_techniques,
            evidence_summary=payload.evidence_summary,
            investigated_at=payload.investigated_at,
            created_at=datetime.now(UTC),
        )


class InvestigationResponse(InvestigationResultBase):
    """Standard persisted investigation entity returned by API endpoints."""
    model_config = ConfigDict(from_attributes=True)

    investigation_id: Annotated[UUID, Field(..., description="Unique investigation entity UUID.")]
    investigated_at: Annotated[datetime, Field(..., description="UTC completion timestamp.")]
    created_at: Annotated[
        datetime,
        Field(default_factory=lambda: datetime.now(UTC), description="Persistence timestamp."),
    ]


class InvestigationDetailResponse(InvestigationResponse):
    """Expanded forensic detail response returned by GET /api/v1/investigations/{id}."""
    model_config = ConfigDict(from_attributes=True)

    status: Annotated[
        str,
        Field(default="COMPLETED", description="Investigation status (e.g., PENDING, IN_PROGRESS, COMPLETED)."),
    ]
    analyst_notes: Annotated[
        str | None,
        Field(default=None, description="Optional reviewer commentary or triage context."),
    ]
    updated_at: Annotated[
        datetime | None,
        Field(default=None, description="Timestamp of the most recent update."),
    ]


class InvestigationListResponse(BaseModel):
    """Paginated collection wrapper for investigation entities."""
    model_config = ConfigDict(from_attributes=True)

    items: Annotated[
        list[InvestigationResponse],
        Field(..., description="Array of investigation summaries."),
    ]
    total: Annotated[int, Field(..., ge=0, description="Total matching records.")]
    limit: Annotated[int, Field(..., ge=1, description="Page limit.")]
    offset: Annotated[int, Field(..., ge=0, description="Page offset.")]


class InvestigationFilterParams(BaseModel):
    """Query parameter validation model for searching investigations."""
    model_config = ConfigDict(extra="forbid")

    detection_event_id: UUID | None = Field(default=None, description="Filter by detection event UUID.")
    correlation_id: UUID | None = Field(default=None, description="Filter by distributed correlation ID.")
    endpoint_class: EndpointClass | None = Field(default=None, description="Filter by asset tier.")
    min_frequency: int | None = Field(default=None, ge=0, description="Filter by minimum event frequency.")
    start_time: datetime | None = Field(default=None, description="Inclusive starting timestamp.")
    end_time: datetime | None = Field(default=None, description="Inclusive ending timestamp.")
    limit: int = Field(default=50, ge=1, le=500, description="Page size limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")