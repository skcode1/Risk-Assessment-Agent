"""
Pydantic v2 Schema Definitions for DetectionEvent Payloads.
Fully aligned with canonical schemas/detection/detection-event-v1.json.
Provides complete ingestion, audit detail, query filter, and list serialization models.
"""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


class DetectionBase(BaseModel):
    """Core common attributes representing a normalized detection event."""

    model_config = ConfigDict(str_strip_whitespace=True)

    source_ip: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            max_length=64,
            description="Originating IPv4 or IPv6 entity address under monitoring.",
            examples=["192.168.1.105", "10.0.4.15"],
        ),
    ]
    confidence: Annotated[
        float,
        Field(
            ...,
            ge=0.0,
            le=1.0,
            description="Normalized detector confidence score between 0.0 and 1.0.",
            examples=[0.92],
        ),
    ]
    event_type: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            max_length=128,
            description="Categorical alert signature, rule identifier, or event name.",
            examples=["credential_access", "privilege_escalation"],
        ),
    ]
    metadata: Annotated[
        dict[str, Any],
        Field(
            default_factory=dict,
            description="Contextual metadata, source headers, or sensor telemetry attributes.",
        ),
    ]


class DetectionCreateRequest(DetectionBase):
    """
    Ingest payload contract consumed by POST /api/v1/detections.
    Accepts optional caller-defined IDs with robust UTC timestamp defaults.
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "source_ip": "10.0.12.84",
                "confidence": 0.88,
                "event_type": "lateral_movement",
                "metadata": {
                    "sensor_id": "sensor-eu-west-01",
                    "protocol": "SMB",
                    "target_host": "dc01.corp.internal",
                },
            }
        },
    )

    detection_id: Annotated[
        UUID | None,
        Field(
            default=None,
            description="Client-supplied correlation ID. Automatically generated if omitted.",
        ),
    ]
    timestamp: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp representing when the signal was initially captured.",
        ),
    ]

    @field_validator("timestamp")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class DetectionResponse(DetectionBase):
    """Standard persisted detection entity returned in summary views and list payloads."""

    model_config = ConfigDict(from_attributes=True)

    detection_id: Annotated[
        UUID,
        Field(..., description="Unique immutable detection entity UUID."),
    ]
    timestamp: Annotated[
        datetime,
        Field(..., description="UTC event timestamp."),
    ]
    created_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="Database record persistence timestamp.",
        ),
    ]


class DetectionDetailResponse(DetectionResponse):
    """
    Expanded audit and diagnostic payload returned by GET /api/v1/detections/{id}.
    Enriches basic event telemetry with investigation linkages, triage status, and tags.
    """

    model_config = ConfigDict(from_attributes=True)

    investigation_id: Annotated[
        UUID | None,
        Field(
            default=None,
            description="Linked investigation record UUID if automatic or manual triage was initiated.",
        ),
    ]
    is_processed: Annotated[
        bool,
        Field(
            default=False,
            description="Flag indicating whether this event has been evaluated by the risk scoring kernel.",
        ),
    ]
    severity_level: Annotated[
        str | None,
        Field(
            default=None,
            description="Derived raw signal severity tier (e.g., LOW, MEDIUM, HIGH, CRITICAL).",
        ),
    ]
    raw_payload: Annotated[
        dict[str, Any],
        Field(
            default_factory=dict,
            description="Complete un-sanitized ingestion payload for forensic audit trails.",
        ),
    ]
    tags: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="SecOps categorization tags, environment labels, or MITRE ATT&CK hints.",
            examples=[["mitre:t1078", "env:production"]],
        ),
    ]
    updated_at: Annotated[
        datetime | None,
        Field(
            default=None,
            description="Timestamp of the most recent modification or status update.",
        ),
    ]


class DetectionListResponse(BaseModel):
    """Paginated collection response wrapper for detection events."""

    model_config = ConfigDict(from_attributes=True)

    items: Annotated[
        list[DetectionResponse],
        Field(
            ..., description="Array of detection records matching the query parameters."
        ),
    ]
    total: Annotated[
        int,
        Field(..., ge=0, description="Total number of matching detection events."),
    ]
    limit: Annotated[
        int,
        Field(..., ge=1, description="Requested page size limit."),
    ]
    offset: Annotated[
        int,
        Field(..., ge=0, description="Offset applied to the query."),
    ]


class DetectionFilterParams(BaseModel):
    """Query parameter validation model for detection searches."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str | None = Field(
        default=None, description="Filter by exact source IP address."
    )
    event_type: str | None = Field(
        default=None, description="Filter by alert signature or event category."
    )
    min_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Filter by minimum detection confidence threshold.",
    )
    start_time: datetime | None = Field(
        default=None, description="Inclusive starting UTC timestamp."
    )
    end_time: datetime | None = Field(
        default=None, description="Inclusive ending UTC timestamp."
    )
    limit: int = Field(default=50, ge=1, le=500, description="Maximum items to return.")
    offset: int = Field(default=0, ge=0, description="Offset index for pagination.")
