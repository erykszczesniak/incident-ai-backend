from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ai.redaction import redact


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Status(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    resolved = "resolved"


class DTO(BaseModel):
    model_config = ConfigDict(
        from_attributes=True, extra="forbid", str_strip_whitespace=True
    )


class IncidentCreate(DTO):
    title: str = Field(min_length=1, max_length=240)
    service: str = Field(min_length=1, max_length=120)
    severity: Severity = Severity.medium
    description: str = Field(default="", max_length=20000)

    @field_validator("title", "service", "description", mode="before")
    @classmethod
    def redact_strings(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value


class IncidentUpdate(DTO):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    severity: Severity | None = None
    status: Status | None = None
    description: str | None = Field(default=None, max_length=20000)

    @field_validator("title", "description", mode="before")
    @classmethod
    def redact_strings(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def prohibit_explicit_nulls(self) -> "IncidentUpdate":
        if not self.model_fields_set or any(
            getattr(self, key) is None for key in self.model_fields_set
        ):
            raise ValueError("Supply at least one non-null field")
        return self


class IncidentRead(IncidentCreate):
    id: str
    status: Status
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class IncidentPage(DTO):
    items: list[IncidentRead]
    total: int
    limit: int
    offset: int


class IngestionItem(DTO):
    incident: IncidentRead
    duplicate: bool


class IngestionResponse(IngestionItem):
    results: list[IngestionItem] = Field(default_factory=list)


class AlertRead(DTO):
    id: str
    incident_id: str
    source: str
    external_id: str
    title: str
    service: str
    severity: Severity
    description: str
    received_at: datetime


class LogInput(DTO):
    timestamp: datetime | None = None
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    message: str = Field(min_length=1, max_length=32768)

    @field_validator("message", mode="before")
    @classmethod
    def redact_message(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, value: Any) -> Any:
        if isinstance(value, str):
            return {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(
                value.upper(), value.upper()
            )
        return value

    @field_validator("timestamp")
    @classmethod
    def timestamp_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            return (
                value.replace(tzinfo=UTC)
                if value.tzinfo is None
                else value.astimezone(UTC)
            )
        return None


class LogsCreate(DTO):
    entries: Annotated[list[LogInput], Field(min_length=1, max_length=1000)]


class LogRead(DTO):
    id: str
    incident_id: str
    timestamp: datetime
    level: str
    message: str


class TimelineCreate(DTO):
    message: str = Field(min_length=1, max_length=10000)

    @field_validator("message", mode="before")
    @classmethod
    def redact_message(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value


class TimelineRead(TimelineCreate):
    id: str
    incident_id: str
    kind: str
    created_at: datetime


class AnalysisRead(DTO):
    id: str
    incident_id: str
    summary: str
    probable_cause: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]
    remediation_steps: list[str]
    caveats: list[str]
    provider: str
    is_fallback: bool
    created_at: datetime


class PostmortemUpdate(DTO):
    markdown: str = Field(min_length=1, max_length=250000)

    @field_validator("markdown", mode="before")
    @classmethod
    def redact_markdown(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value


class PostmortemRead(PostmortemUpdate):
    id: str
    incident_id: str
    version: int
    created_at: datetime
    updated_at: datetime
    jira_issue_key: str | None
    jira_issue_url: str | None
    confluence_url: str | None


class ExportRead(DTO):
    destination: str
    external_id: str
    url: str
    is_demo: bool


class DeviceCreate(DTO):
    token: str = Field(min_length=64, max_length=200, pattern=r"^[a-fA-F0-9]+$")
    platform: Literal["ios"] = "ios"
    environment: Literal["sandbox", "production"] = "sandbox"

    @field_validator("token")
    @classmethod
    def normalize_token(cls, value: str) -> str:
        return value.lower()


class SearchItem(DTO):
    incident: IncidentRead
    score: float


class SearchResults(DTO):
    items: list[SearchItem]
    mode: Literal["semantic", "lexical"]


class JobRead(DTO):
    id: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None


class SeverityCount(DTO):
    severity: Severity
    count: int


class DailyCount(DTO):
    date: str
    count: int


class ServiceCount(DTO):
    service: str
    count: int


class Dashboard(DTO):
    total_incidents: int
    active_incidents: int
    resolved_incidents: int
    mttr_minutes: float | None
    acknowledgement_minutes: float | None
    sla_compliance_percent: float | None
    sla_target_minutes: float
    by_severity: list[SeverityCount]
    daily_counts: list[DailyCount]
    services: list[ServiceCount]
