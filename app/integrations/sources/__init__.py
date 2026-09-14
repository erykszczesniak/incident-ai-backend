"""Alert adapters. Source identifiers include occurrence time where available."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ai.redaction import redact, redact_value

Severity = Literal["critical", "high", "medium", "low"]


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    external_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=240)
    service: str = Field(min_length=1, max_length=120)
    severity: Severity = "medium"
    description: str = Field(default="", max_length=20_000)
    logs: list[dict[str, Any]] = Field(default_factory=list, max_length=1_000)

    @field_validator("title", "service", "description", mode="before")
    @classmethod
    def filter_text(cls, value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value

    @field_validator("logs")
    @classmethod
    def validate_logs(cls, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for entry in entries:
            if not isinstance(entry.get("message"), str):
                raise ValueError("Each log entry needs a string message")
            if len(entry["message"]) > 20_000:
                raise ValueError("Log message exceeds 20000 characters")
            if "level" in entry and not isinstance(entry["level"], str):
                raise ValueError("Log level must be a string")
        filtered: list[dict[str, Any]] = redact_value(entries)
        return filtered


class AlertSource(Protocol):
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]: ...


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _text(value: Any, default: str = "") -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValueError("Expected a text or numeric identifier")
    return str(value)


def _id(source: str, payload: dict[str, Any], *parts: Any) -> str:
    chosen = ":".join(str(part) for part in parts if part is not None and part != "")
    value = chosen or json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if chosen and len(chosen) <= 255:
        return chosen
    return f"{source}-{hashlib.sha256(value.encode()).hexdigest()}"


def _severity(value: Any, *, strict: bool = False) -> Severity:
    normalized = str(value).strip().lower()
    aliases: dict[str, Severity] = {
        "critical": "critical",
        "fatal": "critical",
        "disaster": "critical",
        "p1": "critical",
        "5": "critical",
        "high": "high",
        "error": "high",
        "p2": "high",
        "4": "high",
        "medium": "medium",
        "warning": "medium",
        "warn": "medium",
        "average": "medium",
        "p3": "medium",
        "3": "medium",
        "2": "medium",
        "low": "low",
        "info": "low",
        "information": "low",
        "debug": "low",
        "not classified": "low",
        "p4": "low",
        "p5": "low",
        "1": "low",
        "0": "low",
    }
    if strict and normalized not in aliases:
        raise ValueError("Unsupported severity")
    return aliases.get(normalized, "medium")


class GenericSource:
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]:
        payload = _mapping(payload, "Payload")
        title = payload.get("title")
        service = payload.get("service")
        if not isinstance(title, str) or not isinstance(service, str):
            raise ValueError("Generic alerts require string title and service")
        if "external_id" in payload and not isinstance(payload["external_id"], str):
            raise ValueError("Generic external_id must be a string")
        return [
            NormalizedAlert(
                external_id=_id("generic", payload, payload.get("external_id")),
                title=title,
                service=service,
                severity=_severity(payload.get("severity", "medium"), strict=True),
                description=payload.get("description", ""),
                logs=payload.get("logs", []),
            )
        ]


class GrafanaSource:
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]:
        payload = _mapping(payload, "Payload")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not alerts or len(alerts) > 100:
            raise ValueError("Grafana payload requires 1 to 100 alerts")
        output = []
        for item in alerts:
            alert = _mapping(item, "Grafana alert")
            if alert.get("status", payload.get("status", "firing")) == "resolved":
                continue
            labels = _mapping(alert.get("labels", {}), "labels")
            annotations = _mapping(alert.get("annotations", {}), "annotations")
            output.append(
                NormalizedAlert(
                    external_id=_id(
                        "grafana",
                        alert,
                        alert.get("fingerprint"),
                        alert.get("startsAt"),
                    ),
                    title=_text(
                        annotations.get("summary") or labels.get("alertname"),
                        "Grafana alert",
                    ),
                    service=_text(
                        labels.get("service") or labels.get("job"), "unknown"
                    ),
                    severity=_severity(labels.get("severity", "medium")),
                    description=_text(
                        annotations.get("description") or annotations.get("summary")
                    ),
                    logs=alert.get("logs", []),
                )
            )
        if not output:
            raise ValueError(
                "No firing alerts. Resolve incidents through the incident status API."
            )
        return output


class SentrySource:
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]:
        payload = _mapping(payload, "Payload")
        if payload.get("action") in ("resolved", "closed", "ignored"):
            raise ValueError(
                "Only active Sentry events are ingested; use the incident status API for resolution"
            )
        data = _mapping(payload.get("data", payload), "Sentry data")
        event = _mapping(data.get("event", data.get("issue", data)), "Sentry event")
        if not any(
            event.get(key) for key in ("event_id", "eventID", "id", "title", "message")
        ):
            raise ValueError("Sentry payload has no event or issue")
        project = event.get("project", payload.get("project", "unknown"))
        if isinstance(project, dict):
            project = project.get("slug") or project.get("name") or project.get("id")
        metadata = _mapping(event.get("metadata", {}), "Sentry metadata")
        message = (
            event.get("message") or metadata.get("value") or event.get("culprit", "")
        )
        if isinstance(message, dict):
            message = message.get("formatted") or message.get("message", "")
        return [
            NormalizedAlert(
                external_id=_id(
                    "sentry",
                    event,
                    event.get("event_id") or event.get("eventID") or event.get("id"),
                ),
                title=_text(event.get("title") or message, "Sentry exception"),
                service=_text(project, "unknown"),
                severity=_severity(event.get("level", "error")),
                description=_text(message),
                logs=event.get("logs", []),
            )
        ]


class CloudWatchSource:
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]:
        payload = _mapping(payload, "Payload")
        # SNS envelopes are accepted only as data. Never fetch SubscribeURL.
        if payload.get("Type") == "SubscriptionConfirmation":
            raise ValueError(
                "Confirm SNS subscriptions out of band before sending notifications"
            )
        if "Message" in payload:
            try:
                payload = _mapping(json.loads(payload["Message"]), "SNS Message")
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("SNS Message must contain a JSON object") from exc
        if "detail" in payload:
            detail = _mapping(payload["detail"], "CloudWatch detail")
            state = _mapping(detail.get("state", {}), "CloudWatch state")
            if state.get("value", "ALARM") != "ALARM":
                raise ValueError("Only CloudWatch ALARM transitions are ingested")
            name = detail.get("alarmName")
            if not name:
                raise ValueError("CloudWatch event requires alarmName")
            return [
                NormalizedAlert(
                    external_id=_id(
                        "cloudwatch",
                        payload,
                        payload.get("id") or name,
                        state.get("timestamp"),
                        state.get("value"),
                    ),
                    title=_text(name),
                    service=_text(
                        detail.get("service") or payload.get("source"), "cloudwatch"
                    ),
                    severity="high" if state.get("value") == "ALARM" else "low",
                    description=_text(state.get("reason")),
                )
            ]
        if not payload.get("AlarmName"):
            raise ValueError("CloudWatch notification requires AlarmName")
        if payload.get("NewStateValue", "ALARM") != "ALARM":
            raise ValueError("Only CloudWatch ALARM transitions are ingested")
        trigger = _mapping(payload.get("Trigger", {}), "CloudWatch Trigger")
        dimensions = trigger.get("Dimensions", [])
        if not isinstance(dimensions, list):
            raise ValueError("CloudWatch Dimensions must be an array")
        service = next(
            (
                item.get("value", item.get("Value"))
                for item in dimensions
                if isinstance(item, dict)
                and item.get("name", item.get("Name")) in ("ServiceName", "service")
            ),
            None,
        )
        return [
            NormalizedAlert(
                external_id=_id(
                    "cloudwatch",
                    payload,
                    payload.get("AlarmArn") or payload.get("AlarmName"),
                    payload.get("StateChangeTime"),
                    payload.get("NewStateValue"),
                ),
                title=_text(payload["AlarmName"]),
                service=_text(service or trigger.get("Namespace"), "cloudwatch"),
                severity=(
                    "high"
                    if payload.get("NewStateValue", "ALARM") == "ALARM"
                    else "low"
                ),
                description=_text(
                    payload.get("NewStateReason") or payload.get("AlarmDescription")
                ),
            )
        ]


class ZabbixSource:
    def normalize(self, payload: dict[str, Any]) -> list[NormalizedAlert]:
        payload = _mapping(payload, "Payload")
        if str(payload.get("event_value", "1")) == "0":
            raise ValueError(
                "Only Zabbix problem events are ingested; use the incident status API for recovery"
            )
        title = (
            payload.get("event_name") or payload.get("subject") or payload.get("name")
        )
        event_id = payload.get("event_id") or payload.get("eventid")
        if not title or not event_id:
            raise ValueError(
                "Zabbix payload requires event_id and event_name or subject"
            )
        return [
            NormalizedAlert(
                external_id=_id("zabbix", payload, event_id),
                title=_text(title),
                service=_text(
                    payload.get("service")
                    or payload.get("host")
                    or payload.get("host_name"),
                    "zabbix",
                ),
                severity=_severity(payload.get("severity", "medium")),
                description=_text(payload.get("message") or payload.get("description")),
                logs=payload.get("logs", []),
            )
        ]


_SOURCES: dict[str, AlertSource] = {
    "generic": GenericSource(),
    "grafana": GrafanaSource(),
    "sentry": SentrySource(),
    "cloudwatch": CloudWatchSource(),
    "zabbix": ZabbixSource(),
}


def get_source(name: str) -> AlertSource:
    try:
        return _SOURCES[name.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported alert source: {name}") from exc
