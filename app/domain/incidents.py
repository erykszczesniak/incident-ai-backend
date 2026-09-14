from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.redaction import redact
from app.core.errors import AppError
from app.integrations.sources import NormalizedAlert
from app.repository.models import Alert, Incident, LogEntry, TimelineEvent, utcnow
from app.schemas.api import Dashboard, IncidentCreate, IncidentRead, LogInput, Severity


async def require_incident(
    session: AsyncSession, incident_id: str, lock: bool = False
) -> Incident:
    query = select(Incident).where(Incident.id == incident_id)
    if lock:
        query = query.with_for_update()
    incident = await session.scalar(query)
    if incident is None:
        raise AppError("not_found", "Incident not found", 404)
    return incident


def add_event(
    session: AsyncSession, incident_id: str, kind: str, message: str
) -> TimelineEvent:
    event = TimelineEvent(incident_id=incident_id, kind=kind, message=redact(message))
    session.add(event)
    return event


async def create_incident(
    session: AsyncSession, data: IncidentCreate, source: str = "manual"
) -> Incident:
    incident = Incident(
        title=redact(data.title),
        service=redact(data.service),
        severity=data.severity.value,
        description=redact(data.description),
    )
    session.add(incident)
    await session.flush()
    add_event(session, incident.id, "created", f"Incident created from {source}.")
    return incident


async def add_logs(
    session: AsyncSession, incident_id: str, entries: list[LogInput]
) -> list[LogEntry]:
    logs = [
        LogEntry(
            incident_id=incident_id,
            timestamp=entry.timestamp or utcnow(),
            level=entry.level,
            message=redact(entry.message),
        )
        for entry in entries
    ]
    session.add_all(logs)
    if logs:
        add_event(
            session,
            incident_id,
            "logs_added",
            f"Attached {len(logs)} redacted log entries.",
        )
    await session.flush()
    return logs


async def ingest_alert(
    session: AsyncSession, source: str, alert: NormalizedAlert
) -> tuple[Incident, bool]:
    existing = await session.scalar(
        select(Alert).where(
            Alert.source == source, Alert.external_id == alert.external_id
        )
    )
    if existing:
        return await require_incident(session, existing.incident_id), True
    data = IncidentCreate(
        title=alert.title,
        service=alert.service,
        severity=alert.severity,
        description=alert.description,
    )
    logs = [LogInput.model_validate(entry) for entry in alert.logs]
    if len(logs) > 1000:
        raise AppError(
            "validation_error", "At most 1000 log entries are allowed per alert", 422
        )
    # The incident, unique alert key, logs and timeline are one atomic unit. A
    # concurrent duplicate rolls back its savepoint, including its new incident.
    try:
        async with session.begin_nested():
            incident = await create_incident(session, data, source)
            session.add(
                Alert(
                    incident_id=incident.id,
                    source=source,
                    external_id=alert.external_id,
                    title=incident.title,
                    service=incident.service,
                    severity=incident.severity,
                    description=incident.description,
                )
            )
            await session.flush()
            await add_logs(session, incident.id, logs)
        return incident, False
    except IntegrityError:
        existing = await session.scalar(
            select(Alert).where(
                Alert.source == source, Alert.external_id == alert.external_id
            )
        )
        if existing is None:
            raise
        return await require_incident(session, existing.incident_id), True


def incident_dict(incident: Incident) -> dict[str, Any]:
    return IncidentRead.model_validate(incident).model_dump(mode="json")


async def dashboard(session: AsyncSession, days: int, sla_target: float) -> Dashboard:
    now = utcnow()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=days - 1
    )
    incidents = list(
        (
            await session.scalars(
                select(Incident).where(
                    Incident.created_at >= start, Incident.created_at <= now
                )
            )
        ).all()
    )
    resolved = [
        incident
        for incident in incidents
        if incident.status == "resolved" and incident.resolved_at
    ]
    durations = [
        max(0.0, (incident.resolved_at - incident.created_at).total_seconds() / 60)
        for incident in resolved
        if incident.resolved_at
    ]
    acknowledged = [
        max(0.0, (incident.acknowledged_at - incident.created_at).total_seconds() / 60)
        for incident in incidents
        if incident.acknowledged_at
    ]
    overdue_active = sum(
        1
        for incident in incidents
        if incident.status != "resolved"
        and (now - incident.created_at).total_seconds() / 60 > sla_target
    )
    eligible = len(durations) + overdue_active
    daily = Counter(incident.created_at.date().isoformat() for incident in incidents)
    severities = Counter(incident.severity for incident in incidents)
    services = Counter(incident.service for incident in incidents)
    return Dashboard(
        total_incidents=len(incidents),
        active_incidents=len(incidents) - len(resolved),
        resolved_incidents=len(resolved),
        mttr_minutes=round(sum(durations) / len(durations), 2) if durations else None,
        acknowledgement_minutes=(
            round(sum(acknowledged) / len(acknowledged), 2) if acknowledged else None
        ),
        sla_compliance_percent=(
            round(
                100 * sum(duration <= sla_target for duration in durations) / eligible,
                2,
            )
            if eligible
            else None
        ),
        sla_target_minutes=sla_target,
        by_severity=[
            {"severity": severity, "count": severities[severity]}
            for severity in Severity
        ],
        daily_counts=[
            {
                "date": (start + timedelta(days=index)).date().isoformat(),
                "count": daily[(start + timedelta(days=index)).date().isoformat()],
            }
            for index in range(days)
        ],
        services=[
            {"service": service, "count": count}
            for service, count in services.most_common()
        ],
    )
