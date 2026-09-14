import asyncio
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import ValidationError
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.redaction import redact
from app.core.errors import AppError
from app.core.security import require_auth, require_webhook_auth
from app.domain import incidents
from app.domain.analysis import analyze_incident, latest_analysis
from app.domain.jobs import execute_analysis_job, notify_created
from app.domain.postmortems import generate_postmortem, get_postmortem
from app.domain.search import search_incidents
from app.integrations.archival import archive_logs
from app.integrations.exporters import DemoExporter, get_exporter
from app.integrations.sources import get_source
from app.repository.database import get_session
from app.repository.models import (
    Alert,
    Device,
    ExportRecord,
    Incident,
    Job,
    LogEntry,
    TimelineEvent,
    utcnow,
)
from app.schemas.api import (
    AlertRead,
    AnalysisRead,
    Dashboard,
    DeviceCreate,
    ExportRead,
    IncidentCreate,
    IncidentPage,
    IncidentRead,
    IncidentUpdate,
    IngestionItem,
    IngestionResponse,
    JobRead,
    LogRead,
    LogsCreate,
    PostmortemRead,
    PostmortemUpdate,
    SearchResults,
    Severity,
    Status,
    TimelineCreate,
    TimelineRead,
)

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_auth)])
webhooks = APIRouter(prefix="/api/v1", dependencies=[Depends(require_webhook_auth)])
Session = Annotated[AsyncSession, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def schedule_created(
    request: Request, tasks: BackgroundTasks, incident: Incident
) -> None:
    tasks.add_task(
        notify_created,
        incidents.incident_dict(incident),
        request.app.state.session_factory,
        request.app.state.settings,
    )


@webhooks.post("/webhooks/{source}", response_model=IngestionResponse, tags=["Alerts"])
async def ingest(
    source: str,
    payload: dict[str, Any],
    session: Session,
    request: Request,
    tasks: BackgroundTasks,
) -> IngestionResponse:
    source = source.lower()
    try:
        normalized = get_source(source).normalize(payload)
        if not normalized or len(normalized) > 100:
            raise ValueError("An alert batch must contain between 1 and 100 alerts")
        if session.get_bind().dialect.name == "sqlite":
            # SQLite legacy mode does not BEGIN on SELECT or SAVEPOINT. Start a
            # real write transaction so a failed batch cannot commit a released
            # savepoint, and concurrent webhook deliveries serialize safely.
            await session.execute(text("BEGIN IMMEDIATE"))
        results = []
        created = []
        for alert in normalized:
            incident, duplicate = await incidents.ingest_alert(session, source, alert)
            results.append(
                IngestionItem(
                    incident=IncidentRead.model_validate(incident), duplicate=duplicate
                )
            )
            if not duplicate:
                created.append(incident)
        await session.commit()
    except (ValueError, ValidationError) as exc:
        raise AppError(
            "invalid_alert", "The source or alert payload is invalid", 422
        ) from exc
    for incident in created:
        schedule_created(request, tasks, incident)
        if request.app.state.settings.auto_analyze:
            job = await queue_analysis(str(incident.id), session, request, tasks)
            del job
    return IngestionResponse(
        incident=results[0].incident,
        duplicate=all(item.duplicate for item in results),
        results=results,
    )


@router.get("/incidents", response_model=IncidentPage, tags=["Incidents"])
async def list_incidents(
    session: Session,
    status: (
        Literal["active", "open", "acknowledged", "investigating", "resolved"] | None
    ) = None,
    severity: Severity | None = None,
    search: str | None = Query(default=None, max_length=200),
    limit: Limit = 50,
    offset: Offset = 0,
) -> IncidentPage:
    query = select(Incident)
    if status == "active":
        query = query.where(Incident.status != "resolved")
    elif status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity.value)
    if search:
        query = query.where(
            or_(
                Incident.title.icontains(search, autoescape=True),
                Incident.service.icontains(search, autoescape=True),
                Incident.description.icontains(search, autoescape=True),
            )
        )
    total = (
        await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    )
    rows = (
        await session.scalars(
            query.order_by(Incident.created_at.desc(), Incident.id.desc())
            .offset(offset)
            .limit(limit)
        )
    ).all()
    return IncidentPage(
        items=[IncidentRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/incidents", response_model=IncidentRead, status_code=201, tags=["Incidents"]
)
async def create_incident(
    payload: IncidentCreate, session: Session, request: Request, tasks: BackgroundTasks
) -> IncidentRead:
    incident = await incidents.create_incident(session, payload)
    await session.commit()
    schedule_created(request, tasks, incident)
    return IncidentRead.model_validate(incident)


@router.get("/incidents/{incident_id}", response_model=IncidentRead, tags=["Incidents"])
async def read_incident(incident_id: UUID, session: Session) -> IncidentRead:
    return IncidentRead.model_validate(
        await incidents.require_incident(session, str(incident_id))
    )


@router.patch(
    "/incidents/{incident_id}", response_model=IncidentRead, tags=["Incidents"]
)
async def update_incident(
    incident_id: UUID, payload: IncidentUpdate, session: Session
) -> IncidentRead:
    incident = await incidents.require_incident(session, str(incident_id), lock=True)
    old_status = incident.status
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, key, redact(value) if isinstance(value, str) else value)
    now = utcnow()
    incident.updated_at = now
    if payload.status and old_status != payload.status:
        if (
            payload.status in {Status.acknowledged, Status.investigating}
            and not incident.acknowledged_at
        ):
            incident.acknowledged_at = now
        incident.resolved_at = now if payload.status == Status.resolved else None
        incidents.add_event(
            session,
            incident.id,
            "status_changed",
            f"Status changed from {old_status} to {payload.status.value}.",
        )
    else:
        incidents.add_event(
            session, incident.id, "updated", "Incident details updated."
        )
    if payload.title or payload.description is not None:
        incident.embedding = None
        incident.embedding_model = None
    await session.commit()
    return IncidentRead.model_validate(incident)


@router.delete("/incidents/{incident_id}", status_code=204, tags=["Incidents"])
async def delete_incident(incident_id: UUID, session: Session) -> Response:
    incident = await incidents.require_incident(session, str(incident_id))
    await session.delete(incident)
    await session.commit()
    return Response(status_code=204)


@router.get(
    "/incidents/{incident_id}/alerts", response_model=list[AlertRead], tags=["Alerts"]
)
async def list_alerts(incident_id: UUID, session: Session) -> list[AlertRead]:
    await incidents.require_incident(session, str(incident_id))
    rows = (
        await session.scalars(
            select(Alert)
            .where(Alert.incident_id == str(incident_id))
            .order_by(Alert.received_at)
        )
    ).all()
    return [AlertRead.model_validate(row) for row in rows]


@router.get(
    "/incidents/{incident_id}/logs", response_model=list[LogRead], tags=["Logs"]
)
async def list_logs(
    incident_id: UUID, session: Session, limit: Limit = 100, offset: Offset = 0
) -> list[LogRead]:
    await incidents.require_incident(session, str(incident_id))
    rows = (
        await session.scalars(
            select(LogEntry)
            .where(LogEntry.incident_id == str(incident_id))
            .order_by(LogEntry.timestamp, LogEntry.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return [LogRead.model_validate(row) for row in rows]


@router.post(
    "/incidents/{incident_id}/logs",
    response_model=list[LogRead],
    status_code=201,
    tags=["Logs"],
)
async def attach_logs(
    incident_id: UUID, payload: LogsCreate, session: Session
) -> list[LogRead]:
    await incidents.require_incident(session, str(incident_id))
    rows = await incidents.add_logs(session, str(incident_id), payload.entries)
    await session.commit()
    return [LogRead.model_validate(row) for row in rows]


@router.get(
    "/incidents/{incident_id}/timeline",
    response_model=list[TimelineRead],
    tags=["Timeline"],
)
async def timeline(incident_id: UUID, session: Session) -> list[TimelineRead]:
    await incidents.require_incident(session, str(incident_id))
    rows = (
        await session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.incident_id == str(incident_id))
            .order_by(TimelineEvent.created_at, TimelineEvent.id)
        )
    ).all()
    return [TimelineRead.model_validate(row) for row in rows]


@router.post(
    "/incidents/{incident_id}/timeline",
    response_model=TimelineRead,
    status_code=201,
    tags=["Timeline"],
)
async def add_timeline_event(
    incident_id: UUID, payload: TimelineCreate, session: Session
) -> TimelineRead:
    await incidents.require_incident(session, str(incident_id))
    event = incidents.add_event(session, str(incident_id), "manual", payload.message)
    await session.commit()
    return TimelineRead.model_validate(event)


@router.get(
    "/incidents/{incident_id}/analysis", response_model=AnalysisRead, tags=["Analysis"]
)
async def get_analysis(incident_id: UUID, session: Session) -> AnalysisRead:
    await incidents.require_incident(session, str(incident_id))
    return AnalysisRead.model_validate(await latest_analysis(session, str(incident_id)))


@router.post(
    "/incidents/{incident_id}/analysis", response_model=AnalysisRead, tags=["Analysis"]
)
async def run_analysis(
    incident_id: UUID, session: Session, request: Request
) -> AnalysisRead:
    analysis = await analyze_incident(
        session, str(incident_id), request.app.state.llm, request.app.state.settings
    )
    await session.commit()
    return AnalysisRead.model_validate(analysis)


@router.get(
    "/incidents/{incident_id}/postmortem",
    response_model=PostmortemRead,
    tags=["Postmortems"],
)
async def read_postmortem(incident_id: UUID, session: Session) -> PostmortemRead:
    await incidents.require_incident(session, str(incident_id))
    return PostmortemRead.model_validate(
        await get_postmortem(session, str(incident_id))
    )


@router.post(
    "/incidents/{incident_id}/postmortem",
    response_model=PostmortemRead,
    tags=["Postmortems"],
)
async def create_postmortem(incident_id: UUID, session: Session) -> PostmortemRead:
    result = await generate_postmortem(session, str(incident_id))
    await session.commit()
    return PostmortemRead.model_validate(result)


@router.patch(
    "/incidents/{incident_id}/postmortem",
    response_model=PostmortemRead,
    tags=["Postmortems"],
)
async def edit_postmortem(
    incident_id: UUID, payload: PostmortemUpdate, session: Session
) -> PostmortemRead:
    await incidents.require_incident(session, str(incident_id), lock=True)
    postmortem = await get_postmortem(session, str(incident_id), lock=True)
    postmortem.markdown = redact(payload.markdown)
    postmortem.version += 1
    postmortem.updated_at = utcnow()
    incidents.add_event(
        session,
        str(incident_id),
        "postmortem_edited",
        f"Postmortem edited to version {postmortem.version}.",
    )
    await session.commit()
    return PostmortemRead.model_validate(postmortem)


@router.get(
    "/incidents/{incident_id}/postmortem/markdown",
    response_class=PlainTextResponse,
    tags=["Postmortems"],
)
async def download_markdown(incident_id: UUID, session: Session) -> PlainTextResponse:
    postmortem = await get_postmortem(session, str(incident_id))
    return PlainTextResponse(
        postmortem.markdown,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="postmortem-{incident_id}.md"'
        },
    )


@router.post(
    "/incidents/{incident_id}/postmortem/export/{destination}",
    response_model=ExportRead,
    tags=["Exports"],
)
async def export_postmortem(
    incident_id: UUID,
    destination: Literal["jira", "confluence"],
    session: Session,
    request: Request,
) -> ExportRead:
    # PostgreSQL row locking serializes replicas; the per-process lock also
    # provides duplicate protection for local SQLite demonstration requests.
    async with request.app.state.export_locks[str(incident_id)]:
        incident = await incidents.require_incident(
            session, str(incident_id), lock=True
        )
        previous = await session.scalar(
            select(ExportRecord).where(
                ExportRecord.incident_id == str(incident_id),
                ExportRecord.destination == destination,
            )
        )
        if previous and not previous.is_demo:
            return ExportRead.model_validate(previous)
        exporter = get_exporter(destination, request.app.state.settings)
        if previous and isinstance(exporter, DemoExporter):
            return ExportRead.model_validate(previous)
        postmortem = await get_postmortem(session, str(incident_id), lock=True)
        result = await exporter.export(
            incidents.incident_dict(incident), postmortem.markdown
        )
        if previous:
            record = previous
            for key, value in result.model_dump().items():
                setattr(record, key, value)
        else:
            record = ExportRecord(incident_id=str(incident_id), **result.model_dump())
            session.add(record)
        if destination == "jira":
            postmortem.jira_issue_key = result.external_id
            postmortem.jira_issue_url = result.url
        else:
            postmortem.confluence_url = result.url
        incidents.add_event(
            session,
            str(incident_id),
            "exported",
            f"Postmortem exported to {destination}{' in demo mode' if result.is_demo else ''}.",
        )
        await session.commit()
        return ExportRead.model_validate(record)


@router.get("/dashboard", response_model=Dashboard, tags=["Dashboard"])
async def read_dashboard(
    session: Session, request: Request, days: Annotated[int, Query(ge=1, le=365)] = 30
) -> Dashboard:
    return await incidents.dashboard(
        session, days, request.app.state.settings.sla_target_minutes
    )


@router.post("/devices", tags=["Devices"])
async def register_device(payload: DeviceCreate, session: Session) -> dict[str, bool]:
    insert = (
        postgres_insert
        if session.get_bind().dialect.name == "postgresql"
        else sqlite_insert
    )
    statement = insert(Device).values(**payload.model_dump())
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=[Device.token],
            set_={"platform": payload.platform, "environment": payload.environment},
        )
    )
    await session.commit()
    return {"registered": True}


@router.delete("/devices/{token}", status_code=204, tags=["Devices"])
async def unregister_device(token: str, session: Session) -> Response:
    await session.execute(delete(Device).where(Device.token == token.lower()))
    await session.commit()
    return Response(status_code=204)


@router.get("/search", response_model=SearchResults, tags=["Extended: Search"])
async def search(
    session: Session,
    request: Request,
    q: Annotated[str, Query(min_length=1, max_length=500)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> SearchResults:
    return await search_incidents(
        session, q, limit, request.app.state.llm, request.app.state.settings
    )


@router.get(
    "/incidents/{incident_id}/similar",
    response_model=SearchResults,
    tags=["Extended: Search"],
)
async def similar(
    incident_id: UUID,
    session: Session,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=50)] = 5,
) -> SearchResults:
    incident = await incidents.require_incident(session, str(incident_id))
    return await search_incidents(
        session,
        f"{incident.title} {incident.service}",
        limit,
        request.app.state.llm,
        request.app.state.settings,
        str(incident_id),
    )


async def queue_analysis(
    incident_id: str, session: AsyncSession, request: Request, tasks: BackgroundTasks
) -> Job:
    await incidents.require_incident(session, incident_id)
    job = Job(incident_id=incident_id)
    session.add(job)
    await session.commit()
    if request.app.state.settings.celery_enabled:
        from app.worker import analyze_job

        try:
            await asyncio.to_thread(analyze_job.apply_async, args=[job.id], retry=False)
        except Exception as exc:
            job.status = "failed"
            job.error = (
                "The queue is unavailable. Retry when Redis and the worker are healthy."
            )
            await session.commit()
            raise AppError("queue_unavailable", job.error, 503) from exc
    else:
        tasks.add_task(
            execute_analysis_job,
            job.id,
            request.app.state.session_factory,
            request.app.state.llm,
            request.app.state.settings,
        )
    return job


@router.post(
    "/incidents/{incident_id}/analysis/jobs",
    response_model=JobRead,
    status_code=202,
    tags=["Extended: Jobs"],
)
async def create_analysis_job(
    incident_id: UUID, session: Session, request: Request, tasks: BackgroundTasks
) -> JobRead:
    return JobRead.model_validate(
        await queue_analysis(str(incident_id), session, request, tasks)
    )


@router.get("/jobs/{job_id}", response_model=JobRead, tags=["Extended: Jobs"])
async def read_job(job_id: UUID, session: Session) -> JobRead:
    job = await session.get(Job, str(job_id))
    if job is None:
        raise AppError("job_not_found", "Job not found", 404)
    return JobRead.model_validate(job)


@router.post("/incidents/{incident_id}/archive", tags=["Extended: Archival"])
async def archive(
    incident_id: UUID, session: Session, request: Request
) -> dict[str, Any]:
    await incidents.require_incident(session, str(incident_id))
    logs = (
        await session.scalars(
            select(LogEntry)
            .where(LogEntry.incident_id == str(incident_id))
            .order_by(LogEntry.timestamp)
        )
    ).all()
    result = await archive_logs(
        str(incident_id),
        [LogRead.model_validate(log).model_dump(mode="json") for log in logs],
        request.app.state.settings,
    )
    incidents.add_event(
        session, str(incident_id), "archived", "Redacted log archive created."
    )
    await session.commit()
    return result
