import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.client import LLMClient
from app.core.config import Settings
from app.domain.analysis import analyze_incident
from app.repository.models import Job, utcnow
from app.schemas.api import AnalysisRead

logger = logging.getLogger("incident_ai.jobs")


async def execute_analysis_job(
    job_id: str,
    factory: async_sessionmaker[AsyncSession],
    llm: LLMClient,
    settings: Settings,
) -> None:
    try:
        async with factory() as session:
            # Keep the row lock and status in one transaction until the result is
            # saved. A crashed worker rolls back to queued; late-acked Celery
            # redelivery can then retry safely without a stale running state.
            job = await session.scalar(
                select(Job).where(Job.id == job_id).with_for_update()
            )
            if job is None or job.status == "succeeded":
                return
            job.status = "running"
            job.updated_at = utcnow()
            incident_id = job.incident_id
            analysis = await analyze_incident(session, incident_id, llm, settings)
            result = AnalysisRead.model_validate(analysis).model_dump(mode="json")
            if job:
                job.status = "succeeded"
                job.result = result
                job.updated_at = utcnow()
            await session.commit()
    except Exception as exc:
        logger.warning("Analysis job failed: %s", type(exc).__name__)
        async with factory() as session:
            job = await session.get(Job, job_id)
            if job:
                job.status = "failed"
                job.error = "Analysis failed. Retry after checking provider configuration and availability."
                job.updated_at = utcnow()
                await session.commit()


async def notify_created(
    incident: dict[str, Any],
    factory: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    from app.integrations.notifiers import notify_incident
    from app.repository.models import Device

    try:
        async with factory() as session:
            devices = [
                {
                    "token": device.token,
                    "platform": device.platform,
                    "environment": device.environment,
                }
                for device in (await session.scalars(select(Device))).all()
            ]
        await notify_incident(incident, settings, devices)
    except Exception as exc:
        logger.warning("Incident notification unavailable: %s", type(exc).__name__)
