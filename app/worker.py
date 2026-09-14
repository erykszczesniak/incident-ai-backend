"""Extended Redis/Celery worker: celery -A app.worker.celery_app worker."""

import asyncio

from celery import Celery
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.ai.client import get_llm_client
from app.core.config import get_settings
from app.domain.jobs import execute_analysis_job
from app.repository.database import build_engine

settings = get_settings()
celery_app = Celery(
    "incident_ai", broker=settings.redis_url or "redis://localhost:6379/0"
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_soft_time_limit=300,
    task_time_limit=360,
)


@celery_app.task(name="incident_ai.analyze")
def analyze_job(job_id: str) -> None:
    async def run() -> None:
        engine = build_engine(settings)
        try:
            factory = async_sessionmaker(engine, expire_on_commit=False)
            await execute_analysis_job(
                job_id, factory, get_llm_client(settings), settings
            )
        finally:
            await engine.dispose()

    asyncio.run(run())
