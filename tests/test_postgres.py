"""Exercise real PostgreSQL transactions and migration compatibility.

TEST_POSTGRES_URL must name a dedicated test server with CREATE DATABASE rights.
Alternatively RUN_POSTGRES_TESTS=1 starts an ephemeral pgvector testcontainer.
Every test run uses its own disposable database and never drops a supplied database.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import asyncpg
import httpx
import pytest
from sqlalchemy.engine import make_url

from app.ai.client import DemoLLMClient
from app.core.config import Settings
from app.repository.models import Incident


class FixtureVectorClient(DemoLLMClient):
    """Synthetic fixed vectors exercise SQL distance, never a product provider."""

    async def embed(self, text: str) -> list[float]:
        return [1.0, 0.0, 0.0]


@pytest.fixture
def postgres_server_url() -> Iterator[str]:
    supplied = os.environ.get("TEST_POSTGRES_URL")
    if supplied:
        yield supplied
        return
    if os.environ.get("RUN_POSTGRES_TESTS") != "1":
        pytest.skip(
            "Set TEST_POSTGRES_URL or RUN_POSTGRES_TESTS=1 for PostgreSQL tests"
        )
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("pgvector/pgvector:pg16") as postgres:
        yield postgres.get_connection_url().replace(
            "postgresql+psycopg2", "postgresql+asyncpg"
        )


@pytest.mark.postgres
async def test_postgres_migrations_and_concurrent_ingestion(
    postgres_server_url: str,
) -> None:
    from app.main import create_app

    server = make_url(postgres_server_url)
    control = await asyncpg.connect(
        host=server.host,
        port=server.port or 5432,
        user=server.username,
        password=server.password,
        database=server.database,
    )
    database = f"incident_test_{uuid.uuid4().hex}"
    await control.execute(f'CREATE DATABASE "{database}"')
    url = server.set(
        drivername="postgresql+asyncpg", database=database
    ).render_as_string(hide_password=False)
    root = Path(__file__).resolve().parents[1]
    environment = dict(
        os.environ, DATABASE_URL=url, DEMO_MODE="true", CELERY_ENABLED="false"
    )
    try:
        for arguments in (("upgrade", "head"), ("check",)):
            result = subprocess.run(
                [sys.executable, "-m", "alembic", *arguments],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert result.returncode == 0, result.stdout + result.stderr
        settings = Settings(
            _env_file=None,
            database_url=url,
            demo_mode=True,
            api_key="postgres-test-key",
            webhook_key="postgres-test-webhook",
            llm_provider="demo",
            redis_url="",
            celery_enabled=False,
            rate_limit_per_minute=1000,
        )
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
                headers={"X-API-Key": "postgres-test-key"},
            ) as client:
                payload = {
                    "external_id": "same-occurrence",
                    "title": "Concurrent pool exhaustion",
                    "service": "checkout",
                    "severity": "high",
                    "description": "Database connection pool exhausted",
                    "logs": [
                        {
                            "level": "ERROR",
                            "message": "password=topsecret pool exhausted",
                        }
                    ],
                }
                responses = await asyncio.gather(
                    *(
                        client.post("/api/v1/webhooks/generic", json=payload)
                        for _ in range(6)
                    )
                )
                assert all(response.is_success for response in responses), [
                    response.text for response in responses
                ]
                receipts = [response.json() for response in responses]
                ids = {receipt["incident"]["id"] for receipt in receipts}
                assert len(ids) == 1
                assert sum(not receipt["duplicate"] for receipt in receipts) == 1
                incident_id = ids.pop()
                path = f"/api/v1/incidents/{incident_id}"
                listing = (await client.get("/api/v1/incidents")).json()
                assert listing["total"] == 1
                assert len((await client.get(f"{path}/alerts")).json()) == 1
                assert "topsecret" not in (await client.get(f"{path}/logs")).text
                analysis = await client.post(f"{path}/analysis")
                assert analysis.is_success, analysis.text
                assert analysis.json()["remediation_steps"]
                postmortem = await client.post(f"{path}/postmortem")
                assert postmortem.is_success, postmortem.text
                export = await client.post(f"{path}/postmortem/export/jira")
                assert export.is_success, export.text
                repeated = await client.post(f"{path}/postmortem/export/jira")
                assert repeated.json() == export.json()
                assert export.json()["is_demo"]
                search = await client.get("/api/v1/search", params={"q": "pool"})
                assert search.is_success, search.text
                assert search.json()["items"]
                assert search.json()["mode"] == "lexical"
                app.state.llm = FixtureVectorClient()
                assert (await client.post(f"{path}/analysis")).is_success
                async with app.state.session_factory() as session:
                    session.add(
                        Incident(
                            title="An incompatible historical embedding",
                            service="old-model",
                            severity="low",
                            description="Dimension changes must never break search",
                            embedding=[1.0, 0.0],
                            embedding_model=settings.embedding_model,
                        )
                    )
                    await session.commit()
                semantic = await client.get("/api/v1/search", params={"q": "pool"})
                assert semantic.is_success, semantic.text
                assert semantic.json()["mode"] == "semantic", semantic.text
                assert semantic.json()["items"][0]["incident"]["id"] == incident_id
                assert semantic.json()["items"][0]["score"] == pytest.approx(1.0)
                registrations = await asyncio.gather(
                    *(
                        client.post(
                            "/api/v1/devices",
                            json={"token": "AB" * 32, "environment": "sandbox"},
                        )
                        for _ in range(6)
                    )
                )
                assert all(response.is_success for response in registrations)
                assert (
                    await client.delete(f"/api/v1/devices/{'ab' * 32}")
                ).status_code == 204
                assert (await client.get("/ready")).is_success
                deleted = await client.delete(path)
                assert deleted.status_code == 204
                assert (await client.get(path)).status_code == 404
    finally:
        await control.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
        await control.close()
