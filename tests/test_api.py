import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.ai.client import AnalysisResult
from app.core.config import Settings
from app.domain.jobs import execute_analysis_job
from app.integrations.errors import IntegrationError
from app.integrations.exporters import ExportResult
from app.main import create_app
from app.repository.models import (
    Alert,
    Analysis,
    Incident,
    Job,
    LogEntry,
    TimelineEvent,
)

HEADERS = {"X-API-Key": "incident-ai-demo-key"}
ALERT = {
    "external_id": "api-test-001",
    "title": "Checkout database connection pool exhausted",
    "service": "checkout",
    "severity": "critical",
    "description": "Requests fail with timeouts",
    "logs": [
        {
            "level": "ERROR",
            "message": "DB timeout password=supersecret user@example.com",
        }
    ],
}


@pytest.fixture
async def application(tmp_path: Path) -> AsyncIterator[FastAPI]:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db",
        rate_limit_per_minute=10000,
        s3_demo_directory=str(tmp_path / "archives"),
        jwt_secret="testing-jwt-secret-with-32-characters",
        demo_mode=True,
        redis_url="",
        celery_enabled=False,
        llm_provider="demo",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def client(application: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
        headers=HEADERS,
    ) as client:
        yield client


async def incident(
    client: httpx.AsyncClient,
    title: str = "Database timeout",
    service: str = "checkout",
) -> str:
    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": title,
            "service": service,
            "severity": "high",
            "description": "Investigate service health",
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def test_complete_incident_loop_and_idempotency(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    assert (await client.get("/health")).json()["status"] == "ok"
    assert (await client.get("/ready")).status_code == 200
    created = await client.post("/api/v1/webhooks/generic", json=ALERT)
    assert created.status_code == 200, created.text
    incident_id = created.json()["incident"]["id"]
    assert created.json()["duplicate"] is False
    repeated = await client.post("/api/v1/webhooks/Generic", json=ALERT)
    assert repeated.json()["duplicate"] is True
    assert repeated.json()["incident"]["id"] == incident_id
    logs = (await client.get(f"/api/v1/incidents/{incident_id}/logs")).json()
    assert len(logs) == 1
    assert "supersecret" not in str(logs) and "user@example.com" not in str(logs)
    assert (
        await client.get(f"/api/v1/incidents/{incident_id}/analysis")
    ).status_code == 404
    analysis = await client.post(f"/api/v1/incidents/{incident_id}/analysis")
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["is_fallback"] is True
    assert analysis.json()["remediation_steps"]
    assert any("engineer" in item.lower() for item in analysis.json()["caveats"])
    assert (await client.get(f"/api/v1/incidents/{incident_id}/analysis")).json()[
        "id"
    ] == analysis.json()["id"]
    await client.patch(
        f"/api/v1/incidents/{incident_id}", json={"status": "acknowledged"}
    )
    resolved = await client.patch(
        f"/api/v1/incidents/{incident_id}", json={"status": "resolved"}
    )
    assert resolved.json()["acknowledged_at"] and resolved.json()["resolved_at"]
    manual = await client.post(
        f"/api/v1/incidents/{incident_id}/timeline",
        json={"message": "Rolled back connection-pool change"},
    )
    assert manual.status_code == 201
    timeline = (await client.get(f"/api/v1/incidents/{incident_id}/timeline")).json()
    assert {event["kind"] for event in timeline} >= {
        "created",
        "logs_added",
        "analysis_completed",
        "status_changed",
        "manual",
    }
    postmortem = await client.post(f"/api/v1/incidents/{incident_id}/postmortem")
    assert postmortem.status_code == 200, postmortem.text
    assert postmortem.json()["version"] == 1
    assert "DRAFT" in postmortem.json()["markdown"]
    edited = await client.patch(
        f"/api/v1/incidents/{incident_id}/postmortem",
        json={"markdown": "# Reviewed\nEngineer approved. password=redactme"},
    )
    assert edited.json()["version"] == 2
    assert "redactme" not in edited.text
    downloaded = await client.get(
        f"/api/v1/incidents/{incident_id}/postmortem/markdown"
    )
    assert downloaded.headers["content-type"].startswith("text/markdown")
    assert downloaded.text.startswith("# Reviewed")
    exported = await client.post(
        f"/api/v1/incidents/{incident_id}/postmortem/export/jira"
    )
    assert exported.status_code == 200 and exported.json()["is_demo"]
    assert (
        await client.post(f"/api/v1/incidents/{incident_id}/postmortem/export/jira")
    ).json() == exported.json()
    assert (
        await client.post(
            f"/api/v1/incidents/{incident_id}/postmortem/export/confluence"
        )
    ).json()["is_demo"]
    dashboard = (await client.get("/api/v1/dashboard?days=7")).json()
    assert dashboard["resolved_incidents"] == 1 and dashboard["active_incidents"] == 0
    assert (
        dashboard["mttr_minutes"] is not None
        and dashboard["sla_compliance_percent"] == 100
    )
    assert len(dashboard["daily_counts"]) == 7
    archived = await client.post(f"/api/v1/incidents/{incident_id}/archive")
    assert archived.status_code == 200 and archived.json()["is_demo"]
    files = list(Path(application.state.settings.s3_demo_directory).rglob("*.gz"))
    assert files
    assert "supersecret" not in str(
        (await client.get("/api/v1/search?q=database")).json()
    )


async def test_auth_validation_redacted_errors_and_correlation(
    client: httpx.AsyncClient,
) -> None:
    unauthorized = await client.get("/api/v1/incidents", headers={"X-API-Key": "wrong"})
    assert (
        unauthorized.status_code == 401
        and unauthorized.json()["error"]["code"] == "unauthorized"
    )
    assert (
        unauthorized.headers["x-correlation-id"]
        == unauthorized.json()["correlation_id"]
    )
    response = await client.post(
        "/api/v1/incidents",
        json={"title": "", "password": "do-not-echo"},
        headers={"X-Correlation-ID": "test-request-abc"},
    )
    assert response.status_code == 422
    assert response.json()["correlation_id"] == "test-request-abc"
    assert "do-not-echo" not in response.text
    assert (await client.get("/api/v1/incidents?limit=0")).status_code == 422
    assert (await client.get("/api/v1/incidents?status=broken")).status_code == 422
    assert (await client.get("/api/v1/incidents/not-a-uuid")).status_code == 422
    assert (
        await client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000")
    ).status_code == 404
    assert (
        await client.post("/api/v1/webhooks/missing", json=ALERT)
    ).status_code == 422
    missing = await client.get("/nonexistent")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"
    schema = (await client.get("/openapi.json")).json()
    assert schema["components"]["securitySchemes"]["APIKey"]["name"] == "X-API-Key"
    assert (
        schema["components"]["securitySchemes"]["WebhookKey"]["name"] == "X-Webhook-Key"
    )


async def test_jwt_auth_requires_claims_and_valid_signature(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    now = datetime.now(UTC)
    claims = {
        "sub": "on-call",
        "iss": "incident-ai",
        "aud": "incident-ai-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, application.state.settings.jwt_secret, algorithm="HS256")
    assert (
        await client.get(
            "/api/v1/incidents",
            headers={"X-API-Key": "", "Authorization": f"Bearer {token}"},
        )
    ).status_code == 200
    claims["aud"] = "other-api"
    wrong = jwt.encode(claims, application.state.settings.jwt_secret, algorithm="HS256")
    assert (
        await client.get(
            "/api/v1/incidents",
            headers={"X-API-Key": "", "Authorization": f"Bearer {wrong}"},
        )
    ).status_code == 401


async def test_incident_filters_pagination_reopen_and_cascade(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    first = await incident(client, "Database connection issue")
    await incident(client, "Cache memory pressure", "redis")
    page = (await client.get("/api/v1/incidents?limit=1&offset=1")).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert (await client.get("/api/v1/incidents?search=Database")).json()["total"] == 1
    assert (await client.get("/api/v1/incidents?search=%25")).json()["total"] == 0
    assert (await client.get("/api/v1/incidents?severity=critical")).json()[
        "total"
    ] == 0
    await client.patch(f"/api/v1/incidents/{first}", json={"status": "investigating"})
    await client.patch(f"/api/v1/incidents/{first}", json={"status": "resolved"})
    assert (await client.get("/api/v1/incidents?status=active")).json()["total"] == 1
    reopened = (
        await client.patch(f"/api/v1/incidents/{first}", json={"status": "open"})
    ).json()
    assert reopened["resolved_at"] is None and reopened["acknowledged_at"] is not None
    assert (
        await client.patch(f"/api/v1/incidents/{first}", json={"title": None})
    ).status_code == 422
    await client.post(
        f"/api/v1/incidents/{first}/logs",
        json={"entries": [{"level": "warn", "message": "Investigating"}]},
    )
    assert (await client.delete(f"/api/v1/incidents/{first}")).status_code == 204
    async with application.state.session_factory() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(LogEntry)
                .where(LogEntry.incident_id == first)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(TimelineEvent)
                .where(TimelineEvent.incident_id == first)
            )
            == 0
        )


async def test_parallel_duplicate_alert_delivery_is_atomic(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    responses = await asyncio.gather(
        *(client.post("/api/v1/webhooks/generic", json=ALERT) for _ in range(6))
    )
    assert all(response.status_code == 200 for response in responses), [
        response.text for response in responses
    ]
    assert sum(not response.json()["duplicate"] for response in responses) == 1
    assert len({response.json()["incident"]["id"] for response in responses}) == 1
    async with application.state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Incident)) == 1
        assert await session.scalar(select(func.count()).select_from(Alert)) == 1
        assert await session.scalar(select(func.count()).select_from(LogEntry)) == 1


async def test_bad_batch_rolls_back_all_incidents(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    payload = {
        "alerts": [
            {
                "fingerprint": "valid",
                "labels": {
                    "alertname": "Database",
                    "service": "db",
                    "severity": "critical",
                },
                "annotations": {},
            },
            {
                "fingerprint": "invalid",
                "labels": {"alertname": "a@b.co " * 30},
                "annotations": {},
            },
        ]
    }
    response = await client.post("/api/v1/webhooks/grafana", json=payload)
    # Redaction expands the second title beyond its limit after the first row
    # has been flushed. The enclosing transaction must roll back both records.
    assert response.status_code == 422, response.text
    assert (await client.get("/api/v1/incidents")).json()["total"] == 0


async def test_dashboard_exact_durations_and_overdue_sla(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    now = datetime.now(UTC)
    async with application.state.session_factory() as session:
        session.add_all(
            [
                Incident(
                    title="Fast",
                    service="db",
                    severity="high",
                    status="resolved",
                    created_at=now - timedelta(hours=4),
                    updated_at=now,
                    acknowledged_at=now - timedelta(hours=4) + timedelta(minutes=10),
                    resolved_at=now - timedelta(hours=4) + timedelta(minutes=30),
                ),
                Incident(
                    title="Slow",
                    service="db",
                    severity="critical",
                    status="resolved",
                    created_at=now - timedelta(hours=3),
                    updated_at=now,
                    acknowledged_at=now - timedelta(hours=3) + timedelta(minutes=20),
                    resolved_at=now - timedelta(hours=3) + timedelta(minutes=90),
                ),
                Incident(
                    title="Overdue",
                    service="api",
                    severity="medium",
                    status="open",
                    created_at=now - timedelta(hours=2),
                    updated_at=now,
                ),
                Incident(
                    title="Pending",
                    service="api",
                    severity="low",
                    status="open",
                    created_at=now - timedelta(minutes=5),
                    updated_at=now,
                ),
                Incident(
                    title="Old",
                    service="archive",
                    severity="low",
                    status="resolved",
                    created_at=now - timedelta(days=40),
                    updated_at=now,
                    resolved_at=now - timedelta(days=39),
                ),
            ]
        )
        await session.commit()
    data = (await client.get("/api/v1/dashboard?days=7")).json()
    assert data["total_incidents"] == 4 and data["active_incidents"] == 2
    assert data["mttr_minutes"] == 60.0
    assert data["acknowledgement_minutes"] == 15.0
    assert data["sla_compliance_percent"] == 33.33
    assert sum(row["count"] for row in data["daily_counts"]) == 4
    assert len(data["by_severity"]) == 4


async def test_empty_dashboard_uses_null_for_unknown_metrics(
    client: httpx.AsyncClient,
) -> None:
    data = (await client.get("/api/v1/dashboard")).json()
    assert data["total_incidents"] == 0
    assert data["mttr_minutes"] is None and data["sla_compliance_percent"] is None


async def test_lexical_search_is_honest_and_finds_history(
    client: httpx.AsyncClient,
) -> None:
    first = await incident(client, "Database connection timeout")
    second = await incident(client, "Database connection exhausted")
    await incident(client, "CPU pressure", "worker")
    result = (await client.get("/api/v1/search?q=database+connection")).json()
    assert result["mode"] == "lexical"
    assert {item["incident"]["id"] for item in result["items"]} == {first, second}
    similar = (await client.get(f"/api/v1/incidents/{first}/similar")).json()
    assert first not in [item["incident"]["id"] for item in similar["items"]]
    assert (await client.get("/api/v1/search?q=zzzznevermatches")).json()["items"] == []


async def test_jobs_persist_and_fail_safely(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    incident_id = await incident(client)
    response = await client.post(f"/api/v1/incidents/{incident_id}/analysis/jobs")
    assert response.status_code == 202 and response.json()["status"] == "queued"
    job_id = response.json()["id"]
    completed = (await client.get(f"/api/v1/jobs/{job_id}")).json()
    assert (
        completed["status"] == "succeeded"
        and completed["result"]["incident_id"] == incident_id
    )
    await execute_analysis_job(
        job_id,
        application.state.session_factory,
        application.state.llm,
        application.state.settings,
    )
    async with application.state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Analysis)) == 1
    application.state.llm = AsyncMock()
    application.state.llm.analyze.side_effect = RuntimeError("secret-provider-token")
    response = await client.post(f"/api/v1/incidents/{incident_id}/analysis/jobs")
    failed = await client.get(f"/api/v1/jobs/{response.json()['id']}")
    assert (
        failed.json()["status"] == "failed"
        and "secret-provider-token" not in failed.text
    )


async def test_cancelled_job_rolls_back_and_can_be_retried(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    incident_id = await incident(client)
    async with application.state.session_factory() as session:
        job = Job(incident_id=incident_id)
        session.add(job)
        await session.commit()
        job_id = job.id
    started = asyncio.Event()

    async def slow_analyze(context: dict[str, Any]) -> AnalysisResult:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    llm = AsyncMock()
    llm.analyze.side_effect = slow_analyze
    task = asyncio.create_task(
        execute_analysis_job(
            job_id, application.state.session_factory, llm, application.state.settings
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with application.state.session_factory() as session:
        persisted = await session.get(Job, job_id)
        assert persisted is not None and persisted.status == "queued"
    await execute_analysis_job(
        job_id,
        application.state.session_factory,
        application.state.llm,
        application.state.settings,
    )
    assert (await client.get(f"/api/v1/jobs/{job_id}")).json()["status"] == "succeeded"


async def test_devices_and_payload_limits(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    token = "a" * 64
    for _ in range(2):
        assert (await client.post("/api/v1/devices", json={"token": token})).json() == {
            "registered": True
        }
    assert (
        await client.post("/api/v1/devices", json={"token": "invalid"})
    ).status_code == 422
    assert (await client.delete(f"/api/v1/devices/{token}")).status_code == 204
    application.state.settings.max_request_bytes = 1024
    response = await client.post("/api/v1/incidents", json={"title": "X" * 2000})
    assert (
        response.status_code == 413
        and response.json()["error"]["code"] == "payload_too_large"
    )

    async def chunks() -> AsyncIterator[bytes]:
        yield b"{" + b"x" * 600
        yield b"x" * 600 + b"}"

    chunked = await client.post("/api/v1/incidents", content=chunks())
    assert chunked.status_code == 413


async def test_parallel_device_registration_is_idempotent(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    from app.repository.models import Device

    token = "abcd" * 16
    responses = await asyncio.gather(
        *(client.post("/api/v1/devices", json={"token": token}) for _ in range(6))
    )
    assert all(response.status_code == 200 for response in responses), [
        response.text for response in responses
    ]
    assert (
        await client.post(
            "/api/v1/devices",
            json={"token": token.upper(), "environment": "production"},
        )
    ).status_code == 200
    async with application.state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Device)) == 1
        device = await session.get(Device, token)
        assert device is not None and device.environment == "production"
    assert (await client.delete(f"/api/v1/devices/{token.upper()}")).status_code == 204
    async with application.state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Device)) == 0


async def test_rate_limit_and_metrics_keep_identifiers_private(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    application.state.settings.rate_limit_per_minute = 2
    assert (await client.get("/api/v1/incidents")).status_code == 200
    assert (await client.get("/api/v1/incidents")).status_code == 200
    limited = await client.get("/api/v1/incidents")
    assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
    metrics = await client.get("/metrics")
    assert "incident_ai_http_requests_total" in metrics.text
    assert 'path="/api/v1/incidents"' in metrics.text


async def test_exports_serialize_and_demo_promotes_to_real(
    client: httpx.AsyncClient, application: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = await incident(client)
    await client.post(f"/api/v1/incidents/{incident_id}/postmortem")
    url = f"/api/v1/incidents/{incident_id}/postmortem/export/jira"
    assert (await client.post(url)).json()["is_demo"]
    exporter = AsyncMock()
    exporter.export.return_value = ExportResult(
        destination="jira",
        external_id="OPS-123",
        url="https://jira.example.com/browse/OPS-123",
        is_demo=False,
    )
    monkeypatch.setattr("app.api.routes.get_exporter", lambda *_: exporter)
    responses = await asyncio.gather(*(client.post(url) for _ in range(3)))
    assert all(
        response.status_code == 200 and response.json()["is_demo"] is False
        for response in responses
    )
    assert exporter.export.await_count == 1
    postmortem = (
        await client.get(f"/api/v1/incidents/{incident_id}/postmortem")
    ).json()
    assert postmortem["jira_issue_key"] == "OPS-123"


async def test_export_failure_preserves_postmortem(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = await incident(client)
    await client.post(f"/api/v1/incidents/{incident_id}/postmortem")
    exporter = AsyncMock()
    exporter.export.side_effect = IntegrationError(
        "Jira is unavailable", code="integration_unavailable"
    )
    monkeypatch.setattr("app.api.routes.get_exporter", lambda *_: exporter)
    response = await client.post(
        f"/api/v1/incidents/{incident_id}/postmortem/export/jira"
    )
    assert (
        response.status_code == 503
        and response.json()["error"]["code"] == "integration_unavailable"
    )
    assert (
        await client.get(f"/api/v1/incidents/{incident_id}/postmortem")
    ).status_code == 200


def test_production_configuration_rejects_insecure_defaults() -> None:
    with pytest.raises(ValueError, match="API_KEY"):
        Settings(_env_file=None, demo_mode=False)
    with pytest.raises(ValueError, match="WEBHOOK_KEY"):
        Settings(_env_file=None, demo_mode=False, api_key="a" * 32)


async def test_otel_removes_device_tokens_and_search_queries(tmp_path: Path) -> None:
    from functools import partial

    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from app.core.telemetry import scrub_trace_request

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    app = create_app(
        Settings(
            _env_file=None,
            database_url=f"sqlite+aiosqlite:///{tmp_path}/traces.db",
            otel_enabled=False,
        )
    )
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        server_request_hook=partial(scrub_trace_request, routes=app.routes),
        http_capture_headers_sanitize_fields=[".*"],
    )
    token = "abcdef" * 12
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers=HEADERS,
        ) as client:
            assert (await client.delete(f"/api/v1/devices/{token}")).status_code == 204
            assert (
                await client.get("/api/v1/search?q=private-customer-identifier")
            ).status_code == 200
    spans = exporter.get_finished_spans()
    assert spans
    for span in spans:
        attributes = str(dict(span.attributes or {}))
        assert (
            token not in attributes and "private-customer-identifier" not in attributes
        )
    provider.shutdown()


async def test_large_timeline_postmortem_stays_readable(
    client: httpx.AsyncClient, application: FastAPI
) -> None:
    incident_id = await incident(client)
    async with application.state.session_factory() as session:
        session.add_all(
            [
                TimelineEvent(
                    incident_id=incident_id,
                    kind="manual",
                    message="Investigation detail " * 475,
                )
                for _ in range(30)
            ]
        )
        await session.commit()
    generated = await client.post(f"/api/v1/incidents/{incident_id}/postmortem")
    assert generated.status_code == 200, generated.text
    assert len(generated.json()["markdown"]) < 250000
    assert "Additional timeline content omitted" in generated.json()["markdown"]
    assert (
        await client.get(f"/api/v1/incidents/{incident_id}/postmortem")
    ).status_code == 200
