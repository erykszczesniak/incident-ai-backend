"""Independent API boundary regressions, exercised against the actual adapters."""

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.ai.client import OpenAILLMClient, ResilientLLMClient
from app.core.config import Settings
from app.main import create_app


@pytest.fixture
async def boundary_api() -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient]]:
    app = create_app(
        Settings(
            database_url="sqlite+aiosqlite:///:memory:", rate_limit_per_minute=10_000
        )
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"X-API-Key": "incident-ai-demo-key"},
        ) as client:
            yield app, client


@pytest.mark.parametrize(
    ("source", "payload"),
    [
        (
            "generic",
            {
                "title": "Bad log",
                "service": "api",
                "logs": [{"message": {"token": "private"}}],
            },
        ),
        (
            "generic",
            {
                "title": "Bad timestamp",
                "service": "api",
                "logs": [{"message": "a", "timestamp": {"bad": "data"}}],
            },
        ),
        (
            "generic",
            {
                "title": "Bad level",
                "service": "api",
                "logs": [{"message": "a", "level": []}],
            },
        ),
        ("generic", {"title": "Bad shape", "service": "api", "logs": "private"}),
        ("grafana", {"alerts": [{"labels": None}]}),
        ("grafana", {"alerts": ["private"]}),
        ("sentry", {"data": {"event": {"event_id": "123", "metadata": []}}}),
        ("cloudwatch", {"Message": ["private"]}),
        ("cloudwatch", {"detail": {"state": [], "alarmName": "bad"}}),
        ("zabbix", {"event_id": "1", "event_name": ["private"]}),
    ],
)
async def test_malformed_nested_source_payloads_are_safe_422(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
    source: str,
    payload: dict[str, Any],
) -> None:
    _, client = boundary_api
    response = await client.post(f"/api/v1/webhooks/{source}", json=payload)
    assert response.status_code == 422, response.text
    assert "private" not in response.text
    assert response.json()["correlation_id"] == response.headers["x-correlation-id"]
    assert (await client.get("/api/v1/incidents")).json()["total"] == 0


async def test_cased_source_retry_cannot_duplicate_incident(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    _, client = boundary_api
    payload = {"external_id": "delivery-1", "title": "Timeout", "service": "api"}
    first = await client.post("/api/v1/webhooks/Generic", json=payload)
    second = await client.post("/api/v1/webhooks/generic", json=payload)
    assert first.status_code == second.status_code == 200
    assert second.json()["duplicate"] is True
    assert first.json()["incident"]["id"] == second.json()["incident"]["id"]


@pytest.mark.parametrize(
    ("field", "value", "limit"),
    [
        ("title", "a@b.co " * 30, 240),
        ("service", "a@b.co " * 15, 120),
        ("description", "a@b.co " * 2800, 20000),
    ],
    ids=["title", "service", "description"],
)
async def test_redaction_expansion_does_not_poison_saved_incidents(
    boundary_api: tuple[FastAPI, httpx.AsyncClient], field: str, value: str, limit: int
) -> None:
    _, client = boundary_api
    response = await client.post(
        "/api/v1/incidents", json={"title": "Failure", "service": "api", field: value}
    )
    assert response.status_code in (201, 422), response.text
    if response.status_code == 201:
        assert len(response.json()[field]) <= limit
    listing = await client.get("/api/v1/incidents")
    assert listing.status_code == 200, listing.text
    if response.status_code == 422:
        assert listing.json()["total"] == 0


async def test_non_ascii_authentication_is_401_not_500(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    _, client = boundary_api
    response = await client.get("/api/v1/incidents", headers={b"X-API-Key": b"\xff"})
    assert response.status_code == 401, response.text


async def test_openapi_declares_api_and_webhook_auth_separately(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    _, client = boundary_api
    schema = (await client.get("/openapi.json")).json()
    definitions = schema["components"]["securitySchemes"]
    names = {
        name: entry["name"]
        for name, entry in definitions.items()
        if entry["type"] == "apiKey"
    }
    incident_security = schema["paths"]["/api/v1/incidents"]["get"]["security"]
    webhook_security = schema["paths"]["/api/v1/webhooks/{source}"]["post"]["security"]
    assert any(names[key] == "X-API-Key" for item in incident_security for key in item)
    assert any(
        names[key] == "X-Webhook-Key" for item in webhook_security for key in item
    )


async def test_invalid_real_provider_response_is_an_assistive_fallback(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    app, client = boundary_api
    provider = OpenAILLMClient(
        Settings(openai_api_key="mock-key", llm_max_retries=0),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "untrusted output token=private"},
                        }
                    ]
                },
            )
        ),
    )
    app.state.llm = ResilientLLMClient(provider, provider="openai", timeout=1)
    incident = (
        await client.post(
            "/api/v1/incidents", json={"title": "DB error", "service": "api"}
        )
    ).json()
    response = await client.post(f"/api/v1/incidents/{incident['id']}/analysis")
    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "openai:fallback"
    assert response.json()["is_fallback"] is True
    assert "private" not in response.text


async def test_device_token_is_absent_from_access_log_records(
    boundary_api: tuple[FastAPI, httpx.AsyncClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = boundary_api
    records = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("incident_ai.http")
    monkeypatch.setattr(logger, "handlers", [Capture()])
    token = "fedcba9876543210" * 4
    await client.post("/api/v1/devices", json={"token": token})
    response = await client.delete(f"/api/v1/devices/{token}")
    assert response.status_code == 204
    assert records and all(
        token not in json.dumps(record.__dict__, default=str) for record in records
    )


async def test_production_export_failure_is_typed_and_has_no_fake_success(
    boundary_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    app, client = boundary_api
    incident = (
        await client.post(
            "/api/v1/incidents", json={"title": "Error", "service": "api"}
        )
    ).json()
    identifier = incident["id"]
    await client.post(f"/api/v1/incidents/{identifier}/analysis")
    await client.post(f"/api/v1/incidents/{identifier}/postmortem")
    app.state.settings.demo_mode = False
    response = await client.post(
        f"/api/v1/incidents/{identifier}/postmortem/export/jira"
    )
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "integration_configuration"
    postmortem = (await client.get(f"/api/v1/incidents/{identifier}/postmortem")).json()
    assert postmortem["jira_issue_key"] is None
