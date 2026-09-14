import gzip
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.config import Settings
from app.integrations.archival import archive_logs
from app.integrations.errors import IntegrationError
from app.integrations.exporters import (
    ConfluenceExporter,
    JiraExporter,
    get_exporter,
    markdown_to_adf,
    markdown_to_storage,
)
from app.integrations.notifiers import APNsNotifier, WebhookNotifier, notify_incident
from app.integrations.sources import get_source

INCIDENT = {
    "id": "693af39d-138c-4c58-aab0-8a263e777383",
    "title": "Checkout timeout",
    "service": "checkout",
    "severity": "high",
}


@pytest.mark.parametrize(
    ("source", "payload", "service", "severity"),
    [
        (
            "generic",
            {"title": "Timeout", "service": "api", "severity": "critical"},
            "api",
            "critical",
        ),
        (
            "grafana",
            {
                "alerts": [
                    {
                        "fingerprint": "aa",
                        "startsAt": "2026-09-14T10:00:00Z",
                        "labels": {
                            "alertname": "Latency",
                            "service": "api",
                            "severity": "warning",
                        },
                    }
                ]
            },
            "api",
            "medium",
        ),
        (
            "sentry",
            {
                "data": {
                    "event": {
                        "event_id": "123",
                        "title": "Exception",
                        "project": {"slug": "api"},
                        "level": "error",
                    }
                }
            },
            "api",
            "high",
        ),
        (
            "cloudwatch",
            {
                "AlarmName": "Latency",
                "NewStateValue": "ALARM",
                "StateChangeTime": "2026-09-14",
                "Trigger": {"Namespace": "AWS/RDS"},
            },
            "AWS/RDS",
            "high",
        ),
        (
            "zabbix",
            {
                "event_id": "123",
                "event_name": "CPU saturated",
                "host": "api",
                "severity": "5",
            },
            "api",
            "critical",
        ),
    ],
)
def test_source_normalization_and_deterministic_ids(
    source: str, payload: dict[str, Any], service: str, severity: str
) -> None:
    adapter = get_source(source)
    first = adapter.normalize(payload)
    assert first == adapter.normalize(json.loads(json.dumps(payload)))
    assert first[0].service == service
    assert first[0].severity == severity
    assert first[0].external_id


def test_fallback_identifiers_ignore_json_key_order_and_new_occurrences_differ() -> (
    None
):
    assert (
        get_source("generic")
        .normalize({"service": "api", "title": "Failure"})[0]
        .external_id
        == get_source("generic")
        .normalize({"title": "Failure", "service": "api"})[0]
        .external_id
    )
    adapter = get_source("grafana")
    first = adapter.normalize(
        {"alerts": [{"fingerprint": "abc", "startsAt": "first"}]}
    )[0]
    second = adapter.normalize(
        {"alerts": [{"fingerprint": "abc", "startsAt": "second"}]}
    )[0]
    assert first.external_id != second.external_id


@pytest.mark.parametrize(
    "source", ["generic", "grafana", "sentry", "cloudwatch", "zabbix", "invalid"]
)
def test_invalid_sources_are_rejected(source: str) -> None:
    with pytest.raises(ValueError):
        get_source(source).normalize({})


@pytest.mark.parametrize(
    ("source", "payload"),
    [
        ("grafana", {"alerts": [{"status": "resolved"}]}),
        ("cloudwatch", {"AlarmName": "Latency", "NewStateValue": "OK"}),
        (
            "cloudwatch",
            {
                "Type": "SubscriptionConfirmation",
                "SubscribeURL": "http://localhost/private",
            },
        ),
        ("zabbix", {"event_id": "123", "event_name": "Recovered", "event_value": 0}),
        ("sentry", {"action": "resolved", "data": {"issue": {"id": "123"}}}),
    ],
)
def test_recovery_events_do_not_create_new_incidents(
    source: str, payload: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        get_source(source).normalize(payload)


def test_sns_and_eventbridge_are_normalized_without_fetching_urls() -> None:
    sns = get_source("cloudwatch").normalize(
        {"Message": json.dumps({"AlarmName": "Alarm", "NewStateValue": "ALARM"})}
    )
    event = get_source("cloudwatch").normalize(
        {
            "id": "event-1",
            "source": "aws.cloudwatch",
            "detail": {
                "alarmName": "Alarm",
                "state": {"value": "ALARM", "reason": "Threshold"},
            },
        }
    )
    assert sns[0].title == event[0].title
    assert event[0].description == "Threshold"


def test_source_redacts_descriptions_and_logs() -> None:
    result = get_source("generic").normalize(
        {
            "title": "Contact person@example.org",
            "service": "api",
            "description": "password=secret",
            "logs": [{"message": "token=private remote=10.0.0.5"}],
        }
    )[0]
    serialized = result.model_dump_json()
    assert (
        "person@example.org" not in serialized and "password=secret" not in serialized
    )
    assert "token=private" not in serialized and "10.0.0.5" not in serialized


def test_adf_and_storage_escape_untrusted_text() -> None:
    markdown = "# Root cause\n<script>alert(1)</script>\n- Inspect traces\n```\ntoken=secret\n```"
    adf = markdown_to_adf(markdown)
    assert adf["type"] == "doc" and adf["version"] == 1
    assert adf["content"][0]["type"] == "heading"
    storage = markdown_to_storage(markdown)
    assert "<script>" not in storage and "&lt;script&gt;" in storage
    assert "token=secret" not in storage


async def test_demo_exports_are_explicit_and_deterministic() -> None:
    exporter = get_exporter("jira", Settings())
    first = await exporter.export(INCIDENT, "# Draft")
    assert first == await exporter.export(INCIDENT, "# Updated draft")
    assert first.is_demo and first.external_id.startswith("DEMO-")
    assert first.url.startswith("/api/v1/")


def test_production_missing_export_configuration_fails() -> None:
    settings = Settings().model_copy(update={"demo_mode": False})
    with pytest.raises(IntegrationError) as error:
        get_exporter("jira", settings)
    assert (
        error.value.status_code == 503
        and error.value.code == "integration_configuration"
    )


async def test_real_jira_uses_adf_and_reuses_persisted_identifier() -> None:
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = json.loads(request.content)
        assert request.url.path == "/rest/api/3/issue"
        assert request.headers["authorization"].startswith("Basic ")
        assert body["fields"]["description"]["type"] == "doc"
        assert "password=secret" not in request.content.decode()
        return httpx.Response(201, json={"key": "OPS-12"})

    settings = Settings(
        jira_base_url="https://example.atlassian.net",
        jira_email="account@example.org",
        jira_api_token="test",
        jira_project_key="OPS",
    )
    exporter = JiraExporter(settings, transport=httpx.MockTransport(respond))
    first = await exporter.export(INCIDENT, "# Test\npassword=secret")
    second = await exporter.export(
        INCIDENT | {"jira_issue_key": first.external_id}, "New text"
    )
    assert first == second and len(calls) == 1 and not first.is_demo
    assert first.url == "https://example.atlassian.net/browse/OPS-12"


@pytest.mark.parametrize("status", [401, 429, 503])
async def test_export_create_is_never_blindly_retried(status: int) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, json={"secret": "must-not-leak"})

    settings = Settings(
        jira_base_url="https://example.atlassian.net",
        jira_email="x",
        jira_api_token="y",
        jira_project_key="OPS",
    )
    with pytest.raises(IntegrationError) as error:
        await JiraExporter(settings, transport=httpx.MockTransport(respond)).export(
            INCIDENT, "text"
        )
    assert calls == 1 and "must-not-leak" not in str(error.value)


async def test_confluence_v2_safe_storage_and_url() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.url.path == "/wiki/api/v2/pages"
        assert body["spaceId"] == "123"
        assert body["body"]["representation"] == "storage"
        assert "<script>" not in body["body"]["value"]
        return httpx.Response(
            200, json={"id": "234", "_links": {"webui": "javascript:alert(1)"}}
        )

    settings = Settings(
        confluence_base_url="https://example.atlassian.net/wiki",
        confluence_email="x",
        confluence_api_token="y",
        confluence_space_id="123",
    )
    result = await ConfluenceExporter(
        settings, transport=httpx.MockTransport(respond)
    ).export(INCIDENT, "# Cause\n<script>unsafe</script>")
    assert (
        result.url
        == "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=234"
    )
    assert not result.is_demo


async def test_export_preserves_content_beyond_old_100k_boundary() -> None:
    markdown = "# Postmortem\n" + "x" * 100_001 + "\nFinal verification criteria"

    def respond(request: httpx.Request) -> httpx.Response:
        assert "Final verification criteria" in request.content.decode()
        return httpx.Response(201, json={"key": "OPS-14"})

    settings = Settings(
        jira_base_url="https://example.atlassian.net",
        jira_email="x",
        jira_api_token="y",
        jira_project_key="OPS",
    )
    await JiraExporter(settings, transport=httpx.MockTransport(respond)).export(
        INCIDENT, markdown
    )


async def test_notification_failures_do_not_block_other_destinations(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(
        logging.getLogger("incident_ai.notifications"), "handlers", [caplog.handler]
    )
    observed = []

    async def notify(self: WebhookNotifier, incident: dict[str, Any]) -> None:
        observed.append(self.destination)
        if self.destination == "slack":
            raise RuntimeError("https://private-url-with-secret")

    monkeypatch.setattr(WebhookNotifier, "notify", notify)
    await notify_incident(
        INCIDENT,
        Settings(
            slack_webhook_url="https://slack.example/hook",
            teams_webhook_url="https://teams.example/hook",
        ),
    )
    assert sorted(observed) == ["slack", "teams"]
    assert "private-url-with-secret" not in caplog.text


@pytest.mark.parametrize("destination", ["slack", "teams"])
async def test_chat_notification_payload_is_redacted(destination: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert "private@example.com" not in request.content.decode()
        if destination == "teams":
            assert payload["attachments"][0]["content"]["type"] == "AdaptiveCard"
        return httpx.Response(200, text="ok")

    notifier = WebhookNotifier(
        "https://notify.example/hook",
        destination=destination,
        timeout=1,
        transport=httpx.MockTransport(respond),
    )
    await notifier.notify(INCIDENT | {"title": "Failure private@example.com"})


async def test_apns_jwt_environment_payload_and_per_device_isolation(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        logging.getLogger("incident_ai.notifications"), "handlers", [caplog.handler]
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    settings = Settings(
        apns_key_id="KEY123", apns_team_id="TEAM123", apns_private_key=pem
    )
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        token = request.headers["authorization"].removeprefix("bearer ")
        claims = jwt.decode(token, private_key.public_key(), algorithms=["ES256"])
        assert claims["iss"] == "TEAM123"
        assert jwt.get_unverified_header(token)["kid"] == "KEY123"
        assert request.headers["apns-push-type"] == "alert"
        assert json.loads(request.content)["incident_id"] == INCIDENT["id"]
        return httpx.Response(
            410 if request.url.host.startswith("api.sandbox") else 200
        )

    await APNsNotifier(
        settings,
        [
            {"token": "a" * 64, "environment": "sandbox"},
            {"token": "b" * 64, "environment": "production"},
        ],
        transport=httpx.MockTransport(respond),
    ).notify(INCIDENT)
    assert len(requests) == 2
    assert {request.url.host for request in requests} == {
        "api.sandbox.push.apple.com",
        "api.push.apple.com",
    }
    assert "a" * 64 not in caplog.text
    assert "device_unregistered" in str(caplog.records[0].__dict__)


async def test_archive_demo_writes_redacted_idempotent_gzip(tmp_path: Path) -> None:
    settings = Settings(s3_demo_directory=str(tmp_path))
    logs = [
        {"message": "password=topsecret email=person@example.org", "level": "error"}
    ]
    first = await archive_logs(INCIDENT["id"], logs, settings)
    second = await archive_logs(INCIDENT["id"], logs, settings)
    assert first == second and first["is_demo"]
    raw = gzip.decompress((tmp_path / first["key"]).read_bytes()).decode()
    assert "topsecret" not in raw and "person@example.org" not in raw
    assert json.loads(raw)["level"] == "error"


async def test_s3_upload_is_real_content_addressed_and_encrypted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    import boto3

    client = MagicMock()
    session = MagicMock()
    session.client.return_value = client
    monkeypatch.setattr(boto3.session, "Session", lambda: session)
    result = await archive_logs(
        INCIDENT["id"],
        [{"message": "token=private"}],
        Settings(s3_bucket="test-archive"),
    )
    assert not result["is_demo"] and result["url"].startswith("s3://test-archive/")
    kwargs = client.put_object.call_args.kwargs
    assert (
        kwargs["ServerSideEncryption"] == "AES256"
        and kwargs["ContentEncoding"] == "gzip"
    )
    assert b"private" not in gzip.decompress(kwargs["Body"])
    client.close.assert_called_once()


async def test_archive_failure_and_path_traversal_are_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError):
        await archive_logs("../unsafe", [], Settings())
    with pytest.raises(IntegrationError):
        await archive_logs(
            INCIDENT["id"], [], Settings().model_copy(update={"demo_mode": False})
        )
    monkeypatch.setattr(
        "app.integrations.archival.asyncio.to_thread",
        AsyncMock(side_effect=RuntimeError("private credentials")),
    )
    with pytest.raises(IntegrationError) as error:
        await archive_logs(INCIDENT["id"], [], Settings(s3_bucket="archive"))
    assert "private credentials" not in str(error.value)
