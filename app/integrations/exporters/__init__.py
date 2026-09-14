"""Explicit demo exports and authenticated Jira/Confluence Cloud adapters.

The service persists ExportResult to make completed exports idempotent. A create
POST is never automatically retried because an HTTP timeout may follow creation.
"""

import hashlib
import html
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel

from app.ai.redaction import redact
from app.integrations.errors import IntegrationError
from app.integrations.http import request_json


class ExportResult(BaseModel):
    destination: str
    external_id: str
    url: str
    is_demo: bool


class Exporter(Protocol):
    async def export(self, incident: dict[str, Any], markdown: str) -> ExportResult: ...


def markdown_to_adf(markdown: str) -> dict[str, Any]:
    """Represent Markdown as safe ADF blocks, including headings/lists/code."""
    blocks: list[dict[str, Any]] = []
    code: list[str] | None = None
    for line in redact(markdown).splitlines():
        if line.startswith("```"):
            if code is None:
                code = []
            else:
                blocks.append(
                    {
                        "type": "codeBlock",
                        "content": [{"type": "text", "text": "\n".join(code) or " "}],
                    }
                )
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        if not line.strip():
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            blocks.append(
                {
                    "type": "heading",
                    "attrs": {"level": len(heading[1])},
                    "content": [{"type": "text", "text": heading[2]}],
                }
            )
        elif re.match(r"^[-*]\s+", line):
            item = {
                "type": "listItem",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": line[2:]}],
                    }
                ],
            }
            if blocks and blocks[-1]["type"] == "bulletList":
                blocks[-1]["content"].append(item)
            else:
                blocks.append({"type": "bulletList", "content": [item]})
        else:
            blocks.append(
                {"type": "paragraph", "content": [{"type": "text", "text": line}]}
            )
    if code is not None:
        blocks.append(
            {
                "type": "codeBlock",
                "content": [{"type": "text", "text": "\n".join(code) or " "}],
            }
        )
    return {
        "type": "doc",
        "version": 1,
        "content": blocks or [{"type": "paragraph", "content": []}],
    }


def markdown_to_storage(markdown: str) -> str:
    """Convert the supported ADF block subset to escaped Confluence storage XML."""

    def render(node: dict[str, Any]) -> str:
        kind = node["type"]
        if kind == "text":
            return html.escape(node["text"])
        content = "".join(render(child) for child in node.get("content", []))
        tags = {
            "doc": "div",
            "paragraph": "p",
            "bulletList": "ul",
            "listItem": "li",
            "codeBlock": "pre",
        }
        tag = f"h{node['attrs']['level']}" if kind == "heading" else tags[kind]
        return f"<{tag}>{content}</{tag}>"

    return render(markdown_to_adf(markdown))


def _base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise IntegrationError(
            "Integration base URL must be an HTTPS URL without credentials, query or fragment.",
            code="integration_configuration",
        )
    return value.rstrip("/")


class DemoExporter:
    def __init__(self, destination: str) -> None:
        self.destination = destination

    async def export(self, incident: dict[str, Any], markdown: str) -> ExportResult:
        identifier = str(incident["id"])
        digest = (
            hashlib.sha256(f"{self.destination}:{identifier}".encode())
            .hexdigest()[:10]
            .upper()
        )
        return ExportResult(
            destination=self.destination,
            external_id=f"DEMO-{digest}",
            url=f"/api/v1/incidents/{identifier}/postmortem/markdown",
            is_demo=True,
        )


class JiraExporter:
    def __init__(
        self, settings: Any, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport

    async def export(self, incident: dict[str, Any], markdown: str) -> ExportResult:
        if len(markdown) > 250_000:
            raise IntegrationError(
                "Postmortem exceeds the 250000 character export limit.",
                code="export_too_large",
                status_code=413,
            )
        base = _base_url(self.settings.jira_base_url)
        existing = incident.get("jira_issue_key")
        if existing:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*-\d+", str(existing)):
                raise IntegrationError(
                    "Stored Jira issue identifier is invalid.",
                    code="integration_invalid_response",
                )
            return ExportResult(
                destination="jira",
                external_id=existing,
                url=f"{base}/browse/{existing}",
                is_demo=False,
            )
        async with httpx.AsyncClient(
            timeout=self.settings.integration_timeout_seconds, transport=self.transport
        ) as client:
            data = await request_json(
                client,
                "POST",
                f"{base}/rest/api/3/issue",
                auth=(self.settings.jira_email, self.settings.jira_api_token),
                json={
                    "fields": {
                        "project": {"key": self.settings.jira_project_key},
                        "summary": redact(
                            f"Postmortem: {incident.get('title', 'Incident')}"
                        )[:255],
                        "issuetype": {
                            "name": getattr(self.settings, "jira_issue_type", "Task")
                        },
                        "description": markdown_to_adf(markdown),
                        "labels": ["incident-ai", f"incident-{incident['id']}"],
                    }
                },
            )
        key = data.get("key")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*-\d+", key):
            raise IntegrationError(
                "Jira returned an invalid issue identifier. Check Jira before retrying.",
                code="integration_invalid_response",
            )
        return ExportResult(
            destination="jira",
            external_id=key,
            url=f"{base}/browse/{key}",
            is_demo=False,
        )


class ConfluenceExporter:
    def __init__(
        self, settings: Any, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport

    async def export(self, incident: dict[str, Any], markdown: str) -> ExportResult:
        if len(markdown) > 250_000:
            raise IntegrationError(
                "Postmortem exceeds the 250000 character export limit.",
                code="export_too_large",
                status_code=413,
            )
        base = _base_url(self.settings.confluence_base_url)
        wiki = base if base.endswith("/wiki") else f"{base}/wiki"
        async with httpx.AsyncClient(
            timeout=self.settings.integration_timeout_seconds, transport=self.transport
        ) as client:
            data = await request_json(
                client,
                "POST",
                f"{wiki}/api/v2/pages",
                auth=(
                    self.settings.confluence_email,
                    self.settings.confluence_api_token,
                ),
                json={
                    "spaceId": self.settings.confluence_space_id,
                    "status": "current",
                    "title": redact(f"Postmortem: {incident.get('title', 'Incident')}")[
                        :200
                    ]
                    + f" ({str(incident['id'])[:8]})",
                    "body": {
                        "representation": "storage",
                        "value": markdown_to_storage(markdown),
                    },
                },
            )
        page_id = data.get("id")
        if not isinstance(page_id, str) or not page_id.isdigit():
            raise IntegrationError(
                "Confluence returned an invalid page identifier. Check Confluence before retrying.",
                code="integration_invalid_response",
            )
        return ExportResult(
            destination="confluence",
            external_id=page_id,
            url=f"{wiki}/pages/viewpage.action?pageId={page_id}",
            is_demo=False,
        )


def get_exporter(destination: str, settings: Any) -> Exporter:
    required = {
        "jira": ("jira_base_url", "jira_email", "jira_api_token", "jira_project_key"),
        "confluence": (
            "confluence_base_url",
            "confluence_email",
            "confluence_api_token",
            "confluence_space_id",
        ),
    }
    if destination not in required:
        raise ValueError("Export destination must be jira or confluence")
    if not all(getattr(settings, field, "") for field in required[destination]):
        if settings.demo_mode:
            return DemoExporter(destination)
        raise IntegrationError(
            f"Configure all {destination} settings before exporting.",
            code="integration_configuration",
        )
    return (
        JiraExporter(settings)
        if destination == "jira"
        else ConfluenceExporter(settings)
    )
