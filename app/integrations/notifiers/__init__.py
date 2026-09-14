"""Optional Slack, Teams and APNs notifications with per-destination isolation."""

import asyncio
import hashlib
import logging
import re
import time
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
import jwt

from app.ai.redaction import redact
from app.integrations.errors import IntegrationError

logger = logging.getLogger("incident_ai.notifications")
_JWT_CACHE: dict[str, tuple[float, str]] = {}


class Notifier(Protocol):
    async def notify(self, incident: dict[str, Any]) -> None: ...


def _message(incident: dict[str, Any]) -> str:
    severity = str(incident.get("severity", "medium")).upper()[:20]
    title = redact(str(incident.get("title", "Incident")))[:240]
    service = redact(str(incident.get("service", "unknown")))[:120]
    return f"[{severity}] {title}\nService: {service}\nIncident: {incident['id']}"


class WebhookNotifier:
    def __init__(
        self,
        url: str,
        *,
        destination: str,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self.destination = destination
        self.timeout = timeout
        self.transport = transport

    async def notify(self, incident: dict[str, Any]) -> None:
        parsed = urlsplit(self.url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise IntegrationError(
                "Notification webhook must use HTTPS without embedded credentials."
            )
        message = _message(incident)
        if self.destination == "slack":
            payload = {
                "text": message,
                "mrkdwn": False,
                "unfurl_links": False,
                "unfurl_media": False,
            }
        else:
            payload = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "contentUrl": None,
                        "content": {
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard",
                            "version": "1.2",
                            "body": [
                                {"type": "TextBlock", "text": message, "wrap": True}
                            ],
                        },
                    }
                ],
            }
        # No retry: webhook delivery is not idempotent and may already have succeeded.
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            async with client.stream("POST", self.url, json=payload) as response:
                if not response.is_success:
                    raise IntegrationError(
                        f"{self.destination} notification was rejected."
                    )


def _apns_token(settings: Any) -> str:
    key = settings.apns_private_key.replace("\\n", "\n")
    fingerprint = hashlib.sha256(
        f"{settings.apns_team_id}:{settings.apns_key_id}:{key}".encode()
    ).hexdigest()
    now = time.time()
    cached = _JWT_CACHE.get(fingerprint)
    if cached and 0 <= now - cached[0] < 2_400:
        return cached[1]
    token = jwt.encode(
        {"iss": settings.apns_team_id, "iat": int(now)},
        key,
        algorithm="ES256",
        headers={"kid": settings.apns_key_id},
    )
    # A single active configuration is expected; key rotation must not retain keys.
    _JWT_CACHE.clear()
    _JWT_CACHE[fingerprint] = (now, token)
    return token


class APNsNotifier:
    def __init__(
        self,
        settings: Any,
        devices: list[dict[str, str]],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.devices = devices
        self.transport = transport

    async def notify(self, incident: dict[str, Any]) -> None:
        bearer = _apns_token(self.settings)
        payload = {
            "aps": {
                "alert": {
                    "title": "Incident AI",
                    "body": redact(str(incident.get("title", "New incident")))[:200],
                },
                "sound": "default",
                "thread-id": str(incident["id"]),
            },
            "incident_id": str(incident["id"]),
        }
        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient(
            http2=True,
            timeout=self.settings.integration_timeout_seconds,
            transport=self.transport,
        ) as client:

            async def send(device: dict[str, str]) -> None:
                token = device.get("token", "")
                environment = device.get("environment", "sandbox")
                if not re.fullmatch(
                    r"[0-9a-fA-F]{64,200}", token
                ) or environment not in ("sandbox", "production"):
                    raise IntegrationError("Invalid APNs device registration.")
                host = (
                    "api.sandbox.push.apple.com"
                    if environment == "sandbox"
                    else "api.push.apple.com"
                )
                async with semaphore:
                    async with client.stream(
                        "POST",
                        f"https://{host}/3/device/{token}",
                        headers={
                            "authorization": f"bearer {bearer}",
                            "apns-topic": self.settings.apns_bundle_id,
                            "apns-push-type": "alert",
                            "apns-priority": "10",
                            "apns-expiration": str(int(time.time()) + 3_600),
                            "apns-collapse-id": hashlib.sha256(
                                str(incident["id"]).encode()
                            ).hexdigest(),
                        },
                        json=payload,
                    ) as response:
                        if not response.is_success:
                            # Device tokens and APNs response payloads are private.
                            logger.warning(
                                "apns_delivery_failed",
                                extra={
                                    "status_code": response.status_code,
                                    "reason": (
                                        "device_unregistered"
                                        if response.status_code == 410
                                        else "rejected"
                                    ),
                                },
                            )

            results = await asyncio.gather(
                *(send(device) for device in self.devices), return_exceptions=True
            )
            for result in results:
                if isinstance(result, BaseException):
                    logger.warning(
                        "apns_delivery_failed",
                        extra={"error_type": type(result).__name__},
                    )


async def notify_incident(
    incident: dict[str, Any], settings: Any, devices: list[dict[str, str]] | None = None
) -> None:
    notifiers: list[tuple[str, Notifier]] = []
    for destination in ("slack", "teams"):
        url = getattr(settings, f"{destination}_webhook_url", "")
        if url:
            notifiers.append(
                (
                    destination,
                    WebhookNotifier(
                        url,
                        destination=destination,
                        timeout=settings.integration_timeout_seconds,
                    ),
                )
            )
    apns_fields = ("apns_key_id", "apns_team_id", "apns_private_key", "apns_bundle_id")
    if devices and all(getattr(settings, key, "") for key in apns_fields):
        notifiers.append(("apns", APNsNotifier(settings, devices)))
    elif devices:
        logger.info("apns_not_configured", extra={"device_count": len(devices)})
    results = await asyncio.gather(
        *(notifier.notify(incident) for _, notifier in notifiers),
        return_exceptions=True,
    )
    for (name, _), result in zip(notifiers, results, strict=True):
        if isinstance(result, BaseException):
            logger.warning(
                "notification_failed",
                extra={"destination": name, "error_type": type(result).__name__},
            )
