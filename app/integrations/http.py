"""Bounded HTTP operations. Creation requests are never automatically replayed."""

import asyncio
from typing import Any

import httpx

from app.integrations.errors import IntegrationError

MAX_RESPONSE_BYTES = 512_000


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 0,
    **kwargs: Any,
) -> dict[str, Any]:
    """Retry transient errors only when the caller explicitly declares it safe."""
    retries = min(max(retries, 0), 3)
    for attempt in range(retries + 1):
        delay = min(0.25 * (2**attempt), 2.0)
        try:
            async with client.stream(method, url, **kwargs) as response:
                if response.status_code in (408, 429, 500, 502, 503, 504):
                    if attempt < retries:
                        try:
                            delay = min(
                                max(
                                    float(response.headers.get("retry-after", delay)), 0
                                ),
                                3,
                            )
                        except ValueError:
                            pass
                    else:
                        raise IntegrationError(
                            "External service is temporarily unavailable. Try again later.",
                            code=(
                                "integration_rate_limited"
                                if response.status_code == 429
                                else "integration_unavailable"
                            ),
                        )
                elif not response.is_success:
                    raise IntegrationError(
                        "External service rejected the request. Check integration configuration.",
                        code="integration_rejected",
                    )
                else:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise IntegrationError(
                                "External response exceeded the size limit.",
                                code="integration_invalid_response",
                            )
                    try:
                        import json

                        result = json.loads(body)
                        if not isinstance(result, dict):
                            raise ValueError("Expected object")
                        return result
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise IntegrationError(
                            "External service returned invalid JSON.",
                            code="integration_invalid_response",
                        ) from exc
        except httpx.RequestError as exc:
            if attempt >= retries:
                raise IntegrationError(
                    "External service could not be reached. For exports, check the destination before retrying.",
                    code="integration_timeout",
                ) from exc
        await asyncio.sleep(delay)
    raise IntegrationError("External service retry budget exhausted.")
