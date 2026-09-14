import logging
import re
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.errors import error_response

logger = logging.getLogger("incident_ai.http")
RATE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], 60) end
return count
"""


class RequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        supplied_id = request.headers.get("x-correlation-id", "")
        request.state.correlation_id = (
            supplied_id
            if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", supplied_id)
            else str(uuid.uuid4())
        )
        started = time.monotonic()
        try:
            response = await self.handle_request(request, call_next)
        except Exception as exc:
            logger.error(
                "Unhandled request failure: %s",
                type(exc).__name__,
                extra={"correlation_id": request.state.correlation_id},
            )
            response = error_response(
                request,
                "internal_error",
                "The request could not be completed. Retry using the correlation ID for support.",
                500,
            )
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        route = getattr(request.scope.get("route"), "path", "unmatched")
        elapsed = time.monotonic() - started
        metrics = request.app.state.metrics
        metrics.requests.labels(request.method, route, str(response.status_code)).inc()
        metrics.duration.labels(request.method, route).observe(elapsed)
        logger.info(
            "HTTP request completed",
            extra={
                "correlation_id": request.state.correlation_id,
                "method": request.method,
                "path": route,
                "status": response.status_code,
                "duration_ms": round(elapsed * 1000, 2),
            },
        )
        return response

    async def handle_request(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        settings = request.app.state.settings
        if request.url.path.startswith("/api/"):
            host = request.client.host if request.client else "unknown"
            redis = request.app.state.redis
            if redis is not None:
                try:
                    count = await redis.eval(RATE_SCRIPT, 1, f"incident-ai:rate:{host}")
                    limited = count > settings.rate_limit_per_minute
                except RedisError:
                    return error_response(
                        request,
                        "rate_limiter_unavailable",
                        "Rate limiting is temporarily unavailable",
                        503,
                    )
            else:
                limiter: MemoryRateLimiter = request.app.state.rate_limiter
                limited = limiter.exceeded(host, settings.rate_limit_per_minute)
            if limited:
                return error_response(
                    request,
                    "rate_limited",
                    "Too many requests. Retry in 60 seconds.",
                    429,
                    {"Retry-After": "60"},
                )
        if request.method in {"POST", "PATCH", "PUT"}:
            declared = request.headers.get("content-length")
            if declared:
                try:
                    if int(declared) > settings.max_request_bytes or int(declared) < 0:
                        return error_response(
                            request,
                            "payload_too_large",
                            "Request body exceeds the configured limit",
                            413,
                        )
                except ValueError:
                    return error_response(
                        request,
                        "invalid_content_length",
                        "Invalid Content-Length header",
                        400,
                    )
            chunks: list[bytes] = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_request_bytes:
                    return error_response(
                        request,
                        "payload_too_large",
                        "Request body exceeds the configured limit",
                        413,
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        return await call_next(request)


class MemoryRateLimiter:
    def __init__(self) -> None:
        self.windows: dict[str, deque[float]] = defaultdict(deque)
        self.last_cleanup = time.monotonic()

    def exceeded(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        if now - self.last_cleanup > 60:
            self.windows = defaultdict(
                deque,
                {
                    name: entries
                    for name, entries in self.windows.items()
                    if entries and entries[-1] > now - 60
                },
            )
            self.last_cleanup = now
        window = self.windows[key]
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False
