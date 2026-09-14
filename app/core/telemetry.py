import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime

from opentelemetry.trace import Span
from prometheus_client import CollectorRegistry, Counter, Histogram
from starlette.routing import BaseRoute, Match
from starlette.types import Scope


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name in (
            "correlation_id",
            "method",
            "path",
            "status",
            "duration_ms",
            "provider",
            "error_type",
            "destination",
            "status_code",
            "reason",
            "device_count",
        ):
            if hasattr(record, name):
                payload[name] = getattr(record, name)
        return json.dumps(payload)


def configure_logging() -> None:
    # Our structured middleware logs templates. Default server access logs would
    # expose APNs tokens in the device-unregistration URL.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger = logging.getLogger("incident_ai")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False


def scrub_trace_request(span: Span, scope: Scope, routes: Sequence[BaseRoute]) -> None:
    """Keep route templates in traces, never APNs tokens or search query text."""
    if not span.is_recording():
        return
    path = "/unmatched"
    for route in routes:
        match, _ = route.matches(scope)
        if match in {Match.FULL, Match.PARTIAL}:
            path = getattr(route, "path", "/unmatched")
            break
    span.update_name(f"{scope.get('method', 'HTTP')} {path}")
    for key in ("http.url", "url.full"):
        span.set_attribute(key, f"http://incident-ai{path}")
    for key in ("http.target", "url.path"):
        span.set_attribute(key, path)
    span.set_attribute("url.query", "")


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "incident_ai_http_requests_total",
            "HTTP request count",
            ["method", "path", "status"],
            registry=self.registry,
        )
        self.duration = Histogram(
            "incident_ai_http_request_duration_seconds",
            "HTTP request duration",
            ["method", "path"],
            registry=self.registry,
        )
