import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker
from starlette.exceptions import HTTPException

from app.ai.client import get_llm_client
from app.api.routes import router, webhooks
from app.core.config import Settings, get_settings
from app.core.errors import (
    AppError,
    app_error_handler,
    error_response,
    http_error_handler,
    validation_error_handler,
)
from app.core.middleware import MemoryRateLimiter, RequestMiddleware
from app.core.telemetry import Metrics, configure_logging, scrub_trace_request
from app.integrations.errors import IntegrationError
from app.repository.database import build_engine, create_demo_schema


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        engine = build_engine(config)
        application.state.engine = engine
        application.state.session_factory = async_sessionmaker(
            engine, expire_on_commit=False
        )
        application.state.llm = get_llm_client(config)
        application.state.redis = (
            Redis.from_url(config.redis_url, socket_timeout=3, socket_connect_timeout=3)
            if config.redis_url
            else None
        )
        if config.demo_mode:
            await create_demo_schema(engine)
        try:
            yield
        finally:
            if application.state.redis:
                await application.state.redis.aclose()
            await engine.dispose()

    application = FastAPI(
        title="Incident AI",
        version="1.0.0",
        description="Assistive incident analysis. Engineers must verify evidence and approve remediation. Extended routes are labeled separately.",
        lifespan=lifespan,
    )
    application.state.settings = config
    application.state.metrics = Metrics()
    application.state.rate_limiter = MemoryRateLimiter()
    application.state.export_locks = defaultdict(asyncio.Lock)
    application.add_exception_handler(AppError, app_error_handler)
    application.add_exception_handler(IntegrationError, app_error_handler)
    application.add_exception_handler(HTTPException, http_error_handler)
    application.add_exception_handler(RequestValidationError, validation_error_handler)
    application.add_middleware(RequestMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=config.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=[
            "X-API-Key",
            "X-Webhook-Key",
            "Authorization",
            "Content-Type",
            "X-Correlation-ID",
        ],
        expose_headers=["X-Correlation-ID"],
    )
    application.include_router(router)
    application.include_router(webhooks)

    @application.get("/health", tags=["Operations"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "1.0.0"}

    @application.get("/ready", tags=["Operations"])
    async def ready(request: Request) -> Response:
        from fastapi.responses import JSONResponse

        try:
            async with application.state.engine.connect() as connection:
                await connection.execute(text("SELECT 1 FROM incidents LIMIT 1"))
            if application.state.redis:
                await application.state.redis.ping()
        except Exception:
            return error_response(
                request,
                "not_ready",
                "A required dependency or database migration is unavailable",
                503,
            )
        return JSONResponse({"status": "ready"})

    @application.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(
            generate_latest(application.state.metrics.registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    if config.otel_enabled:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(
            resource=Resource.create({"service.name": config.otel_service_name})
        )
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        FastAPIInstrumentor.instrument_app(
            application,
            tracer_provider=provider,
            server_request_hook=partial(scrub_trace_request, routes=application.routes),
            http_capture_headers_sanitize_fields=[".*"],
            excluded_urls="health,ready,metrics",
        )
    return application


app = create_app()
