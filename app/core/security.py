import hmac

import jwt
from fastapi import Request, Security
from fastapi.security import APIKeyHeader

from app.core.config import Settings
from app.core.errors import AppError

API_KEY = APIKeyHeader(name="X-API-Key", scheme_name="APIKey", auto_error=False)
WEBHOOK_KEY = APIKeyHeader(
    name="X-Webhook-Key", scheme_name="WebhookKey", auto_error=False
)


async def require_auth(
    request: Request, _api_key: str | None = Security(API_KEY)
) -> None:
    settings: Settings = request.app.state.settings
    supplied = request.headers.get("x-api-key", "")
    if supplied and hmac.compare_digest(
        supplied.encode("utf-8"), settings.api_key.encode("utf-8")
    ):
        return
    authorization = request.headers.get("authorization", "")
    if settings.jwt_secret and authorization.startswith("Bearer "):
        try:
            jwt.decode(
                authorization[7:],
                settings.jwt_secret,
                algorithms=["HS256"],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
            return
        except jwt.PyJWTError:
            pass
    raise AppError("unauthorized", "A valid API key or bearer token is required", 401)


async def require_webhook_auth(
    request: Request, _webhook_key: str | None = Security(WEBHOOK_KEY)
) -> None:
    settings: Settings = request.app.state.settings
    key = request.headers.get("x-webhook-key", "")
    if (
        key
        and settings.webhook_key
        and hmac.compare_digest(
            key.encode("utf-8"), settings.webhook_key.encode("utf-8")
        )
    ):
        return
    if settings.demo_mode:
        await require_auth(request)
        return
    raise AppError("unauthorized", "A valid webhook key is required", 401)
