from collections.abc import Mapping
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


class AppError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def error_response(
    request: Request,
    code: str,
    message: str,
    status: int,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        {
            "error": {"code": code, "message": message},
            "correlation_id": getattr(request.state, "correlation_id", "unknown"),
        },
        status_code=status,
        headers=headers,
    )


async def app_error_handler(request: Request, exc: Any) -> JSONResponse:
    return error_response(request, exc.code, exc.message, exc.status_code)


async def http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPException)
    codes = {
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        429: "rate_limited",
        503: "unavailable",
    }
    return error_response(
        request,
        codes.get(exc.status_code, "request_error"),
        str(exc.detail),
        exc.status_code,
        exc.headers,
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # Never echo rejected input: it may contain credentials or private log data.
    fields = ", ".join(
        ".".join(str(part) for part in error["loc"]) for error in exc.errors()[:5]
    )
    return error_response(
        request, "validation_error", f"Invalid request fields: {fields}", 422
    )
