"""Unified error handling — ServiceError + RequestValidationError → JSON."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from vulnsentinel.dao.base import InvalidCursorError
from vulnsentinel.services import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    ServiceError,
    ValidationError,
)

_STATUS_MAP: dict[type[ServiceError], int] = {
    NotFoundError: 404,
    ConflictError: 409,
    ValidationError: 422,
    AuthenticationError: 401,
}


async def _service_error_handler(_request: Request, exc: ServiceError) -> JSONResponse:
    status = 500
    for cls in type(exc).__mro__:
        if cls in _STATUS_MAP:
            status = _STATUS_MAP[cls]
            break
    return JSONResponse(status_code=status, content={"detail": str(exc)})


async def _validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = exc.errors()
    messages = []
    for err in errors:
        loc = " → ".join(str(part) for part in err["loc"])
        messages.append(f"{loc}: {err['msg']}")
    return JSONResponse(
        status_code=422,
        content={"detail": "; ".join(messages)},
    )


async def _invalid_cursor_handler(
    _request: Request, exc: InvalidCursorError
) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


def register_error_handlers(app: FastAPI) -> None:
    """Register exception handlers on the app."""
    app.add_exception_handler(ServiceError, _service_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(InvalidCursorError, _invalid_cursor_handler)  # type: ignore[arg-type]
