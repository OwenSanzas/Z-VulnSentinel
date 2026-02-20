"""Request ID middleware — generates or validates X-Request-ID for every request."""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

log = structlog.get_logger()


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique request_id to every request via structlog contextvars."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        raw_id = request.headers.get("x-request-id", "")
        request_id = raw_id if _is_valid_uuid(raw_id) else str(uuid.uuid4())

        tokens = structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        start = time.perf_counter()
        try:
            log.info("request started")
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start) * 1000, 1)
            log.info("request completed", status_code=response.status_code, duration_ms=duration_ms)
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 1)
            log.exception("request failed", duration_ms=duration_ms)
            raise
        finally:
            structlog.contextvars.reset_contextvars(**tokens)
