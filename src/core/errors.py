import structlog
from fastapi import Request
from fastapi.responses import JSONResponse
from structlog.contextvars import get_contextvars

log = structlog.get_logger("errors")


async def unhandled_exception_handler(request: Request, exc: Exception):
    # Primary source: request.state (set by middleware)
    request_id = getattr(request.state, "request_id", None)

    # Fallback: structlog contextvars
    if not request_id:
        try:
            request_id = (get_contextvars() or {}).get("request_id")
        except Exception:
            request_id = None

    log.exception(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        request_id=request_id,
    )

    res = JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "request_id": request_id,
        },
    )

    if request_id:
        res.headers["X-Request-Id"] = request_id

    return res
