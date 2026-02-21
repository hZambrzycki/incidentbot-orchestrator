# src/middlewares/access_log.py
import time

import structlog
from fastapi import Request

log = structlog.get_logger("access")


async def access_log_middleware(request: Request, call_next):
    start = time.perf_counter()
    status_code = 500

    client_ip = request.client.host if request.client else None
    request_id = getattr(request.state, "request_id", None)

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response

    finally:
        dur_ms = int((time.perf_counter() - start) * 1000)

        level = "info"
        if status_code >= 500:
            level = "error"
        elif status_code >= 400:
            level = "warning"

        getattr(log, level)(
            "http_request",
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            status_code=status_code,
            duration_ms=dur_ms,
            client_ip=client_ip,
            request_id=request_id,
        )
