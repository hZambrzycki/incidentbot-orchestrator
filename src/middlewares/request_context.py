# src/middlewares/request_context.py

import uuid

import structlog
import structlog.contextvars
from fastapi import Request


async def request_context_middleware(request: Request, call_next):
    request_id = uuid.uuid4().hex[:12]
    request.state.request_id = request_id  # clave

    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        client_ip=request.client.host if request.client else "unknown",
    )

    try:
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response
    finally:
        structlog.contextvars.clear_contextvars()
