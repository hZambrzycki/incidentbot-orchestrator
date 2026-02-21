# src/api/middleware.py
from __future__ import annotations

from fastapi import Request

from ..middlewares.access_log import access_log_middleware
from ..middlewares.request_context import request_context_middleware


async def access_log_mw(request: Request, call_next):
    return await access_log_middleware(request, call_next)


async def request_context_mw(request: Request, call_next):
    return await request_context_middleware(request, call_next)
