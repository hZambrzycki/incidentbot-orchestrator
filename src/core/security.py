from __future__ import annotations

import asyncio
import hashlib
import math
import secrets
import time
from typing import Dict, Optional, Tuple

import structlog
import structlog.contextvars
from fastapi import Header, HTTPException, Request, status

from .config import settings

# ===========================================
# Imports
# ===========================================


log = structlog.get_logger("security")

# ===========================================
# Admin auth helpers
# ===========================================


def _token_from_headers(
    x_admin_token: Optional[str],
    authorization: Optional[str],
) -> Optional[str]:
    if x_admin_token:
        return x_admin_token.strip()

    if getattr(settings, "admin_allow_bearer", True) and authorization:
        # Authorization: Bearer <token>
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    return None


def _token_actor_id(token: str) -> str:
    h = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"admin:{h[:12]}"


def require_admin(
    request: Request,
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> str:
    allowed = settings.admin_token_list

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin token not configured",
        )

    token = _token_from_headers(x_admin_token, authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )

    # constant-time compare across allowed tokens
    ok = any(secrets.compare_digest(token, t) for t in allowed)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )

    request.state.actor_id = _token_actor_id(token)
    structlog.contextvars.bind_contextvars(actor_id=request.state.actor_id)

    return request.state.actor_id


# ===========================================
# Simple in-memory rate limiter
# ===========================================

_rate_lock = asyncio.Lock()
_hits: Dict[Tuple[str, str], list[float]] = {}


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _rate_key(request: Request, bucket: str) -> Tuple[str, str]:
    mode = getattr(settings, "rate_limit_key_mode", "token_or_ip")
    if mode == "ip_only":
        return (_client_ip(request), bucket)

    actor = getattr(getattr(request, "state", None), "actor_id", None)
    if actor:
        return (actor, bucket)

    return (_client_ip(request), bucket)


async def rate_limit(
    request: Request,
    bucket: str,
    max_hits: int,
    window_seconds: int,
) -> None:
    key = _rate_key(request, bucket)
    now = time.time()
    cutoff = now - window_seconds

    async with _rate_lock:
        arr = _hits.get(key, [])
        arr = [t for t in arr if t >= cutoff]

        if len(arr) >= max_hits:
            retry_after = math.ceil(arr[0] + window_seconds - now)
            if retry_after < 0:
                retry_after = 0

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limited ({bucket}). Retry in {retry_after}s",
                headers={"Retry-After": str(retry_after)},
            )

        arr.append(now)
        _hits[key] = arr
