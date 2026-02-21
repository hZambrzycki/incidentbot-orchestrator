# src/api/helpers.py
from __future__ import annotations

import asyncio
import random
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field


class ConfirmRunbookRequest(BaseModel):
    incident_id: str
    pending_execution_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


async def _execute_retry(
    *, db, sql: str, params=(), retries: int = 8, base_sleep: float = 0.03
):
    for i in range(retries):
        try:
            return await db.execute(sql, params)
        except sqlite3.OperationalError as e:
            if "database is locked" not in str(e).lower():
                raise
            await asyncio.sleep(base_sleep * (2**i) + random.random() * base_sleep)
    return await db.execute(sql, params)


def normalize_execution_status(execution) -> tuple[str, bool]:
    st = str(getattr(execution.status, "value", execution.status)).lower()
    if st == "failed":
        st = "error"
    is_ok = st in ("success", "skipped")
    return st, is_ok


def _derive_confirmation_status_from_payload(payload: dict) -> Optional[str]:
    st = (payload.get("runbook_status") or "").strip().lower()
    if not st:
        exec_obj = payload.get("execution") or {}
        st = str(exec_obj.get("status") or "").strip().lower()

    if st == "failed":
        st = "error"
    if st in ("success", "skipped", "error"):
        return st

    if "success" in payload:
        return "success" if bool(payload.get("success")) else "error"
    return None


# Telegram-safe in-memory limiter (used by confirmation impl when request=None)
_TG_CONFIRM_WINDOW_S = 30
_TG_CONFIRM_MAX = 6
_tg_confirm_hits: dict[str, deque[float]] = defaultdict(deque)


def _tg_rate_limit_confirm(chat_id: Optional[str]) -> None:
    if not chat_id:
        return
    now = time.time()
    q = _tg_confirm_hits[str(chat_id)]
    while q and (now - q[0]) > _TG_CONFIRM_WINDOW_S:
        q.popleft()
    if len(q) >= _TG_CONFIRM_MAX:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for telegram confirm (chat_id={chat_id})",
        )
    q.append(now)


def _parse_iso_utc(dt_raw: Optional[str]) -> Optional[datetime]:
    if not dt_raw:
        return None
    try:
        dt = datetime.fromisoformat(dt_raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None
        return None
