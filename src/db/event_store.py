# src/db/event_store.py
"""
Event store (SQLite) for Incident Bot.

Goals:
- Timeline events: idempotent inserts via event_key (ON CONFLICT DO NOTHING)
- Runbook failures: idempotent inserts via failure_key (recommended) so we don't
  accidentally drop useful rows when a single execution fails in multiple ways.

IMPORTANT DB MIGRATIONS (schema.sql):
1) incident_events must have UNIQUE(event_key)
2) runbook_failures should add failure_key + unique index:

   ALTER TABLE runbook_failures ADD COLUMN failure_key TEXT;
   CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_failures_failure_key
     ON runbook_failures(failure_key);

If you cannot / don't want to add a column, use an alternative unique index:
   CREATE UNIQUE INDEX IF NOT EXISTS uq_rf_exec_kind_final
     ON runbook_failures(execution_id, failure_kind, is_final);
and adjust ON CONFLICT accordingly. This module uses failure_key by default.
"""

# ===========================================
# Imports
# ===========================================

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiosqlite

from .connection import DB_PATH, DB_WRITE_LOCK

# ===========================================
# Helpers (pure / formatting)
# ===========================================


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(obj: Any) -> str:
    return json.dumps(obj or {}, ensure_ascii=False, default=str)


def _hash_error(msg: Optional[str]) -> Optional[str]:
    if not msg:
        return None
    s = msg.strip()
    if not s:
        return None
    # stable grouping key (don’t store huge stacktraces in the hash)
    s = s[:2000]
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _normalize_severity(severity: Optional[str]) -> str:
    sev = (severity or "info").strip().lower()
    # Keep small stable vocabulary (UI-friendly)
    if sev not in ("debug", "info", "warning", "error", "critical"):
        sev = "info"
    return sev


def _failure_key(
    execution_id: str, failure_kind: str, is_final: bool, attempt_no: Optional[int]
) -> str:
    """
    Stable idempotency key for failures.

    Design:
    - execution_id: mandatory
    - failure_kind: groups "timeout", "exception", "validation", ...
    - is_final: distinguish terminal vs intermediate
    - attempt_no: optional; if present it lets you keep per-attempt rows distinct.
      If you want "exactly one final per execution", pass attempt_no=None for finals.
    """
    fk = (failure_kind or "unknown").strip().lower()[:64]
    fin = "1" if is_final else "0"
    att = "" if attempt_no is None else str(int(attempt_no))
    return f"{execution_id}:{fk}:{fin}:{att}"


# ===========================================
# DB write plumbing
# ===========================================


async def _connect_write() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA busy_timeout = 10000;")
    await db.execute("PRAGMA foreign_keys=ON;")
    await db.execute("PRAGMA synchronous=NORMAL;")
    return db


async def _with_write(fn, *, retries: int = 8, base_sleep: float = 0.03):
    """
    Single global write lock avoids SQLITE_BUSY storms under load.

    We still retry inside the lock for cases where another *process* (outside this
    app instance) is holding a write lock.
    """
    async with DB_WRITE_LOCK:
        last_err: Optional[Exception] = None

        for i in range(int(retries)):
            db = await _connect_write()
            try:
                await db.execute("BEGIN IMMEDIATE")
                out = await fn(db)
                await db.commit()
                return out

            except sqlite3.OperationalError as e:
                last_err = e
                try:
                    await db.rollback()
                except Exception:
                    pass

                if "database is locked" not in str(e).lower():
                    raise

                # expo backoff + jitter
                await asyncio.sleep(base_sleep * (2**i) + random.random() * base_sleep)

            finally:
                try:
                    await db.close()
                except Exception:
                    pass

        # After retries, re-raise for visibility (callers may swallow fail-open)
        if last_err:
            raise last_err
        raise sqlite3.OperationalError("database is locked")


# ===========================================
# Public API
# ===========================================


async def emit_event(
    *,
    event_key: str,
    event_type: str,
    actor: str,
    source: str,
    severity: str = "info",
    message: Optional[str] = None,
    incident_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    confirmation_id: Optional[str] = None,
    queue_execution_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Idempotent timeline event.
    Returns True if inserted, False if already existed or if storage failed.

    Requirements:
    - incident_events has UNIQUE(event_key)
    """
    if not event_key:
        return False

    sev = _normalize_severity(severity)

    async def _op(db: aiosqlite.Connection) -> bool:
        cur = await db.execute(
            """
            INSERT INTO incident_events(
              id, event_key, created_at,
              incident_id, execution_id, confirmation_id, queue_execution_id,
              event_type, severity, actor, source, message, details_json
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(event_key) DO NOTHING
            """,
            (
                str(uuid.uuid4()),
                event_key,
                _now_iso(),
                incident_id,
                execution_id,
                confirmation_id,
                queue_execution_id,
                event_type,
                sev,
                (actor or "system")[:200],
                (source or "unknown")[:200],
                message,
                _json(details),
            ),
        )
        # rowcount is 1 if inserted, 0 if conflict
        return getattr(cur, "rowcount", 0) == 1

    try:
        return await _with_write(_op)
    except Exception:
        # fail-open: timeline must not crash engine
        return False


async def record_failure(
    *,
    execution_id: str,
    runbook_name: str,
    failure_kind: str,
    final_status: str,
    incident_id: Optional[str] = None,
    target_service: Optional[str] = None,
    target_instance: Optional[str] = None,
    execution_origin: Optional[str] = None,
    retry_of_execution_id: Optional[str] = None,
    attempt_no: Optional[int] = None,
    is_final: bool = True,
    error_message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Insert a runbook failure row (best-effort).
    Idempotent via failure_key (UNIQUE index).

    Requires:
    - runbook_failures has a 'failure_key' TEXT column
    - UNIQUE INDEX uq_runbook_failures_failure_key ON runbook_failures(failure_key)
    """
    if not execution_id or not runbook_name:
        return False

    # For strict “one final per execution” semantics:
    # - make attempt_no=None when is_final=True (so all finals collide)
    fk_attempt = None if is_final else attempt_no
    failure_key = _failure_key(execution_id, failure_kind, is_final, fk_attempt)

    ek = (execution_origin or "").strip()[:64] or None
    rk = (retry_of_execution_id or "").strip()[:64] or None
    fk = (failure_kind or "unknown").strip().lower()[:64]
    fs = (final_status or "error").strip().lower()[:32]
    err = (error_message or "").strip()
    err = err[:2000] if err else None

    async def _op(db: aiosqlite.Connection) -> bool:
        cur = await db.execute(
            """
            INSERT INTO runbook_failures(
              id, created_at,
              incident_id, execution_id, runbook_name,
              target_service, target_instance,
              failure_kind, final_status,
              execution_origin, retry_of_execution_id,
              attempt_no, is_final,
              error_message, error_hash, details_json,
              failure_key
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(failure_key) DO NOTHING
            """,
            (
                str(uuid.uuid4()),
                _now_iso(),
                incident_id,
                execution_id,
                runbook_name,
                target_service,
                target_instance,
                fk,
                fs,
                ek,
                rk,
                int(attempt_no) if attempt_no is not None else None,
                1 if is_final else 0,
                err,
                _hash_error(err),
                _json(details),
                failure_key,
            ),
        )
        return getattr(cur, "rowcount", 0) == 1

    try:
        return await _with_write(_op)
    except Exception:
        # fail-open: failure recording must not crash engine
        return False
