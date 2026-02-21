# src/api/telegram_wiring.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from ..core.config import settings
from ..db.connection import DB_PATH
from ..incidents.incident_manager import incident_manager
from ..runbooks.runbook_engine import registry, runbook_engine
from ..telegram.telegram_bot import TelegramConfig, telegram_bot
from .helpers import _parse_iso_utc
from .services.runbook_confirmation import confirm_runbook_execution_impl
from .status_core import get_system_status_core  # ver nota abajo


async def _runbooks_queue_state_snapshot(*, limit: int = 5) -> dict:
    if limit <= 0:
        limit = 5
    limit = min(limit, 50)

    now = datetime.now(timezone.utc)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA busy_timeout = 5000;")
        await db.execute("PRAGMA foreign_keys = ON;")
        await db.execute("PRAGMA synchronous = NORMAL;")

        pending = 0
        running = 0
        cur = await db.execute(
            """
            SELECT lower(status) AS st, count(*) AS n
            FROM runbook_executions
            WHERE lower(status) IN ('pending','running')
            GROUP BY lower(status)
            """
        )
        rows = await cur.fetchall()
        await cur.close()
        for r in rows:
            st = (r["st"] or "").lower()
            n = int(r["n"] or 0)
            if st == "pending":
                pending = n
            elif st == "running":
                running = n

        # oldest pending
        cur = await db.execute(
            """
            SELECT started_at
            FROM runbook_executions
            WHERE lower(status)='pending' AND started_at IS NOT NULL
            ORDER BY started_at ASC
            LIMIT 1
            """
        )
        r1 = await cur.fetchone()
        await cur.close()
        pending_oldest = 0.0
        if r1 and r1["started_at"]:
            dt = _parse_iso_utc(r1["started_at"])
            if dt:
                pending_oldest = max(0.0, (now - dt).total_seconds())

        # oldest running
        cur = await db.execute(
            """
            SELECT started_at
            FROM runbook_executions
            WHERE lower(status)='running' AND started_at IS NOT NULL
            ORDER BY started_at ASC
            LIMIT 1
            """
        )
        r2 = await cur.fetchone()
        await cur.close()
        running_oldest = 0.0
        if r2 and r2["started_at"]:
            dt = _parse_iso_utc(r2["started_at"])
            if dt:
                running_oldest = max(0.0, (now - dt).total_seconds())

    return {
        "totals": {"pending": pending, "running": running},
        "oldest_seconds": {"pending": pending_oldest, "running": running_oldest},
        "ts": now.isoformat(),
    }


def _parse_kv_params(params: dict) -> tuple[Optional[str], Optional[str], dict]:
    p = dict(params or {})
    target_service = p.pop("service", None) or p.pop("target_service", None)
    target_instance = p.pop("instance", None) or p.pop("target_instance", None)
    incident_id = p.pop("incident_id", None)
    return (
        target_service,
        target_instance,
        {"incident_id": incident_id, "parameters": p},
    )


async def start_telegram(logger) -> None:
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        logger.warning(
            "telegram_enabled_but_missing_config",
            has_token=bool(settings.telegram_bot_token),
            has_chat_id=bool(settings.telegram_chat_id),
        )
        return

    telegram_bot.set_logger(logger)
    telegram_bot.configure(
        TelegramConfig(
            enabled=True,
            token=settings.telegram_bot_token,
            chat_id=str(settings.telegram_chat_id),
            poll_interval_seconds=float(
                getattr(settings, "telegram_poll_interval_seconds", 1.0)
            ),
            request_timeout_seconds=35.0,
        )
    )

    # Callbacks (telegram-safe)
    async def _tg_status():
        base = await get_system_status_core()
        qs = await _runbooks_queue_state_snapshot(limit=5)
        return {
            "app": settings.app_name,
            "env": settings.app_env,
            "status": base["status"],
            "active_incidents": base["active_incidents"],
            "runbooks_pending": qs["totals"]["pending"],
            "runbooks_running": qs["totals"]["running"],
            "oldest_pending_s": int(qs["oldest_seconds"]["pending"]),
            "oldest_running_s": int(qs["oldest_seconds"]["running"]),
        }

    async def _tg_incidents():
        incidents = await incident_manager.get_active_incidents()
        if not incidents:
            return []

        inc_ids = [i.id for i in incidents if getattr(i, "id", None)]
        pending_by_inc: dict[str, list[dict]] = {iid: [] for iid in inc_ids}
        now = datetime.now(timezone.utc)

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.execute("PRAGMA synchronous = NORMAL;")

            qmarks = ",".join(["?"] * len(inc_ids))
            cur = await db.execute(
                f"""
                SELECT id, incident_id, runbook_name, started_at
                FROM runbook_executions
                WHERE lower(status)='pending'
                  AND incident_id IN ({qmarks})
                ORDER BY started_at ASC
                """,
                tuple(inc_ids),
            )
            rows = await cur.fetchall()
            await cur.close()

        for r in rows:
            rb = r["runbook_name"]
            cfg = registry.get(rb) if rb else None
            if not (cfg and runbook_engine.requires_confirmation(cfg)):
                continue
            started = _parse_iso_utc(r["started_at"])
            age = int((now - started).total_seconds()) if started else 0
            if age < 0:
                age = 0
            iid = r["incident_id"]
            if iid in pending_by_inc:
                pending_by_inc[iid].append({"id": r["id"], "age_seconds": age})

        out = []
        for i in incidents:
            out.append(
                {
                    "id": i.id,
                    "severity": getattr(i.severity, "value", i.severity),
                    "title": i.title,
                    "status": getattr(i.status, "value", i.status),
                    "service": i.service,
                    "instance": i.instance,
                    "pending_confirmations": pending_by_inc.get(i.id, []),
                }
            )
        return out

    async def _tg_pending():
        now = datetime.now(timezone.utc)
        rows = await runbook_engine.list_pending_confirmations(limit=200)
        items: list[dict] = []

        for r in rows or []:
            execution_id = r.get("execution_id")
            rb = r.get("runbook")
            if not execution_id or not rb:
                continue

            cfg = registry.get(rb)
            if not (cfg and runbook_engine.requires_confirmation(cfg)):
                continue

            started_raw = r.get("started_at")
            started = _parse_iso_utc(started_raw)
            age_s = int((now - started).total_seconds()) if started else 0
            if age_s < 0:
                age_s = 0

            items.append(
                {
                    "confirmation_id": execution_id,
                    "pending_execution_id": execution_id,
                    "incident_id": r.get("incident_id"),
                    "runbook_name": rb,
                    "target_service": r.get("target_service"),
                    "target_instance": r.get("target_instance"),
                    "triggered_by": r.get("triggered_by") or "system",
                    "started_at": started_raw,
                    "age_seconds": age_s,
                }
            )

        items.sort(
            key=lambda x: (x.get("started_at") is None, -(x.get("age_seconds") or 0))
        )
        return items[:50]

    async def _tg_history():
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.execute("PRAGMA synchronous = NORMAL;")
            cur = await db.execute(
                """
                SELECT id, incident_id, runbook_name, status,
                       target_service, target_instance,
                       started_at, completed_at, duration_seconds,
                       triggered_by, error
                FROM runbook_executions
                ORDER BY COALESCE(completed_at, started_at) DESC
                LIMIT 20
                """
            )
            rows = await cur.fetchall()
            await cur.close()
        return [dict(r) for r in rows]

    async def _tg_runbook_execute(*, runbook_name: str, params: dict):
        target_service, target_instance, rest = _parse_kv_params(params or {})
        incident_id = (
            rest.get("incident_id")
            or params.get("incident_id")
            or params.get("incident")
            or params.get("inc")
        )
        rb_params = rest.get("parameters") or {}

        if not incident_id:
            return {
                "accepted": False,
                "error": "Falta incident_id. Ej: /runbook health_check incident_id=<id> service=<svc>",
            }

        ex = await runbook_engine.execute_async(
            runbook_name=runbook_name,
            incident_id=incident_id,
            target_service=target_service,
            target_instance=target_instance,
            parameters=rb_params,
            triggered_by="telegram",
            skip_validation=False,
        )
        return {
            "accepted": True,
            "execution_id": ex.id,
            "runbook": ex.runbook_name,
            "status": str(getattr(ex.status, "value", ex.status)),
            "target_service": ex.target_service,
            "target_instance": getattr(ex, "target_instance", None),
        }

    async def _tg_confirm(*, confirmation_id: str, chat_id: str):
        ex = await runbook_engine.get_execution(confirmation_id)
        if not ex or not ex.incident_id:
            return {
                "ok": False,
                "error": "pending execution not found or missing incident_id",
            }

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.execute("PRAGMA synchronous = NORMAL;")

            return await confirm_runbook_execution_impl(
                request=None,
                incident_id=ex.incident_id,
                execution_id=confirmation_id,
                payload={"parameters": {}},
                actor_id="telegram",
                db=db,
                telegram_chat_id=chat_id,
            )

    async def _tg_skip(*, confirmation_id: str):
        try:
            ex = await runbook_engine.get_execution(confirmation_id)
            out = await runbook_engine.cancel_execution(
                confirmation_id, actor_id="telegram"
            )
            return {
                "ok": True,
                "cancelled": True,
                "execution_id": confirmation_id,
                "incident_id": getattr(ex, "incident_id", None),
                **out,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    telegram_bot.set_callbacks(
        get_status=_tg_status,
        list_incidents=_tg_incidents,
        runbook_history=_tg_history,
        runbook_execute=_tg_runbook_execute,
        pending=_tg_pending,
        confirm=_tg_confirm,
        skip=_tg_skip,
    )

    await telegram_bot.initialize()
    await telegram_bot.start()
    logger.info("telegram_started_on_startup")


async def stop_telegram(logger) -> None:
    try:
        await telegram_bot.stop()
    except Exception as e:
        logger.warning("telegram_failed_to_stop", error=str(e))
