# ---------------------------
# Worker: pending reminder / escalation (logs + audit + events)
# ---------------------------

import asyncio
from datetime import datetime, timezone

import aiosqlite

from ...core.config import settings
from ...core.logging_config import audit_logger
from ...db.connection import DB_PATH
from ...db.event_store import emit_event


async def pending_reminder_loop(*, logger, **_):
    """
    Recordatorios / escalado (sin Telegram por ahora):
    - Emite logs + audit para pendings que superan ciertos umbrales.
    - Evita spam: un mismo pending solo se “recuerda” 1 vez por threshold.
    """
    thresholds = getattr(
        settings, "pending_reminder_thresholds_list", [600, 3600, 21600]
    )
    if not thresholds:
        thresholds = [600, 3600, 21600]

    seen: dict[str, set[int]] = {}

    def _parse_iso(dt_raw: str):
        try:
            dt = datetime.fromisoformat(dt_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    interval = int(getattr(settings, "pending_reminder_loop_interval_seconds", 60))

    while True:
        try:
            now = datetime.now(timezone.utc)

            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("PRAGMA busy_timeout = 5000;")
                await db.execute("PRAGMA foreign_keys = ON;")
                await db.execute("PRAGMA synchronous = NORMAL;")

                cur = await db.execute(
                    """
                        SELECT id, incident_id, runbook_name, target_service, started_at
                        FROM runbook_executions
                        WHERE lower(status) = 'pending'
                        AND started_at IS NOT NULL
                        ORDER BY started_at ASC
                        LIMIT 500
                        """
                )
                rows = await cur.fetchall()
                await cur.close()

            for r in rows:
                started = _parse_iso(r["started_at"])
                if not started:
                    continue

                age_s = int((now - started).total_seconds())
                if age_s < 0:
                    continue

                ex_id = str(r["id"])
                done = seen.get(ex_id)
                if done is None:
                    done = set()
                    seen[ex_id] = done

                for t in thresholds:
                    t = int(t)
                    if t in done:
                        continue
                    if age_s >= t:
                        done.add(t)
                        logger.warning(
                            "pending_confirmation_stale_reminder",
                            execution_id=ex_id,
                            incident_id=r["incident_id"],
                            runbook=r["runbook_name"],
                            target_service=r["target_service"],
                            age_seconds=age_s,
                            threshold_seconds=t,
                        )
                        try:
                            audit_logger.log(
                                event_type="runbook_confirmation",
                                actor="system",
                                resource_type="runbook_execution",
                                resource_id=ex_id,
                                action="pending_reminder",
                                details={
                                    "incident_id": r["incident_id"],
                                    "runbook": r["runbook_name"],
                                    "target_service": r["target_service"],
                                    "age_seconds": age_s,
                                    "threshold_seconds": t,
                                },
                                success=True,
                            )
                            await emit_event(
                                event_key=f"exec:{ex_id}:pending_reminder:{t}",
                                event_type="runbook.confirmation.pending_reminder",
                                actor="system",
                                source="main.pending_reminder_loop",
                                severity="warning",
                                message="Pending confirmation reminder threshold reached",  # noqa: E501
                                incident_id=r["incident_id"],
                                execution_id=ex_id,
                                confirmation_id=ex_id,
                                details={
                                    "runbook": r["runbook_name"],
                                    "target_service": r["target_service"],
                                    "age_seconds": age_s,
                                    "threshold_seconds": t,
                                },
                            )
                        except Exception:
                            pass

            pending_ids = {str(r["id"]) for r in rows}
            for k in list(seen.keys()):
                if k not in pending_ids:
                    seen.pop(k, None)

        except Exception as e:
            logger.warning("pending_reminder_loop_failed", error=str(e))

        await asyncio.sleep(interval)
