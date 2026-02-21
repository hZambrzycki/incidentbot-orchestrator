from datetime import datetime, timedelta, timezone
from typing import Optional

import aiosqlite

from ...core.config import settings
from ...core.logging_config import get_logger, setup_logging
from ...core.models import Incident, IncidentStatus
from ...db.connection import DB_PATH
from ...incidents.incident_manager import incident_manager
from ...incidents.log_analyzer import log_analyzer
from ...observability.metrics_collector import metrics_collector
from ...runbooks.runbook_engine import runbook_engine
from ...telegram.telegram_bot import telegram_bot
from ..helpers import normalize_execution_status

PROCESS_COOLDOWN_SECONDS = 60

# Logging
setup_logging()
logger = get_logger("main")

# ============================================================
# INCIDENT PROCESSING ORCHESTRATOR
# ============================================================


async def process_incident_async(incident: Incident):
    """Process an incident asynchronously (diagnosis + runbook)."""
    incident = await incident_manager.get_incident(incident.id)
    if not incident:
        return

    logger.info(
        "incident_processing_check",
        incident_id=incident.id,
        last_processed_at=str(incident.last_processed_at),
    )

    if incident.status == IncidentStatus.RESOLVED:
        return

    now = datetime.now(timezone.utc)

    # cooldown
    if incident.last_processed_at and (now - incident.last_processed_at) < timedelta(
        seconds=PROCESS_COOLDOWN_SECONDS
    ):
        logger.info("incident_processing_skipped_cooldown", incident_id=incident.id)
        return

    await incident_manager.set_last_processed_at(incident.id, now)

    try:
        # -----------------------
        # 1) Diagnosis (con fallback)
        # -----------------------
        diagnosis = None
        try:
            diagnosis = await log_analyzer.diagnose_incident(incident)
            summary = (
                getattr(diagnosis, "summary", "Diagnosis completed")
                or "Diagnosis completed"
            )
            details = getattr(diagnosis, "details", None) or []

            MAX_LINES = 25
            MAX_LINE_LEN = 200
            safe_details = [str(d)[:MAX_LINE_LEN] for d in details[:MAX_LINES]]

            full_text = summary
            if safe_details:
                full_text += "\n" + "\n".join(safe_details)

            await incident_manager.set_incident_diagnosis(incident.id, full_text)

            logger.info(
                "incident_diagnosed",
                incident_id=incident.id,
                summary=summary,
                detail_lines=len(safe_details),
                suggested_actions=getattr(diagnosis, "suggested_actions", None),
            )
        except Exception as e:
            fallback_summary = f"No diagnosis available yet: {str(e)}"
            await incident_manager.set_incident_diagnosis(incident.id, fallback_summary)
            logger.warning(
                "incident_diagnosis_skipped",
                incident_id=incident.id,
                error=str(e),
            )

        # -----------------------
        # 2) Telegram
        # -----------------------
        if getattr(settings, "telegram_enabled", False):
            try:
                await telegram_bot.notify_incident(incident)
                metrics_collector.record_notification_sent("telegram", "incident", True)
            except Exception as e:
                metrics_collector.record_notification_sent(
                    "telegram", "incident", False
                )
                logger.warning(
                    "telegram_notify_incident_failed",
                    incident_id=incident.id,
                    error=str(e),
                )

        # -----------------------
        # 3) Runbooks
        # -----------------------

        episode_start = None
        if incident.episodes:
            active_eps = [ep for ep in incident.episodes if ep.resolved_at is None]
            if active_eps:
                episode_start = max(ep.started_at for ep in active_eps)
            else:
                episode_start = max(ep.started_at for ep in incident.episodes)

        def _ran_in_current_episode(e) -> bool:
            if not episode_start:
                return True
            return bool(e.started_at and e.started_at >= episode_start)

        async def _already_ran_from_db(
            incident_id: str, episode_start: Optional[datetime]
        ) -> set[str]:
            params = [incident_id]
            episode_sql = ""
            if episode_start:
                episode_sql = "AND started_at >= ?"
                params.append(episode_start.isoformat())

            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("PRAGMA busy_timeout = 5000;")
                await db.execute("PRAGMA foreign_keys = ON;")
                await db.execute("PRAGMA synchronous = NORMAL;")
                cur = await db.execute(
                    f"""
                    SELECT DISTINCT runbook_name
                    FROM runbook_executions
                    WHERE incident_id = ?
                      AND lower(status) NOT IN ('pending','running')
                      {episode_sql}
                    """,
                    tuple(params),
                )
                rows = await cur.fetchall()
                await cur.close()
            return {r["runbook_name"] for r in rows if r["runbook_name"]}

        already_ran = await _already_ran_from_db(incident.id, episode_start)

        runbooks_to_try = [
            rb for rb in pick_runbooks_for_incident(incident) if rb not in already_ran
        ]

        if diagnosis and getattr(diagnosis, "suggested_actions", None):
            for rb in diagnosis.suggested_actions:
                if rb not in runbooks_to_try and rb not in already_ran:
                    runbooks_to_try.append(rb)

        logger.info(
            "runbooks_selected_for_incident",
            incident_id=incident.id,
            runbooks=runbooks_to_try,
        )

        if not runbooks_to_try:
            return

        filtered_runbooks: list[str] = []
        for rb in runbooks_to_try:
            svc = (incident.service or "").strip().lower()
            if rb == "restart_service" and (not svc or svc == "unknown"):
                logger.info(
                    "skipping_restart_no_service",
                    incident_id=incident.id,
                    reason="incident.service is None",
                )
                continue
            filtered_runbooks.append(rb)

        if not filtered_runbooks:
            return

        executions = await runbook_engine.execute_for_incident(
            incident, filtered_runbooks
        )
        for execution in executions:
            st, is_ok = normalize_execution_status(execution)
            if st in ("pending", "running"):
                continue
            if getattr(settings, "telegram_enabled", False):
                try:
                    await telegram_bot.notify_runbook_result(
                        runbook_name=execution.runbook_name,
                        success=is_ok,
                        message=execution.output or execution.error or "",
                        incident_id=incident.id,
                    )
                except Exception as e:
                    logger.warning(
                        "telegram_notify_runbook_failed",
                        incident_id=incident.id,
                        runbook=execution.runbook_name,
                        error=str(e),
                    )

    except Exception as e:
        logger.exception(
            "incident_processing_failed", incident_id=incident.id, error=str(e)
        )


# ============================================================
# RUNBOOK SELECTION POLICY
# ============================================================
def pick_runbooks_for_incident(incident: Incident) -> list[str]:
    # 1) override manual desde annotations (Alertmanager)
    rb = (incident.annotations or {}).get("runbook")
    if rb:
        return [rb]

    # 2) policy por error_type
    policy = {
        "disk_space_low": ["cleanup_disk", "health_check"],
        "high_cpu": ["restart_service", "health_check"],
        "high_memory": ["restart_service", "health_check"],
    }

    if incident.error_type and incident.error_type in policy:
        return policy[incident.error_type]

    # 3) default
    return ["health_check"]
