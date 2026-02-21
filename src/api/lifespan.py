# src/api/lifespan.py
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ..core.config import settings
from ..core.logging_config import get_logger, setup_logging  # si lo usas
from ..db import init_db
from ..db.connection import DB_PATH
from ..incidents.incident_manager import incident_manager
from ..observability.metrics_collector import metrics_collector
from ..runbooks.runbook_engine import runbook_engine
from .telegram_wiring import start_telegram, stop_telegram
from .workers.audit_warm import audit_snapshot_warm_loop
from .workers.auto_cancel import auto_cancel_loop
from .workers.pending_reminder import pending_reminder_loop
from .workers.refresh_status import refresh_active_incidents_loop

setup_logging()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP ---
    await init_db()
    await incident_manager.load_from_db()

    # Rehidratar engine desde DB
    try:
        await runbook_engine.load_active_from_db()
        logger.info("runbook_engine_rehydrated_on_startup")
        try:
            rec = await runbook_engine.reconcile_inflight_confirmations_from_db()
            logger.info("runbook_confirmations_reconciled_on_startup", **rec)
        except Exception as e:
            logger.warning("runbook_confirmations_reconcile_failed", error=str(e))
    except Exception as e:
        logger.warning("runbook_engine_rehydrate_failed", error=str(e))

    try:
        await runbook_engine.resume_durable_queue_from_db()
        logger.info("runbook_engine_queue_resumed_on_startup")
    except Exception as e:
        logger.warning("runbook_engine_queue_resume_failed", error=str(e))

    try:
        runbook_engine.start_queue_worker()
        runbook_engine.start_stale_pending_scheduler()
        logger.info("runbook_queue_worker_started")
    except Exception as e:
        logger.warning("runbook_queue_worker_failed_to_start", error=str(e))

    metrics_collector.update_system_status("healthy")
    logger.info("metrics_initialized_on_startup")

    # Telegram
    if getattr(settings, "telegram_enabled", False):
        await start_telegram(logger)

    # Metrics loops
    task_queue_metrics = None
    try:
        task_queue_metrics = metrics_collector.start_runbook_queue_metrics_loop(
            DB_PATH, interval_seconds=5
        )
        logger.info("runbook_queue_metrics_loop_started")
    except Exception as e:
        logger.warning("runbook_queue_metrics_loop_failed_to_start", error=str(e))

    try:
        metrics_collector.start_container_mapper_loop(interval_seconds=30)
        logger.info("container_mapper_started")
    except Exception as e:
        logger.warning("container_mapper_failed_to_start", error=str(e))

    # Workers
    task_status = asyncio.create_task(
        refresh_active_incidents_loop(), name="refresh_status"
    )
    task_audit = asyncio.create_task(
        audit_snapshot_warm_loop(logger=logger), name="audit_warm"
    )
    task_autocancel = asyncio.create_task(
        auto_cancel_loop(logger=logger), name="auto_cancel"
    )
    task_reminders = asyncio.create_task(
        pending_reminder_loop(logger=logger), name="pending_reminder"
    )

    yield

    # --- SHUTDOWN ---
    for t in (task_status, task_audit, task_autocancel, task_reminders):
        t.cancel()

    if task_queue_metrics:
        task_queue_metrics.cancel()

    await asyncio.gather(
        task_status, task_audit, task_autocancel, task_reminders, return_exceptions=True
    )
    if task_queue_metrics:
        await asyncio.gather(task_queue_metrics, return_exceptions=True)

    try:
        await runbook_engine.stop_queue_worker()
        await runbook_engine.stop_stale_pending_scheduler()
        logger.info("runbook_queue_worker_stopped")
    except Exception as e:
        logger.warning("runbook_queue_worker_failed_to_stop", error=str(e))

    if getattr(settings, "telegram_enabled", False):
        await stop_telegram(logger)

    logger.info("shutting_down_incident_bot")
