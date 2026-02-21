# ---------------------------
# Webhooks: Alertmanager
# ---------------------------

import time

from fastapi import APIRouter, BackgroundTasks

from ...core.logging_config import get_logger, setup_logging
from ...core.models import AlertmanagerWebhook, APIResponse, Severity
from ...incidents.incident_manager import incident_manager
from ...observability.metrics_collector import metrics_collector
from ..services.incident_processor import process_incident_async

setup_logging()
logger = get_logger("main")

router = APIRouter(tags=["webhooks"])


@router.post("/webhook/alertmanager")
async def alertmanager_webhook(
    webhook: AlertmanagerWebhook,
    background_tasks: BackgroundTasks,
):
    start_time = time.time()

    logger.info(
        "alertmanager_webhook_received",
        status=webhook.status,
        alert_count=len(webhook.alerts),
        group_key=webhook.groupKey,
    )

    # Minimal metrics: record alert count by severity if present
    for alert in webhook.alerts:
        sev_label = (alert.labels.get("severity") or "").lower()
        if not sev_label:
            # fallback si no viene en labels
            sev_label = (
                "critical"
                if alert.severity == Severity.CRITICAL
                else "warning"
                if alert.severity == Severity.WARNING
                else "info"
            )

        metrics_collector.record_alert_received(
            alertname=alert.alertname,
            severity=sev_label,
        )

    # Minimal processing: call manager (stub) and enqueue background work
    affected_incidents = await incident_manager.process_alertmanager_webhook(webhook)

    for incident, result in affected_incidents:
        # alimenta ALERTS_PROCESSED
        metrics_collector.record_alert_processed(result)

        # “Procesa” si es nuevo/reabierto O si hay runbook sugerido y aún no se procesó
        has_runbook = bool((incident.annotations or {}).get("runbook"))
        never_processed = incident.last_processed_at is None

        should_process = (result in ("new_incident", "reopened")) or (
            has_runbook and never_processed
        )

        if result in ("new_incident", "reopened"):
            metrics_collector.record_incident_created(incident.severity.value)

        if should_process:
            logger.info("scheduled_process_incident_async", incident_id=incident.id)
            background_tasks.add_task(process_incident_async, incident)

        if result == "resolved":
            metrics_collector.record_incident_resolved(
                incident.severity.value,
                incident.duration_seconds,
            )

        logger.info(
            "alertmanager_webhook_result",
            incident_id=incident.id,
            result=result,
            has_runbook=has_runbook,
            never_processed=never_processed,
            should_process=should_process,
            last_processed_at=(
                incident.last_processed_at.isoformat()
                if incident.last_processed_at
                else None
            ),
        )

    metrics_collector.record_webhook_request(
        "alertmanager",
        "success",
        time.time() - start_time,
    )
    logger.info(
        "alertmanager_webhook_done",
        affected=len(affected_incidents),
        duration_ms=int((time.time() - start_time) * 1000),
    )
    return APIResponse(
        success=True,
        message=f"Processed {len(affected_incidents)} incidents",
        data={
            "incidents": [
                {"id": inc.id, "result": res} for inc, res in affected_incidents
            ]
        },
    )
