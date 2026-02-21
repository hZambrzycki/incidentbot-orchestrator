# ---------------------------
# Prometheus metrics
# ---------------------------

from fastapi import APIRouter
from fastapi.responses import Response

from ...db.connection import DB_PATH
from ...observability.metrics_collector import metrics_collector

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
async def metrics():
    # fuerza refresh justo antes de exponer métricas
    await metrics_collector.refresh_runbook_queue_metrics_from_db(DB_PATH)
    return Response(
        content=metrics_collector.get_metrics(),
        media_type=metrics_collector.content_type,
    )
