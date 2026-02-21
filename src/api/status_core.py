from __future__ import annotations

from ..core.config import settings
from ..core.models import Severity
from ..incidents.incident_manager import incident_manager
from ..observability.metrics_collector import metrics_collector


async def get_system_status_core() -> dict:
    incidents = await incident_manager.get_active_incidents()
    by_sev = {"info": 0, "warning": 0, "critical": 0}
    for i in incidents:
        if i.severity == Severity.CRITICAL:
            by_sev["critical"] += 1
        elif i.severity == Severity.WARNING:
            by_sev["warning"] += 1
        else:
            by_sev["info"] += 1

    metrics_collector.set_active_incidents("info", by_sev["info"])
    metrics_collector.set_active_incidents("warning", by_sev["warning"])
    metrics_collector.set_active_incidents("critical", by_sev["critical"])

    critical_count = by_sev["critical"]
    warning_count = by_sev["warning"]

    status = (
        "critical"
        if critical_count > 0
        else "degraded"
        if warning_count > 0
        else "healthy"
    )
    metrics_collector.update_system_status(status)

    return {
        "status": status,
        "active_incidents": len(incidents),
        "app_name": settings.app_name,
        "env": settings.app_env,
    }
