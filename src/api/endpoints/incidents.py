# ---------------------------
# Incidents
# ---------------------------

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder

from ...core.logging_config import audit_logger
from ...core.models import IncidentListResponse, IncidentStatus, Severity
from ...core.security import require_admin
from ...db.connection import get_db
from ...incidents.incident_manager import incident_manager

router = APIRouter(tags=["incidents"])


@router.get("/api/incidents")
async def list_incidents(
    active_only: bool = True,
    severity: Optional[str] = None,
    limit: int = 50,
):
    if active_only:
        incidents = await incident_manager.get_active_incidents()
    else:
        incidents = await incident_manager.get_recent_incidents(hours=24)

    if severity:
        s = severity.lower()
        mapping = {
            "info": Severity.INFO,
            "warning": Severity.WARNING,
            "critical": Severity.CRITICAL,
        }
        if s in mapping:
            sev = mapping[s]
            incidents = [i for i in incidents if i.severity == sev]
        else:
            try:
                sev = Severity(int(severity))
                incidents = [i for i in incidents if i.severity == sev]
            except Exception:
                pass

    return IncidentListResponse(
        total=len(incidents),
        active=len([i for i in incidents if i.is_active]),
        incidents=incidents[:limit],
    )


@router.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = await incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/api/incidents/{incident_id}/runbooks")
async def list_incident_runbooks(
    incident_id: str,
    limit: int = 100,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    """
    Historial de ejecuciones por incidente (source of truth = runbook_executions).
    Útil para UI / debugging / timeline.
    """
    if limit <= 0:
        limit = 100
    limit = min(limit, 500)

    # valida que el incidente exista en DB (no dependemos de RAM)
    cur = await db.execute(
        "SELECT 1 FROM incidents WHERE id = ? LIMIT 1", (incident_id,)
    )
    row = await cur.fetchone()
    await cur.close()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    cur = await db.execute(
        """
        SELECT
          id, incident_id, runbook_name, status, triggered_by,
          target_service, target_instance, parameters_json,
          output, error, started_at, completed_at, duration_seconds,
          confirmed_execution_id, confirmed_by, confirmed_at
        FROM runbook_executions
        WHERE incident_id = ?
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (incident_id, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items = []
    for r in rows:
        d = dict(r)
        # parse parameters_json
        params_obj: Dict[str, Any] = {}
        if d.get("parameters_json"):
            try:
                params_obj = json.loads(d["parameters_json"])
            except Exception:
                params_obj = {}
        d["parameters"] = jsonable_encoder(params_obj)
        d.pop("parameters_json", None)
        items.append(d)

    return {
        "incident_id": incident_id,
        "total": len(items),
        "executions": items,
        "limit": limit,
    }


@router.post("/api/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    status: str,
    request: Request,
    actor_id: str = Depends(require_admin),
):
    try:
        new_status = IncidentStatus(status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    incident = await incident_manager.update_incident_status(
        incident_id=incident_id,
        new_status=new_status,
        actor="api",
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    audit_logger.api_request(
        endpoint=f"/api/incidents/{incident_id}/status",
        method="POST",
        ip_address=request.client.host,
        success=True,
        actor=actor_id,
    )

    return incident
