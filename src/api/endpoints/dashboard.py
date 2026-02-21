# ---------------------------
# Dashboard (aggregations)
# ---------------------------

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder

from ...core.security import require_admin
from ...db.connection import get_db
from ...incidents.incident_manager import incident_manager
from ..endpoints.runbooks import list_pending_runbooks, runbooks_queue_state
from ..status_core import get_system_status_core

router = APIRouter(tags=["dashboard"])


@router.get("/api/dashboard/summary")
async def dashboard_summary(
    limit_samples: int = 10,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    # 1) status base (RAM manager + métricas)
    base = await get_system_status_core()

    # 2) incidentes activos
    active_incidents = await incident_manager.get_active_incidents()
    by_sev = {"info": 0, "warning": 0, "critical": 0}
    for i in active_incidents:
        sev = _sev_key(i.severity)
        if sev in by_sev:
            by_sev[sev] += 1

    # 3) queue state (DB source of truth) — reutiliza tu endpoint interno
    qs = await runbooks_queue_state(
        limit=min(limit_samples, 50), include_samples=True, actor_id=actor_id, db=db
    )

    # 4) pendings confirmables (para panel “human-in-the-loop”)
    pend = await list_pending_runbooks(
        limit=min(limit_samples, 50),
        incident_id=None,
        runbook=None,
        min_age_seconds=0,
        include_resolved=False,
        only_confirmable=True,
        actor_id=actor_id,
        db=db,
    )
    top = await dashboard_failures_top(hours=24, limit=5, actor_id=actor_id, db=db)
    recent = await dashboard_events_recent(
        limit=50, incident_id=None, execution_id=None, actor_id=actor_id, db=db
    )
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "system": base,
        "incidents": {
            "active_total": len(active_incidents),
            "by_severity": by_sev,
            "items": [
                {
                    "id": i.id,
                    "title": i.title,
                    "severity": getattr(i.severity, "value", i.severity),
                    "status": getattr(i.status, "value", i.status),
                    "service": i.service,
                    "instance": i.instance,
                    "error_type": i.error_type,
                    "created_at": i.created_at.isoformat() if i.created_at else None,
                    "updated_at": i.updated_at.isoformat() if i.updated_at else None,
                }
                for i in active_incidents[:limit_samples]
            ],
        },
        "queue": qs,
        "pending_confirmations": pend,
        "failures_top": top,
        "events": {"recent": recent["events"]},
    }


@router.get("/api/dashboard/failures/top")
async def dashboard_failures_top(
    hours: int = 24,
    limit: int = 10,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if hours <= 0:
        hours = 24
    hours = min(hours, 24 * 30)

    if limit <= 0:
        limit = 10
    limit = min(limit, 50)

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # 1) Top error_hash (agrupación real)
    cur = await db.execute(
        """
        SELECT
          COALESCE(error_hash,'no_hash') AS k,
          COUNT(*) AS n,
          MAX(created_at) AS last_seen,
          MIN(created_at) AS first_seen
        FROM runbook_failures
        WHERE created_at >= ?
        GROUP BY COALESCE(error_hash,'no_hash')
        ORDER BY n DESC
        LIMIT ?
        """,
        (since, limit),
    )
    by_hash = [dict(r) for r in await cur.fetchall()]
    await cur.close()

    # 2) Top runbooks
    cur = await db.execute(
        """
        SELECT
          runbook_name AS k,
          COUNT(*) AS n,
          MAX(created_at) AS last_seen
        FROM runbook_failures
        WHERE created_at >= ?
        GROUP BY runbook_name
        ORDER BY n DESC
        LIMIT ?
        """,
        (since, limit),
    )
    by_runbook = [dict(r) for r in await cur.fetchall()]
    await cur.close()

    # 3) Top failure_kind
    cur = await db.execute(
        """
        SELECT
          failure_kind AS k,
          COUNT(*) AS n,
          MAX(created_at) AS last_seen
        FROM runbook_failures
        WHERE created_at >= ?
        GROUP BY failure_kind
        ORDER BY n DESC
        LIMIT ?
        """,
        (since, limit),
    )
    by_kind = [dict(r) for r in await cur.fetchall()]
    await cur.close()

    return {
        "window_hours": hours,
        "since": since,
        "top_error_hash": by_hash,
        "top_runbooks": by_runbook,
        "top_failure_kind": by_kind,
    }


@router.get("/api/dashboard/events/recent")
async def dashboard_events_recent(
    limit: int = 100,
    incident_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if limit <= 0:
        limit = 100
    limit = min(limit, 500)

    where = []
    params: list[Any] = []

    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)

    if execution_id:
        where.append("execution_id = ?")
        params.append(execution_id)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    cur = await db.execute(
        f"""
        SELECT
          id, event_key, created_at,
          incident_id, execution_id, confirmation_id, queue_execution_id,
          event_type, severity, actor, source, message, details_json
        FROM incident_events
        {where_sql}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items = []
    for r in rows:
        d = dict(r)
        if d.get("details_json"):
            try:
                d["details"] = json.loads(d["details_json"])
            except Exception:
                d["details"] = {"raw": d["details_json"]}
        else:
            d["details"] = None
        d.pop("details_json", None)
        items.append(d)

    return {"total": len(items), "events": items}


@router.get("/api/dashboard/executions")
async def dashboard_executions(
    limit: int = 60,
    incident_id: Optional[str] = None,
    runbook_name: Optional[str] = None,
    target_service: Optional[str] = None,
    status: Optional[str] = None,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if limit <= 0:
        limit = 60
    limit = min(limit, 500)

    where = []
    params: list[Any] = []

    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)

    if runbook_name:
        where.append("runbook_name = ?")
        params.append(runbook_name)

    if target_service:
        where.append("target_service = ?")
        params.append(target_service)

    if status:
        where.append("lower(status) = ?")
        params.append(status.strip().lower())

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    cur = await db.execute(
        f"""
        SELECT
          id, incident_id, runbook_name, status, triggered_by,
          target_service, target_instance,
          parameters_json, output, error,
          started_at, completed_at, duration_seconds,
          execution_origin, retry_of_execution_id
        FROM runbook_executions
        {where_sql}
        ORDER BY COALESCE(started_at, completed_at) DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        # parse parameters_json (small enough for UI)
        params_obj: Dict[str, Any] = {}
        if d.get("parameters_json"):
            try:
                params_obj = json.loads(d["parameters_json"])
            except Exception:
                params_obj = {}
        d["parameters"] = jsonable_encoder(params_obj)
        d.pop("parameters_json", None)
        items.append(d)

    return {"total": len(items), "items": items}


@router.get("/api/dashboard/executions/{execution_id}")
async def dashboard_execution_forensics(
    execution_id: str,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    # execution (source of truth)
    cur = await db.execute(
        """
        SELECT
          id, incident_id, runbook_name, status, triggered_by,
          target_service, target_instance,
          parameters_json, output, error,
          started_at, completed_at, duration_seconds,
          execution_origin, retry_of_execution_id
        FROM runbook_executions
        WHERE id = ?
        LIMIT 1
        """,
        (execution_id,),
    )
    row = await cur.fetchone()
    await cur.close()
    if not row:
        raise HTTPException(status_code=404, detail="Execution not found")

    ex = dict(row)
    params_obj: Dict[str, Any] = {}
    if ex.get("parameters_json"):
        try:
            params_obj = json.loads(ex["parameters_json"])
        except Exception:
            params_obj = {}
    ex["parameters"] = jsonable_encoder(params_obj)
    ex.pop("parameters_json", None)

    # queue item (control-plane queue)
    cur = await db.execute(
        """
        SELECT
          execution_id, runbook_name, incident_id,
          target_service, target_instance,
          status, attempts, last_heartbeat,
          available_at, lease_owner, lease_expires_at,
          created_at, updated_at
        FROM runbook_queue
        WHERE execution_id = ?
        LIMIT 1
        """,
        (execution_id,),
    )
    qrow = await cur.fetchone()
    await cur.close()
    queue_item = dict(qrow) if qrow else None

    # failures for this execution
    cur = await db.execute(
        """
        SELECT
          id, created_at, incident_id, execution_id, runbook_name,
          target_service, target_instance,
          failure_kind, final_status, attempt_no, is_final,
          error_message, error_hash
        FROM runbook_failures
        WHERE execution_id = ?
        ORDER BY created_at DESC
        LIMIT 50
        """,
        (execution_id,),
    )
    failures = [dict(r) for r in await cur.fetchall()]
    await cur.close()

    # events for this execution (reuse your logic; keep small)
    cur = await db.execute(
        """
        SELECT
          id, created_at, event_type, severity, actor, source, message
        FROM incident_events
        WHERE execution_id = ?
        ORDER BY created_at ASC, id ASC
        LIMIT 300
        """,
        (execution_id,),
    )
    events = [dict(r) for r in await cur.fetchall()]
    await cur.close()

    return {
        "execution": ex,
        "queue_item": queue_item,
        "failures": failures,
        "events": events,
    }


def _sev_key(x) -> str:
    v = getattr(x, "value", x)  # enum -> value, si no -> x

    # Si viene como int, lo mapeas a tu taxonomía
    if isinstance(v, int):
        # AJUSTA si tu escala es distinta
        # Ejemplo típico: 1=info, 2=warning, 3=critical
        return {1: "info", 2: "warning", 3: "critical"}.get(v, "info")

    # Si viene como string u otra cosa, lo normalizas
    s = str(v).strip().lower()
    # Si te llegan cosas tipo "warn" o "crit"
    s = {"warn": "warning", "crit": "critical"}.get(s, s)
    return s
