# ---------------------------
# Runbooks: list/execute/history/cancel
# + Pending/Confirmations/Confirm endpoints
# + Queue state & events/timeline
# ---------------------------

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request
from fastapi.encoders import jsonable_encoder

from ...core.config import settings
from ...core.logging_config import audit_logger
from ...core.models import Incident, IncidentStatus
from ...core.security import rate_limit, require_admin
from ...db.connection import DB_WRITE_LOCK, get_db
from ...db.event_store import emit_event, record_failure
from ...incidents.incident_manager import incident_manager
from ...observability.metrics_collector import (
    PENDING_STALE_THRESHOLDS_SECONDS,
    metrics_collector,
)
from ...runbooks.registry import registry
from ...runbooks.runbook_engine import runbook_engine
from ..helpers import ConfirmRunbookRequest
from ..services.runbook_confirmation import confirm_runbook_execution_impl

router = APIRouter(tags=["runbooks"])


@router.get("/api/runbooks")
async def list_runbooks():
    """List available runbooks (allowlist)."""
    return {"runbooks": runbook_engine.list_available_runbooks()}


@router.post("/api/runbooks/{runbook_name}")
async def execute_runbook(
    runbook_name: str,
    request: Request,
    service: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = Body(default=None),
    actor_id: str = Depends(require_admin),
):
    # Rate limit
    await rate_limit(
        request=request,
        bucket="runbook_execute",
        max_hits=settings.rate_limit_runbook_max,
        window_seconds=settings.rate_limit_window_seconds,
    )
    """
    Execute a runbook manually.

    - service -> target_service en engine
    - parameters -> dict de parámetros del runbook
    """
    start = time.time()
    payload = payload or {}
    parameters = payload.get("parameters", {}) or {}
    # permitir que el body también pase "service"
    if not service and "service" in payload:
        service = payload["service"]
    # aceptar también "target_service" (compat con tus tests)
    if not service and "target_service" in payload:
        service = payload["target_service"]
    skip_validation = bool(payload.get("skip_validation", False))
    incident_id = payload.get("incident_id")
    execution = await runbook_engine.execute_async(
        runbook_name=runbook_name,
        incident_id=incident_id,
        target_service=service,
        parameters=parameters,
        triggered_by="api",
        skip_validation=skip_validation,
    )

    audit_logger.api_request(
        endpoint=f"/api/runbooks/{runbook_name}",
        method="POST",
        ip_address=request.client.host if request.client else "unknown",
        actor=actor_id,
        success=True,
    )

    metrics_collector.record_webhook_request(
        "runbook_execute",
        "success",
        time.time() - start,
    )

    return {
        "accepted": True,
        "execution_id": execution.id,
        "runbook": execution.runbook_name,
        "status": (
            execution.status.value
            if hasattr(execution.status, "value")
            else str(execution.status)
        ),
        "target_service": execution.target_service,
        "triggered_by": execution.triggered_by,
        "started_at": (
            execution.started_at.isoformat() if execution.started_at else None
        ),
        "poll_url": f"/api/runbooks/history/{execution.id}",
    }


@router.get("/api/runbooks/history")
async def runbook_history(
    limit: int = 20,
    runbook_name: Optional[str] = None,
    actor_id: str = Depends(require_admin),
):
    """Get recent runbook executions."""
    executions = await runbook_engine.get_recent_executions(
        limit=limit, runbook_name=runbook_name
    )
    return {"total": len(executions), "executions": executions}


@router.get("/api/runbooks/history/{execution_id}")
async def runbook_execution_detail(
    execution_id: str, actor_id: str = Depends(require_admin)
):
    """Get a specific execution by ID."""
    e = await runbook_engine.get_execution(execution_id)
    if not e:
        raise HTTPException(status_code=404, detail="Execution not found")
    return e


@router.post("/api/runbooks/{execution_id}/cancel")
async def cancel_runbook_execution(
    execution_id: str,
    actor_id: str = Depends(require_admin),
):
    """
    Cancela una ejecución:
    - si está RUNNING en memoria: cancela la task asyncio
    - marca ejecución como SKIPPED (cancelled) + runbook_queue como dead
    Idempotente: repetir devuelve ok igualmente.
    """
    return await runbook_engine.cancel_execution(execution_id, actor_id=actor_id)


@router.get("/api/runbooks/stats")
async def runbook_stats(actor_id: str = Depends(require_admin)):
    """Basic runbook execution statistics."""
    return await runbook_engine.get_statistics()


# --------
# Pending
# --------


@router.get("/api/runbooks/pending")
async def list_pending_runbooks(
    limit: int = 50,
    incident_id: Optional[str] = None,
    runbook: Optional[str] = None,
    min_age_seconds: int = 0,
    include_resolved: bool = False,
    only_confirmable: bool = True,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    """
    Lista ejecuciones PENDING (source of truth = tabla runbook_executions).
    - only_confirmable=True => solo las que requieren confirmación (según registry)
    - include_resolved=True => permite incidentes resueltos (y cualquier pending huérfana)
    """
    now = datetime.now(timezone.utc)

    if limit <= 0:
        limit = 50
    limit = min(limit, 500)

    where = ["lower(status) = 'pending'"]
    params: list = []

    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)

    if runbook:
        where.append("runbook_name = ?")
        params.append(runbook)

    where_sql = "WHERE " + " AND ".join(where)

    prelimit = min(limit * 5, 2000)

    cur = await db.execute(
        f"""
        SELECT
          id, incident_id, runbook_name, status, triggered_by,
          target_service, target_instance, parameters_json,
          output, error, started_at, completed_at
        FROM runbook_executions
        {where_sql}
        ORDER BY started_at ASC
        LIMIT ?
        """,
        (*params, prelimit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items: List[Dict[str, Any]] = []
    incident_cache: Dict[str, Optional[Incident]] = {}

    for r in rows:
        d = dict(r)

        started_at_raw = d.get("started_at")
        if not started_at_raw:
            continue

        try:
            started_at = datetime.fromisoformat(started_at_raw)
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        age_seconds = int((now - started_at).total_seconds())
        if age_seconds < min_age_seconds:
            continue

        cfg = registry.get(d["runbook_name"])
        is_confirmable = bool(
            cfg
            and (
                cfg.requires_confirmation
                or (
                    getattr(settings, "runbook_require_confirmation", False)
                    and getattr(cfg, "dangerous", False)
                )
            )
        )

        if only_confirmable and not is_confirmable:
            continue

        inc_obj: Optional[Incident] = None
        inc_id = d.get("incident_id")
        if inc_id:
            if inc_id not in incident_cache:
                incident_cache[inc_id] = await incident_manager.get_incident(inc_id)
            inc_obj = incident_cache[inc_id]

            if (
                inc_obj
                and (not include_resolved)
                and inc_obj.status == IncidentStatus.RESOLVED
            ):
                continue

        params_obj: Dict[str, Any] = {}
        if d.get("parameters_json"):
            try:
                params_obj = json.loads(d["parameters_json"])
            except Exception:
                params_obj = {}

        item = {
            "pending_execution_id": d["id"],
            "runbook_name": d["runbook_name"],
            "status": "pending",
            "confirmable": is_confirmable,
            "dangerous": bool(getattr(cfg, "dangerous", False)) if cfg else False,
            "triggered_by": d.get("triggered_by") or "system",
            "target_service": d.get("target_service"),
            "target_instance": d.get("target_instance"),
            "parameters": jsonable_encoder(params_obj),
            "started_at": started_at.isoformat(),
            "age_seconds": age_seconds,
            "incident": None,
            "confirm_url": None,
        }

        if inc_obj:
            item["incident"] = {
                "id": inc_obj.id,
                "title": inc_obj.title,
                "severity": inc_obj.severity.value,
                "status": inc_obj.status.value,
                "service": inc_obj.service,
                "instance": inc_obj.instance,
                "error_type": inc_obj.error_type,
                "created_at": inc_obj.created_at.isoformat(),
                "updated_at": inc_obj.updated_at.isoformat(),
            }
            item["confirm_url"] = (
                f"/api/incidents/{inc_obj.id}/runbooks/{d['id']}/confirm"
            )
        else:
            item["incident"] = {"id": inc_id, "missing": True} if inc_id else None

        items.append(item)

    items.sort(key=lambda x: x["age_seconds"], reverse=True)
    items = items[:limit]

    return {
        "total": len(items),
        "pending": items,
        "filters": {
            "incident_id": incident_id,
            "runbook": runbook,
            "min_age_seconds": min_age_seconds,
            "include_resolved": include_resolved,
            "only_confirmable": only_confirmable,
            "limit": limit,
        },
    }


@router.get("/api/runbooks/pending/stale")
async def list_or_cancel_stale_pending(
    min_age_seconds: int = 3600,
    limit: int = 200,
    action: str = "none",  # none | cancel
    reason: str = "stale_pending_ttl",
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if min_age_seconds < 0:
        min_age_seconds = 0
    if limit <= 0:
        limit = 200
    limit = min(limit, 2000)

    now = datetime.now(timezone.utc)

    # 1) listar candidatos (solo lectura)
    cur = await db.execute(
        """
        SELECT id, incident_id, runbook_name, started_at, target_service, target_instance
        FROM runbook_executions
        WHERE lower(status) = 'pending' AND started_at IS NOT NULL
        ORDER BY started_at ASC
        LIMIT ?
        """,
        (limit,),
    )
    rows = await cur.fetchall()
    await cur.close()

    stale = []
    for r in rows:
        d = dict(r)
        try:
            started_at = datetime.fromisoformat(d["started_at"])
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        age = int((now - started_at).total_seconds())
        if age < min_age_seconds:
            continue

        stale.append(
            {
                "pending_execution_id": d["id"],
                "incident_id": d.get("incident_id"),
                "runbook_name": d["runbook_name"],
                "started_at": started_at.isoformat(),
                "age_seconds": age,
                "target_service": d.get("target_service"),
                "target_instance": d.get("target_instance"),
            }
        )

    stale.sort(key=lambda x: x["age_seconds"], reverse=True)

    if action.strip().lower() != "cancel":
        return {
            "action": "none",
            "min_age_seconds": min_age_seconds,
            "total": len(stale),
            "stale": stale[:limit],
        }

    # 2) cancelación con lock global (evita "database is locked")
    canceled = []
    now_iso = now.isoformat()

    async with DB_WRITE_LOCK:
        await db.execute("BEGIN IMMEDIATE")
        try:
            for item in stale[:limit]:
                pending_id = item["pending_execution_id"]

                output_payload = {
                    "status": "skipped",
                    "success": False,
                    "message": "Auto-canceled stale pending execution (TTL policy)",
                    "reason": reason,
                    "canceled_by": actor_id,
                    "canceled_at": now_iso,
                }
                out = json.dumps(output_payload, ensure_ascii=False)

                res = await db.execute(
                    """
                    UPDATE runbook_executions
                    SET status='skipped', output=?, completed_at=?
                    WHERE id=? AND lower(status)='pending'
                    """,
                    (out, now_iso, pending_id),
                )

                if getattr(res, "rowcount", 0) == 1:
                    # actualiza confirmaciones si existían
                    await db.execute(
                        """
                        UPDATE runbook_confirmations
                        SET status='skipped', updated_at=?, result_json=?
                        WHERE pending_execution_id = ?
                          AND lower(status)='pending'
                        """,
                        (now_iso, out, pending_id),
                    )

                    canceled.append({**item, "canceled": True, "reason": reason})

            await db.commit()
            # timeline + failure (best-effort) fuera del lock/tx
            for item in canceled:
                ex_id = item["pending_execution_id"]
                try:
                    await emit_event(
                        event_key=f"exec:{ex_id}:ttl_skipped_endpoint",
                        event_type="runbook.confirmation.skipped_stale_endpoint",
                        actor=actor_id,
                        source="api",
                        severity="warning",
                        message="Stale pending skipped via endpoint",
                        incident_id=item.get("incident_id"),
                        execution_id=ex_id,
                        confirmation_id=ex_id,
                        details={
                            "reason": reason,
                            "min_age_seconds": min_age_seconds,
                            "canceled_at": now_iso,
                            "runbook": item.get("runbook_name"),
                            "target_service": item.get("target_service"),
                            "target_instance": item.get("target_instance"),
                        },
                    )
                except Exception:
                    pass

                try:
                    await record_failure(
                        execution_id=ex_id,
                        runbook_name=item.get("runbook_name") or "unknown",
                        failure_kind="ttl_skipped",
                        final_status="skipped",
                        incident_id=item.get("incident_id"),
                        target_service=item.get("target_service"),
                        target_instance=item.get("target_instance"),
                        execution_origin="api",
                        retry_of_execution_id=None,
                        attempt_no=None,
                        is_final=True,
                        error_message=reason,
                        details={
                            "canceled_at": now_iso,
                            "via": "pending/stale endpoint",
                        },
                    )
                except Exception:
                    pass
        except Exception:
            await db.rollback()
            raise

    # best-effort cache bust fuera del lock
    for item in canceled:
        try:
            await runbook_engine.invalidate_execution_cache(
                item["pending_execution_id"]
            )
        except Exception:
            pass

    # audit best-effort fuera del lock
    for item in canceled:
        try:
            audit_logger.log(
                event_type="runbook_confirmation",
                actor=actor_id,
                resource_type="runbook_execution",
                resource_id=item["pending_execution_id"],
                action="pending_skipped_stale_endpoint",
                details={
                    "reason": reason,
                    "canceled_at": now_iso,
                    "min_age_seconds": min_age_seconds,
                },
                success=True,
            )
        except Exception:
            pass

    return {
        "action": "cancel",
        "min_age_seconds": min_age_seconds,
        "requested": min(len(stale), limit),
        "canceled": len(canceled),
        "items": canceled,
    }


# --------------
# Confirmations
# --------------


@router.get("/api/runbooks/confirmations")
async def list_runbook_confirmations(
    limit: int = 50,
    incident_id: Optional[str] = None,
    runbook: Optional[str] = None,
    status: Optional[str] = None,  # pending|success|skipped|error
    actor_id_filter: Optional[str] = None,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    """
    Auditoría de confirmaciones (source of truth = tabla runbook_confirmations).
    Filtros opcionales: incident_id, runbook, status, actor_id_filter.
    """
    # sanea limit
    if limit <= 0:
        limit = 50
    limit = min(limit, 500)

    where = []
    params = []

    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)

    if runbook:
        where.append("runbook_name = ?")
        params.append(runbook)

    if status:
        st = status.strip().lower()
        if st not in ("pending", "success", "skipped", "error"):
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        where.append("status = ?")
        params.append(st)

    if actor_id_filter:
        where.append("actor_id = ?")
        params.append(actor_id_filter)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    cur = await db.execute(
        f"""
        SELECT
          pending_execution_id,
          incident_id,
          runbook_name,
          actor_id,
          status,
          confirmed_execution_id,
          created_at,
          updated_at,
          result_json
        FROM runbook_confirmations
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items = []
    for r in rows:
        d = dict(r)
        # parse result_json a dict si es posible (y si no, lo dejamos como string)
        if d.get("result_json"):
            try:
                d["result"] = json.loads(d["result_json"])
            except Exception:
                d["result"] = {"raw": d["result_json"]}
        else:
            d["result"] = None

        # no duplicar payload gigante
        d.pop("result_json", None)
        items.append(d)

    return {
        "total": len(items),
        "confirmations": items,
        "filters": {
            "limit": limit,
            "incident_id": incident_id,
            "runbook": runbook,
            "status": status,
            "actor_id": actor_id_filter,
        },
    }


@router.post("/api/incidents/{incident_id}/runbooks/{execution_id}/confirm")
async def confirm_runbook_execution_endpoint(
    request: Request,
    incident_id: str = Path(...),
    execution_id: str = Path(...),
    payload: Optional[Dict[str, Any]] = Body(default=None),
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    return await confirm_runbook_execution_impl(
        request=request,
        incident_id=incident_id,
        execution_id=execution_id,
        payload=payload,
        actor_id=actor_id,
        db=db,
    )


@router.post("/api/runbooks/confirm")
async def confirm_runbook(
    req: ConfirmRunbookRequest,
    request: Request,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    """
    Wrapper: delega al endpoint idempotente.

    Cambios clave:
    - NO depende de runbook_engine.get_execution() (memoria/cache).
    - Valida contra SQLite (runbook_executions) para que sea crash-safe.
    - Sigue permitiendo replay idempotente (aunque ya no esté pending en memoria).
    """
    # 1) incident existe (RAM/DB manager), ok mantenerlo
    incident = await incident_manager.get_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # 2) Validación en DB (source of truth)
    cur = await db.execute(
        """
        SELECT id, incident_id, runbook_name, status
        FROM runbook_executions
        WHERE id = ?
        LIMIT 1
        """,
        (req.pending_execution_id,),
    )
    row = await cur.fetchone()
    await cur.close()

    if not row:
        raise HTTPException(status_code=404, detail="pending_execution_id not found")

    # row puede ser sqlite Row o dict-like; soportamos ambos
    pending_incident_id = (
        row["incident_id"]
        if isinstance(row, dict) or hasattr(row, "__getitem__")
        else None
    )
    if pending_incident_id != req.incident_id:
        raise HTTPException(
            status_code=409, detail="Execution does not belong to this incident"
        )

    # 3) Delegar al impl idempotente (él ya valida requires_confirmation, etc.)
    return await confirm_runbook_execution_impl(
        request=request,
        incident_id=req.incident_id,
        execution_id=req.pending_execution_id,
        payload={"parameters": req.parameters or {}},
        actor_id=actor_id,
        db=db,
    )


# ----------------
# Events / Timeline
# ----------------


@router.get("/api/runbooks/{execution_id}/events")
async def execution_events(
    execution_id: str,
    limit: int = 300,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if limit <= 0:
        limit = 300
    limit = min(limit, 1500)

    cur = await db.execute(
        """
        SELECT
          id, event_key, created_at,
          incident_id, execution_id, confirmation_id, queue_execution_id,
          event_type, severity, actor, source, message, details_json
        FROM incident_events
        WHERE execution_id = ?
        ORDER BY created_at ASC, id ASC
        LIMIT ?
        """,
        (execution_id, limit),
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

    return {"execution_id": execution_id, "total": len(items), "events": items}


@router.get("/api/incidents/{incident_id}/timeline")
async def incident_timeline(
    incident_id: str,
    limit: int = 200,
    cursor: Optional[str] = None,  # formato: "<created_at>|<id>"
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if limit <= 0:
        limit = 200
    limit = min(limit, 1000)

    # valida incidente existe (DB, no RAM)
    cur = await db.execute("SELECT 1 FROM incidents WHERE id=? LIMIT 1", (incident_id,))
    ok = await cur.fetchone()
    await cur.close()
    if not ok:
        raise HTTPException(status_code=404, detail="Incident not found")

    where = "WHERE incident_id = ?"
    params: list[Any] = [incident_id]

    # cursor: paginación estable
    # Trae eventos "más nuevos primero". Cursor apunta al último que viste.
    if cursor:
        try:
            c_ts, c_id = cursor.split("|", 1)
            where += " AND (created_at < ? OR (created_at = ? AND id < ?))"
            params.extend([c_ts, c_ts, c_id])
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor format")

    cur = await db.execute(
        f"""
        SELECT
          id, event_key, created_at,
          incident_id, execution_id, confirmation_id, queue_execution_id,
          event_type, severity, actor, source, message, details_json
        FROM incident_events
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items: list[dict[str, Any]] = []
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

    next_cursor = None
    if items:
        last = items[-1]
        next_cursor = f"{last['created_at']}|{last['id']}"

    return {
        "incident_id": incident_id,
        "total": len(items),
        "next_cursor": next_cursor,
        "events": items,
    }


# ----------------
# Queue (control plane)
# ----------------


@router.get("/api/runbooks/queue/state")
async def runbooks_queue_state(
    limit: int = 25,
    include_samples: bool = True,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    """
    Vista operativa tipo "control plane":
    - Totales pending/running
    - Oldest age (s)
    - Stale totals por threshold
    - (opcional) samples de los más viejos pending/running
    """
    if limit <= 0:
        limit = 25
    limit = min(limit, 200)

    now = datetime.now(timezone.utc)

    # 1) Totales
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

    # Helper parse ISO
    def _parse_iso(dt_raw: str):
        try:
            dt = datetime.fromisoformat(dt_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    # 2) Pending oldest  stale counts
    pending_oldest_seconds = 0.0
    stale_counts = {int(t): 0 for t in (PENDING_STALE_THRESHOLDS_SECONDS or [])}

    cur = await db.execute(
        """
        SELECT started_at
        FROM runbook_executions
        WHERE lower(status) = 'pending'
          AND started_at IS NOT NULL
        ORDER BY started_at ASC
        """
    )
    pend_rows = await cur.fetchall()
    await cur.close()

    ages: list[float] = []
    for pr in pend_rows:
        raw = pr["started_at"]
        if not raw:
            continue
        dt = _parse_iso(raw)
        if not dt:
            continue
        age_s = (now - dt).total_seconds()
        if age_s < 0:
            continue
        ages.append(age_s)
        for t in list(stale_counts.keys()):
            if age_s >= float(t):
                stale_counts[t] += 1
    pending_oldest_seconds = float(max(ages)) if ages else 0.0

    # 3) Running oldest
    running_oldest_seconds = 0.0
    cur = await db.execute(
        """
        SELECT started_at
        FROM runbook_executions
        WHERE lower(status) = 'running'
          AND started_at IS NOT NULL
        ORDER BY started_at ASC
        """
    )
    run_rows = await cur.fetchall()
    await cur.close()

    run_ages: list[float] = []
    for rr in run_rows:
        raw = rr["started_at"]
        if not raw:
            continue
        dt = _parse_iso(raw)
        if not dt:
            continue
        age_s = (now - dt).total_seconds()
        if age_s >= 0:
            run_ages.append(age_s)
    running_oldest_seconds = float(max(run_ages)) if run_ages else 0.0

    # 4) Samples (oldest first)
    samples_pending = []
    samples_running = []
    if include_samples:
        cur = await db.execute(
            """
            SELECT
              id, incident_id, runbook_name, status, triggered_by,
              target_service, target_instance, started_at
            FROM runbook_executions
            WHERE lower(status) = 'pending'
              AND started_at IS NOT NULL
            ORDER BY started_at ASC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cur.fetchall()
        await cur.close()
        for r in rows:
            started = _parse_iso(r["started_at"]) if r["started_at"] else None
            age_s = int((now - started).total_seconds()) if started else None
            samples_pending.append(
                {
                    "execution_id": r["id"],
                    "incident_id": r["incident_id"],
                    "runbook": r["runbook_name"],
                    "triggered_by": r["triggered_by"],
                    "target_service": r["target_service"],
                    "target_instance": r["target_instance"],
                    "started_at": r["started_at"],
                    "age_seconds": age_s,
                }
            )

        cur = await db.execute(
            """
            SELECT
              id, incident_id, runbook_name, status, triggered_by,
              target_service, target_instance, started_at
            FROM runbook_executions
            WHERE lower(status) = 'running'
              AND started_at IS NOT NULL
            ORDER BY started_at ASC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cur.fetchall()
        await cur.close()
        for r in rows:
            started = _parse_iso(r["started_at"]) if r["started_at"] else None
            age_s = int((now - started).total_seconds()) if started else None
            samples_running.append(
                {
                    "execution_id": r["id"],
                    "incident_id": r["incident_id"],
                    "runbook": r["runbook_name"],
                    "triggered_by": r["triggered_by"],
                    "target_service": r["target_service"],
                    "target_instance": r["target_instance"],
                    "started_at": r["started_at"],
                    "age_seconds": age_s,
                }
            )

    return {
        "ts": now.isoformat(),
        "totals": {
            "pending": pending,
            "running": running,
        },
        "oldest_seconds": {
            "pending": pending_oldest_seconds,
            "running": running_oldest_seconds,
        },
        "pending_stale_total": {
            str(k): int(v) for k, v in sorted(stale_counts.items(), key=lambda x: x[0])
        },
        "samples": (
            {
                "pending": samples_pending,
                "running": samples_running,
            }
            if include_samples
            else None
        ),
        "config": {
            "stale_thresholds_seconds": [
                int(t) for t in (PENDING_STALE_THRESHOLDS_SECONDS or [])
            ],
            "limit": limit,
        },
    }


@router.get("/api/dashboard/queue/items")
async def dashboard_queue_items(
    limit: int = 60,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if limit <= 0:
        limit = 60
    limit = min(limit, 500)

    now = datetime.now(timezone.utc)

    def _parse_iso(dt_raw: Optional[str]) -> Optional[datetime]:
        if not dt_raw:
            return None
        try:
            dt = datetime.fromisoformat(dt_raw)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    # totals by status (simple)
    cur = await db.execute(
        """
        SELECT lower(status) AS st, count(*) AS n
        FROM runbook_queue
        GROUP BY lower(status)
        """
    )
    rows = await cur.fetchall()
    await cur.close()

    totals = {"queued": 0, "running": 0}
    for r in rows:
        st = (r["st"] or "").lower()
        n = int(r["n"] or 0)
        if st in totals:
            totals[st] = n

    # queued items (oldest available first)
    cur = await db.execute(
        """
        SELECT
          execution_id, runbook_name, incident_id,
          target_service, target_instance,
          status, attempts, available_at,
          lease_owner, lease_expires_at,
          created_at, updated_at, last_heartbeat
        FROM runbook_queue
        WHERE lower(status) IN ('queued','pending')
        ORDER BY COALESCE(available_at, created_at) ASC
        LIMIT ?
        """,
        (limit,),
    )
    queued_rows = await cur.fetchall()
    await cur.close()

    # running items
    cur = await db.execute(
        """
        SELECT
          execution_id, runbook_name, incident_id,
          target_service, target_instance,
          status, attempts, available_at,
          lease_owner, lease_expires_at,
          created_at, updated_at, last_heartbeat
        FROM runbook_queue
        WHERE lower(status) = 'running'
        ORDER BY COALESCE(updated_at, created_at) ASC
        LIMIT ?
        """,
        (limit,),
    )
    running_rows = await cur.fetchall()
    await cur.close()

    def _with_age(d: dict) -> dict:
        # age based on available_at (queued) or created_at (fallback)
        base = _parse_iso(d.get("available_at")) or _parse_iso(d.get("created_at"))
        if base:
            d["age_seconds"] = max(0, int((now - base).total_seconds()))
        else:
            d["age_seconds"] = None
        return d

    queued = [_with_age(dict(r)) for r in queued_rows]
    running = [_with_age(dict(r)) for r in running_rows]

    return {
        "ts": now.isoformat(),
        "totals": totals,
        "items": {"queued": queued, "running": running},
    }
