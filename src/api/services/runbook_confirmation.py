import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiosqlite
from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder

from ...core.config import settings
from ...core.logging_config import get_logger, setup_logging
from ...core.models import RunbookStatus
from ...core.security import rate_limit
from ...db.connection import DB_PATH, DB_WRITE_LOCK
from ...db.event_store import emit_event, record_failure
from ...incidents.incident_manager import incident_manager
from ...observability.metrics_collector import metrics_collector
from ...runbooks.registry import registry
from ...runbooks.runbook_engine import runbook_engine
from ..helpers import (
    _derive_confirmation_status_from_payload,
    _execute_retry,
    _tg_rate_limit_confirm,
    normalize_execution_status,
)
from .queue_service import _enqueue_runbook_execution_db

# Logging
setup_logging()
logger = get_logger("main")


async def confirm_runbook_execution_impl(
    *,
    request: Optional[Request],
    incident_id: str,
    execution_id: str,
    actor_id: str,
    db,
    payload: Optional[Dict[str, Any]] = None,
    telegram_chat_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Confirmación idempotente + durable queue (blindada).

    Flujo:
      0) Validaciones
      1) TX corta: replay/reserva fila en runbook_confirmations (idempotencia fuerte)
      2) Fuera de TX: crea ejecución confirmada (execute_async) y asegura enqueue durable
      3) TX corta: persiste status + link pending->confirmed + result_json
      4) Si no terminal: finalizer que cerrará success|skipped|error al completar
    """
    payload = payload or {}
    extra_params: Dict[str, Any] = payload.get("parameters") or {}

    # ----------------------------
    # 0) Validaciones (sin lock)
    # ----------------------------
    incident = await incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    target = await runbook_engine.get_execution(execution_id)
    if not target:
        raise HTTPException(status_code=404, detail="Execution not found")

    if target.incident_id != incident_id:
        raise HTTPException(
            status_code=409, detail="Execution does not belong to this incident"
        )

    cfg = registry.get(target.runbook_name)
    if not cfg:
        raise HTTPException(status_code=404, detail="Runbook not registered")

    if not runbook_engine.requires_confirmation(cfg):
        raise HTTPException(
            status_code=409, detail="This runbook does not require confirmation"
        )

    # ------------------------------------------------------------
    # RATE LIMIT
    #
    # HTTP path → existing limiter
    # Telegram path → telegram_chat_id limiter
    # ------------------------------------------------------------

    if request is not None:
        await rate_limit(
            request,
            "confirm",
            settings.rate_limit_confirm_max,
            settings.rate_limit_window_seconds,
        )
    else:
        # Telegram path
        try:
            _tg_rate_limit_confirm(telegram_chat_id)
        except Exception as e:
            logger.warning(
                "telegram_confirm_rate_limited",
                execution_id=execution_id,
                chat_id=telegram_chat_id,
                error=str(e),
            )
            raise HTTPException(
                status_code=429,
                detail="Telegram confirmation rate limited",
            )

    now_iso = datetime.now(timezone.utc).isoformat()

    # ----------------------------
    # 1) Reserva / Replay (TX corta)
    # ----------------------------
    async with DB_WRITE_LOCK:
        await db.execute("BEGIN IMMEDIATE")
        try:
            cur = await db.execute(
                """
                SELECT status, confirmed_execution_id, result_json
                FROM runbook_confirmations
                WHERE pending_execution_id = ?
                """,
                (target.id,),
            )
            row = await cur.fetchone()
            await cur.close()

            # 1.a) Replay idempotente
            if row:
                await db.execute("COMMIT")

                persisted_status = (row["status"] or "").lower() or "pending"
                persisted_confirmed = row["confirmed_execution_id"]

                if row["result_json"]:
                    try:
                        result = json.loads(row["result_json"])
                    except Exception as e:
                        logger.warning(
                            "confirm_result_json_invalid",
                            pending_execution_id=target.id,
                            error=str(e),
                        )
                        return {
                            "success": persisted_status == "success",
                            "status": persisted_status,
                            "already_confirmed": persisted_status != "pending",
                            "pending_execution_id": target.id,
                            "confirmed_execution_id": persisted_confirmed,
                            "execution": None,
                            "message": "Execution already confirmed (invalid persisted payload)",
                        }

                    # self-heal suave si el payload contradice columnas
                    desired_status = _derive_confirmation_status_from_payload(result)
                    desired_confirmed = (
                        result.get("confirmed_execution_id") or persisted_confirmed
                    )

                    if desired_status and (
                        persisted_status != desired_status
                        or persisted_confirmed != desired_confirmed
                    ):
                        try:
                            async with DB_WRITE_LOCK:
                                await _execute_retry(
                                    db=db,
                                    sql="""
                                    UPDATE runbook_confirmations
                                    SET status = ?, confirmed_execution_id = ?, updated_at = ?
                                    WHERE pending_execution_id = ?
                                    """,
                                    params=(
                                        desired_status,
                                        desired_confirmed,
                                        datetime.now(timezone.utc).isoformat(),
                                        target.id,
                                    ),
                                )
                        except Exception as e:
                            logger.warning(
                                "confirm_self_heal_failed",
                                pending_execution_id=target.id,
                                error=str(e),
                            )

                    result["already_confirmed"] = True
                    result.setdefault("pending_execution_id", target.id)
                    result.setdefault("confirmed_execution_id", desired_confirmed)
                    result["message"] = (
                        "Execution already confirmed (idempotent replay)"
                    )
                    return result

                # No hay payload persistido
                return {
                    "success": persisted_status == "success",
                    "status": persisted_status,
                    "already_confirmed": persisted_status != "pending",
                    "pending_execution_id": target.id,
                    "confirmed_execution_id": persisted_confirmed,
                    "execution": None,
                    "message": (
                        "Execution already confirmed"
                        if persisted_status != "pending"
                        else "Execution is pending confirmation processing"
                    ),
                }

            # 1.b) No existe fila -> debe seguir PENDING
            if target.status != RunbookStatus.PENDING:
                await db.execute("ROLLBACK")
                raise HTTPException(
                    status_code=409,
                    detail=f"execution is not pending: {getattr(target.status, 'value', str(target.status))}",
                )

            # 1.c) Reserva fila
            await _execute_retry(
                db=db,
                sql="""
                INSERT INTO runbook_confirmations(
                  pending_execution_id, incident_id, runbook_name, actor_id,
                  status, confirmed_execution_id, created_at, updated_at, result_json
                ) VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?, NULL)
                """,
                params=(
                    target.id,
                    incident.id,
                    target.runbook_name,
                    actor_id,
                    now_iso,
                    now_iso,
                ),
            )
            await db.execute("COMMIT")
        except Exception:
            await db.execute("ROLLBACK")
            raise

    # ----------------------------
    # 2) Ejecutar/encolar (FUERA TX)
    #     - create confirmed execution
    #     - ensure durable enqueue (fallback)
    # ----------------------------
    confirmed_id: Optional[str] = None
    conf_status: str = "error"
    result_payload: Dict[str, Any] = {}

    try:
        # best-effort: marca el pending como reemplazado en el incidente
        try:
            await incident_manager.replace_pending_execution(
                incident_id=incident.id,
                execution_id=target.id,
                replaced_by="human",
            )
        except Exception:
            pass

        merged_params = {
            **(getattr(target, "parameters", None) or {}),
            **(extra_params or {}),
        }

        execution = await runbook_engine.execute_async(
            runbook_name=target.runbook_name,
            incident_id=incident.id,
            target_service=target.target_service,
            target_instance=getattr(target, "target_instance", None),
            parameters=merged_params,
            triggered_by="human",
            skip_validation=False,
        )
        confirmed_id = execution.id

        # ---- DURABLE QUEUE GUARDRAIL ----
        # Si el engine NO metio en cola en runbook_queue, lo hacemos aquí.
        # (idempotente por PRIMARY KEY execution_id)
        try:
            # check sin lock (lectura)
            cur = await db.execute(
                "SELECT 1 FROM runbook_queue WHERE execution_id = ? LIMIT 1",
                (confirmed_id,),
            )
            exists = await cur.fetchone()
            await cur.close()

            if not exists:
                # insert con lock + TX corta
                async with DB_WRITE_LOCK:
                    await db.execute("BEGIN IMMEDIATE")
                    try:
                        await _enqueue_runbook_execution_db(
                            db=db,
                            execution_id=confirmed_id,
                            incident_id=incident.id,
                            runbook_name=target.runbook_name,
                            target_service=target.target_service,
                            target_instance=getattr(target, "target_instance", None),
                            parameters=merged_params,
                            triggered_by="human",
                            execution_origin="human",
                            now_iso=datetime.now(timezone.utc).isoformat(),
                        )
                        await db.execute("COMMIT")
                    except Exception:
                        await db.execute("ROLLBACK")
                        raise

                logger.warning(
                    "confirm_enqueue_fallback_used",
                    pending_execution_id=target.id,
                    confirmed_execution_id=confirmed_id,
                    runbook=target.runbook_name,
                )
        except Exception as e:
            logger.warning(
                "confirm_enqueue_fallback_check_failed",
                pending_execution_id=target.id,
                confirmed_execution_id=confirmed_id,
                error=str(e),
            )

        # hot-consume (best-effort)
        try:
            runbook_engine.kick_queue_worker()
        except Exception:
            pass

        # timeline (best-effort)
        try:
            await incident_manager.add_execution_to_incident(incident.id, execution)
        except Exception:
            pass

        st, is_ok = normalize_execution_status(execution)
        is_terminal = st in {"success", "error", "timeout", "skipped"}

        if is_terminal:
            conf_status = (
                "success"
                if st == "success"
                else "skipped"
                if st == "skipped"
                else "error"
            )
            msg = (
                "Execution confirmed and runbook executed"
                if conf_status == "success"
                else (
                    "Execution confirmed (runbook skipped)"
                    if conf_status == "skipped"
                    else "Execution confirmed but runbook failed"
                )
            )
            result_payload = {
                "success": is_ok,
                "already_confirmed": False,
                "pending_execution_id": target.id,
                "confirmed_execution_id": confirmed_id,
                "execution": jsonable_encoder(execution),
                "runbook_status": st,
                "status": conf_status,
                "message": msg,
            }
        else:
            conf_status = "pending"
            result_payload = {
                "success": True,
                "already_confirmed": False,
                "pending_execution_id": target.id,
                "confirmed_execution_id": confirmed_id,
                "execution": jsonable_encoder(execution),
                "runbook_status": st,
                "queue_state": "queued_or_running",
                "status": "pending",
                "message": "Execution confirmed; runbook queued/running (final status will be updated)",
            }

    except Exception as e:
        conf_status = "error"
        result_payload = {
            "success": False,
            "already_confirmed": False,
            "pending_execution_id": target.id,
            "confirmed_execution_id": None,
            "execution": None,
            "runbook_status": "error",
            "status": "error",
            "message": f"Execution failed: {str(e)}",
        }

    # ----------------------------
    # 3) Persistir confirmación + link (TX corta)
    # ----------------------------
    now2 = datetime.now(timezone.utc).isoformat()

    async with DB_WRITE_LOCK:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await _execute_retry(
                db=db,
                sql="""
                UPDATE runbook_confirmations
                SET status = ?,
                    confirmed_execution_id = ?,
                    updated_at = ?,
                    result_json = ?
                WHERE pending_execution_id = ?
                """,
                params=(
                    conf_status,
                    confirmed_id,
                    now2,
                    json.dumps(result_payload, ensure_ascii=False, default=str),
                    target.id,
                ),
            )

            if confirmed_id:
                await _execute_retry(
                    db=db,
                    sql="""
                    UPDATE runbook_executions
                    SET confirmed_execution_id = ?, confirmed_by = ?, confirmed_at = ?
                    WHERE id = ?
                    """,
                    params=(confirmed_id, actor_id, now2, target.id),
                )

            await db.execute("COMMIT")
            try:
                started_iso = (
                    target.started_at.isoformat()
                    if getattr(target, "started_at", None)
                    else (
                        target.started_at
                        if isinstance(getattr(target, "started_at", None), str)
                        else ""
                    )
                )
                metrics_collector.record_runbook_confirmation_latency(
                    runbook=target.runbook_name,
                    started_at_iso=started_iso,
                    confirmed_at_iso=now2,
                )
            except Exception:
                pass
        except Exception:
            await db.execute("ROLLBACK")
            raise

    # cache bust (best-effort)
    try:
        await runbook_engine.invalidate_execution_cache(target.id)
    except Exception:
        pass

    # ----------------------------
    # 4) Finalizer si no terminal
    # ----------------------------
    if confirmed_id and conf_status == "pending":
        try:
            asyncio.create_task(
                _finalize_confirmation_async(target.id, confirmed_id),
                name=f"confirm-finalize:{target.id}",
            )
        except Exception:
            pass

    # métricas (best-effort)
    try:
        metrics_collector.record_runbook_confirmation(
            runbook=target.runbook_name,
            status=conf_status,
            actor=actor_id,
        )
    except Exception:
        pass

    logger.info(
        "runbook_confirmed",
        incident_id=incident.id,
        pending_execution_id=target.id,
        confirmed_execution_id=confirmed_id,
        runbook=target.runbook_name,
        status=conf_status,
        actor=actor_id,
    )
    # timeline: confirmation completed (best-effort)
    try:
        await emit_event(
            event_key=f"confirm:{target.id}:{confirmed_id or 'none'}:{conf_status}",
            event_type="runbook.confirmation.completed",
            actor=actor_id,
            source="api.confirm",
            severity=(
                "info" if conf_status in ("success", "skipped", "pending") else "error"
            ),
            message="Runbook confirmation processed",
            incident_id=incident.id,
            execution_id=target.id,
            confirmation_id=target.id,
            details={
                "pending_execution_id": target.id,
                "confirmed_execution_id": confirmed_id,
                "status": conf_status,
                "runbook": target.runbook_name,
            },
        )
    except Exception:
        pass

    # failures: if confirmation itself errored hard (not just runbook later)
    if conf_status == "error" and not confirmed_id:
        try:
            await record_failure(
                execution_id=target.id,
                runbook_name=target.runbook_name,
                failure_kind="exception",
                final_status="error",
                incident_id=incident.id,
                target_service=target.target_service,
                target_instance=getattr(target, "target_instance", None),
                execution_origin="human",
                retry_of_execution_id=None,
                is_final=True,
                error_message=result_payload.get("message") or "confirm_failed",
                details={"stage": "confirm_runbook_execution_impl"},
            )
        except Exception:
            pass
    return result_payload


async def _finalize_confirmation_async(
    pending_execution_id: str,
    confirmed_execution_id: str,
) -> None:
    terminal = {"success", "failed", "timeout", "skipped"}
    deadline = time.time() + 600  # 10 min

    try:
        last_ex = None
        last_st = None

        while time.time() < deadline:
            ex = await runbook_engine.get_execution(confirmed_execution_id)
            if ex:
                st = str(getattr(ex.status, "value", ex.status)).lower()
                last_ex = ex
                last_st = st
                if st in terminal:
                    break
            await asyncio.sleep(0.5)

        if not last_ex or not last_st:
            return

        st_norm = "error" if last_st in ("failed", "timeout") else last_st
        conf_status = (
            "success"
            if st_norm == "success"
            else "skipped"
            if st_norm == "skipped"
            else "error"
        )

        payload = {
            "success": conf_status in ("success", "skipped"),
            "already_confirmed": True,
            "pending_execution_id": pending_execution_id,
            "confirmed_execution_id": confirmed_execution_id,
            "execution": jsonable_encoder(last_ex),
            "runbook_status": st_norm,
            "message": (
                "Execution confirmed and runbook executed"
                if conf_status == "success"
                else (
                    "Execution confirmed (runbook skipped)"
                    if conf_status == "skipped"
                    else "Execution confirmed but runbook failed"
                )
            ),
            "status": conf_status,
        }

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.execute("PRAGMA synchronous = NORMAL;")

            async with DB_WRITE_LOCK:
                await db.execute("BEGIN IMMEDIATE")
                try:
                    await _execute_retry(
                        db=db,
                        sql="""
                        UPDATE runbook_confirmations
                        SET status = ?, updated_at = ?, result_json = ?
                        WHERE pending_execution_id = ?
                        """,
                        params=(
                            conf_status,
                            datetime.now(timezone.utc).isoformat(),
                            json.dumps(payload, ensure_ascii=False, default=str),
                            pending_execution_id,
                        ),
                    )
                    await db.execute("COMMIT")
                except Exception:
                    await db.execute("ROLLBACK")
                    raise

    except Exception:
        return
