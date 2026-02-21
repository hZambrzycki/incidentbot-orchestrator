"""
Runbook Engine - Secure execution of registered runbooks.
Handles execution, timeout, logging, and audit trail.
"""

# ============================================================
# Imports (stdlib)
# ============================================================
import asyncio
import json
import os
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# ============================================================
# Imports (third-party)
# ============================================================
import aiosqlite
from fastapi.encoders import jsonable_encoder

# ============================================================
# Imports (local / project)
# ============================================================
# Import runbooks to register them
import src.runbooks.definitions as _runbooks  # noqa: F401
from src.core.config import settings
from src.core.logging_config import audit_logger, get_logger
from src.core.models import Incident, RunbookExecution, RunbookStatus
from src.db.connection import DB_PATH, DB_WRITE_LOCK
from src.db.event_store import emit_event, record_failure
from src.observability.metrics_collector import metrics_collector
from src.runbooks.registry import registry

logger = get_logger("runbook_engine")

# ============================================================
# Confirmation guardrails
# ============================================================
# Who can actually run a runbook that requires confirmation
ALLOWED_CONFIRM_TRIGGERS = {"human"}  # the endpoint /confirm uses triggered_by="human"


class RunbookEngine:
    """
    Engine for executing runbooks safely.

    Security features:
    - Only executes registered (allowlisted) runbooks
    - Validates service targets
    - Enforces timeouts
    - Records full audit trail
    - Rate limiting for auto-execution
    """

    # ============================================================
    # Lifecycle / init
    # ============================================================
    def __init__(self):
        # ---- In-memory state ----
        self._executions: Dict[str, RunbookExecution] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

        # ---- Concurrency controls ----
        self._semaphore = asyncio.Semaphore(settings.runbook_max_concurrent)

        # Concurrency per service
        self._svc_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._execution_svc_locks: Dict[
            str, str
        ] = {}  # execution_id -> service_name acquired

        raw = (getattr(settings, "runbook_service_concurrency", None) or "").strip()
        if raw:
            for part in raw.split(","):
                p = part.strip()
                if not p or "=" not in p:
                    continue
                name, v = p.split("=", 1)
                name = name.strip()
                try:
                    n = int(v.strip())
                except Exception:
                    continue
                if name and n > 0:
                    self._svc_semaphores[name] = asyncio.Semaphore(n)

        # ---- Rate limit (soft validation) ----
        self._rate_limit: Dict[str, datetime] = {}  # runbook:service -> last_execution
        self._rate_limit_seconds = 300  # Min time between auto-executions

        # ---- Durable queue worker ----
        self._queue_worker_task: Optional[asyncio.Task] = None
        self._queue_wake = asyncio.Event()
        self._queue_stop = asyncio.Event()

        self._queue_heartbeat_interval_s = int(
            getattr(settings, "runbook_queue_heartbeat_seconds", 5)
        )
        self._queue_stale_running_seconds = int(
            getattr(settings, "runbook_queue_stale_running_seconds", 30)
        )
        self._lease_seconds = int(getattr(settings, "runbook_lease_seconds", 30))
        self._max_retries = int(getattr(settings, "runbook_max_retries", 2))
        self._retry_backoff_base = int(
            getattr(settings, "runbook_retry_backoff_base_seconds", 5)
        )
        self._retry_backoff_max = int(
            getattr(settings, "runbook_retry_backoff_max_seconds", 120)
        )
        self._lease_owner = os.getenv("HOSTNAME") or f"pid:{os.getpid()}"

        # ---- Stale pending scheduler ----
        self._stale_pending_task: Optional[asyncio.Task] = None
        self._stale_pending_stop = asyncio.Event()
        self._stale_pending_lock = asyncio.Lock()

        self._stale_pending_interval_s = int(
            getattr(settings, "runbook_stale_pending_check_seconds", 30)
        )
        self._stale_pending_max_age_s = int(
            getattr(settings, "runbook_stale_pending_max_age_seconds", 86400)
        )

        # ---- Recovery ----
        self._recovery_running = False

        # ---- DB write coordination ----
        self._db_write_lock = DB_WRITE_LOCK

    # ============================================================
    # DB write wrapper (BEGIN IMMEDIATE + retries)
    # ============================================================
    async def _with_db_write(self, fn, *, retries: int = 8, base_sleep: float = 0.03):
        async with self._db_write_lock:
            for i in range(retries):
                db = await self._db()
                try:
                    await db.execute("BEGIN IMMEDIATE")
                    result = await fn(db)
                    await db.commit()
                    return result
                except sqlite3.OperationalError as e:
                    try:
                        await db.rollback()
                    except Exception:
                        pass
                    if "database is locked" not in str(e).lower():
                        raise
                    await asyncio.sleep(
                        base_sleep * (2**i) + random.random() * base_sleep
                    )
                finally:
                    try:
                        await db.close()
                    except Exception:
                        pass

            # last try (without swallowing exception)
            db = await self._db()
            try:
                await db.execute("BEGIN IMMEDIATE")
                result = await fn(db)
                await db.commit()
                return result
            finally:
                await db.close()

    # ============================================================
    # Small helpers (origin / backoff / confirmation)
    # ============================================================
    def _infer_origin(self, triggered_by: str, incident_id: Optional[str]) -> str:
        tb = (triggered_by or "system").lower()
        if tb == "human":
            return "human"
        if tb == "api":
            return "api"
        if tb == "telegram":
            return "human"
        # system:
        return "alert" if incident_id else "system"

    def _retry_backoff_seconds(self, attempt_no: int) -> int:
        # attempt_no: 1..N
        base = max(1, self._retry_backoff_base)
        cap = max(base, self._retry_backoff_max)
        # base * 2^(attempt-1)
        val = base * (2 ** max(0, int(attempt_no) - 1))
        return int(min(val, cap))

    @staticmethod
    def requires_confirmation(cfg) -> bool:
        return bool(
            cfg
            and (
                cfg.requires_confirmation
                or (
                    getattr(settings, "runbook_require_confirmation", False)
                    and getattr(cfg, "dangerous", False)
                )
            )
        )

    # ============================================================
    # Durable queue worker public API
    # ============================================================
    def start_queue_worker(self) -> None:
        if self._queue_worker_task and not self._queue_worker_task.done():
            return
        self._queue_stop.clear()
        self._queue_worker_task = asyncio.create_task(
            self._queue_worker_loop(), name="runbook-queue-worker"
        )

    async def stop_queue_worker(self) -> None:
        self._queue_stop.set()
        self._queue_wake.set()
        if self._queue_worker_task:
            self._queue_worker_task.cancel()
            await asyncio.gather(self._queue_worker_task, return_exceptions=True)
        self._queue_worker_task = None

    def kick_queue_worker(self) -> None:
        self._queue_wake.set()

    # ============================================================
    # Stale pending scheduler public API
    # ============================================================
    def start_stale_pending_scheduler(self) -> None:
        if self._stale_pending_task and not self._stale_pending_task.done():
            return
        self._stale_pending_stop.clear()
        self._stale_pending_task = asyncio.create_task(
            self._stale_pending_scheduler_loop(),
            name="runbook-stale-pending-scheduler",
        )

    async def stop_stale_pending_scheduler(self) -> None:
        self._stale_pending_stop.set()
        if self._stale_pending_task:
            self._stale_pending_task.cancel()
            await asyncio.gather(self._stale_pending_task, return_exceptions=True)
        self._stale_pending_task = None

    async def _stale_pending_scheduler_loop(self) -> None:
        logger.info(
            "stale_pending_scheduler_started",
            interval_seconds=self._stale_pending_interval_s,
            max_age_seconds=self._stale_pending_max_age_s,
        )

        while not self._stale_pending_stop.is_set():
            try:
                # No overlap local si una pasada tarda
                if not self._stale_pending_lock.locked():
                    async with self._stale_pending_lock:
                        from src.incidents.incident_manager import incident_manager

                        cancelled = await incident_manager.auto_cancel_stale_pending(
                            max_age_seconds=self._stale_pending_max_age_s
                        )
                        if cancelled:
                            logger.warning(
                                "stale_pending_auto_cancelled",
                                count=cancelled,
                                max_age_seconds=self._stale_pending_max_age_s,
                            )
                # if locked, silent skip
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("stale_pending_scheduler_error", error=str(e))

            try:
                await asyncio.wait_for(
                    self._stale_pending_stop.wait(),
                    timeout=float(self._stale_pending_interval_s),
                )
            except asyncio.TimeoutError:
                continue

        logger.info("stale_pending_scheduler_stopped")

    # ============================================================
    # DB connection + row mapping
    # ============================================================
    def _row_to_execution(self, row: aiosqlite.Row) -> RunbookExecution:
        d = dict(row)
        params = {}
        if d.get("parameters_json"):
            try:
                params = json.loads(d["parameters_json"])
            except Exception:
                params = {}

        payload = {
            "id": d["id"],
            "runbook_name": d["runbook_name"],
            "incident_id": d.get("incident_id"),
            "status": (d["status"] or "").lower(),
            "triggered_by": d.get("triggered_by") or "system",
            "target_service": d.get("target_service"),
            "target_instance": d.get("target_instance"),
            "parameters": params,
            "output": d.get("output") or "",
            "error": d.get("error"),
            "started_at": d.get("started_at"),
            "completed_at": d.get("completed_at"),
            "duration_seconds": d.get("duration_seconds"),
            "confirmed_execution_id": d.get("confirmed_execution_id"),
            "confirmed_by": d.get("confirmed_by"),
            "confirmed_at": d.get("confirmed_at"),
        }
        # Pydantic ISO->datetime
        return RunbookExecution.model_validate(payload)

    async def _db(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(DB_PATH)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA busy_timeout = 5000;")
        await db.execute("PRAGMA foreign_keys=ON;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        return db

    # ============================================================
    # DB helpers (UPSERT execution / enqueue)
    # ============================================================
    async def _persist_execution_on_db(
        self, db: aiosqlite.Connection, execution: RunbookExecution
    ) -> None:
        """
        Same as _persist_execution, but uses an existing DB connection/transaction.
        IMPORTANT: caller is responsible for BEGIN/COMMIT/ROLLBACK.
        """
        payload = jsonable_encoder(execution)
        params_json = json.dumps(payload.get("parameters") or {}, ensure_ascii=False)

        await db.execute(
            """
            INSERT INTO runbook_executions(
              id, incident_id, runbook_name, status, triggered_by,
              execution_origin, retry_of_execution_id,
              target_service, target_instance, parameters_json,
              output, error, started_at, completed_at, duration_seconds,
              confirmed_execution_id, confirmed_by, confirmed_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              incident_id=excluded.incident_id,
              runbook_name=excluded.runbook_name,
              status=excluded.status,
              triggered_by=excluded.triggered_by,
              execution_origin=excluded.execution_origin,
              retry_of_execution_id=excluded.retry_of_execution_id,
              target_service=excluded.target_service,
              target_instance=excluded.target_instance,
              parameters_json=excluded.parameters_json,
              output=excluded.output,
              error=excluded.error,
              started_at=excluded.started_at,
              completed_at=excluded.completed_at,
              duration_seconds=excluded.duration_seconds,
              confirmed_execution_id=excluded.confirmed_execution_id,
              confirmed_by=excluded.confirmed_by,
              confirmed_at=excluded.confirmed_at
            """,
            (
                execution.id,
                execution.incident_id,
                execution.runbook_name,
                execution.status.value
                if hasattr(execution.status, "value")
                else str(execution.status),
                execution.triggered_by or "system",
                getattr(execution, "execution_origin", None)
                or self._infer_origin(execution.triggered_by, execution.incident_id),
                getattr(execution, "retry_of_execution_id", None),
                execution.target_service,
                execution.target_instance,
                params_json,
                execution.output or "",
                execution.error,
                payload.get("started_at"),
                payload.get("completed_at"),
                getattr(execution, "duration_seconds", None),
                execution.confirmed_execution_id,
                execution.confirmed_by,
                payload.get("confirmed_at"),
            ),
        )

    async def _enqueue_execution_on_db(
        self,
        db: aiosqlite.Connection,
        execution: RunbookExecution,
        *,
        available_at_iso: Optional[str] = None,
    ) -> None:
        """
        Same as _enqueue_execution, but uses an existing DB connection/transaction.
        IMPORTANT: caller is responsible for BEGIN/COMMIT/ROLLBACK.
        """
        now = datetime.now(timezone.utc).isoformat()
        payload = jsonable_encoder(execution)
        params_json = json.dumps(payload.get("parameters") or {}, ensure_ascii=False)
        tb = execution.triggered_by or "system"
        origin = getattr(execution, "execution_origin", None) or self._infer_origin(
            tb, execution.incident_id
        )
        available = available_at_iso or now

        await db.execute(
            """
            INSERT INTO runbook_queue(
                execution_id, runbook_name, incident_id,
                target_service, target_instance,
                parameters_json, triggered_by,
                execution_origin, retry_of_execution_id,
                status, attempts, last_heartbeat,
                available_at, lease_owner, lease_expires_at,
                created_at, updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(execution_id) DO UPDATE SET
                runbook_name=excluded.runbook_name,
                incident_id=excluded.incident_id,
                target_service=excluded.target_service,
                target_instance=excluded.target_instance,
                parameters_json=excluded.parameters_json,
                triggered_by=excluded.triggered_by,
                execution_origin=excluded.execution_origin,
                retry_of_execution_id=excluded.retry_of_execution_id,
                status=CASE
                    WHEN runbook_queue.status IN ('done','dead') THEN runbook_queue.status
                    ELSE 'queued'
                END,
                available_at=excluded.available_at,
                updated_at=excluded.updated_at
            """,
            (
                execution.id,
                execution.runbook_name,
                execution.incident_id,
                execution.target_service,
                execution.target_instance,
                params_json,
                tb,
                origin,
                getattr(execution, "retry_of_execution_id", None),
                "queued",
                0,
                None,
                available,
                None,
                None,
                now,
                now,
            ),
        )

    # ============================================================
    # Public async API: create execution (pending/enqueue)
    # ============================================================
    async def execute_async(
        self,
        runbook_name: str,
        incident_id: Optional[str] = None,
        target_service: Optional[str] = None,
        target_instance: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        triggered_by: str = "system",
        skip_validation: bool = False,
    ) -> RunbookExecution:
        parameters = parameters or {}

        runbook_config = registry.get(runbook_name)
        requires_confirm = False
        if runbook_config:
            requires_confirm = bool(
                runbook_config.requires_confirmation
                or (
                    getattr(settings, "runbook_require_confirmation", False)
                    and getattr(runbook_config, "dangerous", False)
                )
            )

        # ------------------------------------------------------------
        # FAIL-FAST HARD GUARD (BEFORE persist/enqueue/pending)
        # - prevents illegal queue/executions even on config/db corruption
        # ------------------------------------------------------------
        hard_err = self._hard_validate_execution(
            runbook_name=runbook_name,
            target_service=target_service,
            triggered_by=triggered_by,
            incident_id=incident_id,
        )
        if hard_err:
            # SRE-friendly: persist a failed execution for auditability, but DO NOT enqueue
            execution = RunbookExecution(
                runbook_name=runbook_name,
                incident_id=incident_id,
                target_service=target_service,
                target_instance=target_instance,
                parameters=parameters,
                triggered_by=triggered_by,
                execution_origin=self._infer_origin(triggered_by, incident_id),
            )
            execution.complete(success=False, error=hard_err)

            logger.warning(
                "runbook_execution_async_rejected",
                execution_id=execution.id,
                runbook=runbook_name,
                incident_id=incident_id,
                target_service=target_service,
                triggered_by=triggered_by,
                error=hard_err,
            )

            async with self._lock:
                self._executions[execution.id] = execution
                self._update_queue_metrics()
            await self._persist_execution(execution)

            await emit_event(
                event_key=f"exec:{execution.id}:rejected",
                event_type="runbook.execution.rejected",
                actor=triggered_by,
                source="runbook_engine",
                severity="warning",
                message="Execution rejected by hard validation",
                incident_id=incident_id,
                execution_id=execution.id,
                details={
                    "runbook": runbook_name,
                    "target_service": target_service,
                    "error": hard_err,
                },
            )
            await record_failure(
                execution_id=execution.id,
                runbook_name=runbook_name,
                failure_kind="validation",
                final_status="failed",
                incident_id=incident_id,
                target_service=target_service,
                target_instance=target_instance,
                execution_origin=execution.execution_origin,
                retry_of_execution_id=getattr(execution, "retry_of_execution_id", None),
                error_message=hard_err,
                details={"stage": "execute_async_hard_guard"},
            )

            return execution

        # ------------------------------------------------------------
        # Idempotence for confirmable runbooks (only if you pass hard guard)
        # ------------------------------------------------------------
        if (
            requires_confirm
            and triggered_by in ("system", "api", "telegram")
            and incident_id
        ):
            existing = await self._get_existing_pending(
                incident_id=incident_id,
                runbook_name=runbook_name,
                target_service=target_service,
            )
            if existing:
                logger.info(
                    "runbook_pending_idempotent_reuse",
                    incident_id=incident_id,
                    runbook=runbook_name,
                    target_service=target_service,
                    existing_execution_id=existing.id,
                    triggered_by=triggered_by,
                )
                try:
                    audit_logger.log(
                        event_type="runbook_confirmation",
                        actor=triggered_by,
                        resource_type="runbook_execution",
                        resource_id=existing.id,
                        action="pending_reused",
                        details={
                            "incident_id": incident_id,
                            "runbook": runbook_name,
                            "target_service": target_service,
                            "target_instance": target_instance,
                        },
                        success=True,
                    )
                    await emit_event(
                        event_key=f"exec:{existing.id}:pending_reused",
                        event_type="runbook.confirmation.pending_reused",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="info",
                        message="Pending confirmation reused (idempotency)",
                        incident_id=incident_id,
                        execution_id=existing.id,
                        confirmation_id=existing.id,
                        details={
                            "runbook": runbook_name,
                            "target_service": target_service,
                        },
                    )
                except Exception:
                    pass
                return existing

        # ------------------------------------------------------------
        # Create + persist (now safe)
        # ------------------------------------------------------------
        execution = RunbookExecution(
            runbook_name=runbook_name,
            incident_id=incident_id,
            target_service=target_service,
            target_instance=target_instance,
            parameters=parameters,
            triggered_by=triggered_by,
            execution_origin=self._infer_origin(triggered_by, incident_id),
        )

        logger.info(
            "runbook_execution_async_created",
            execution_id=execution.id,
            runbook=runbook_name,
            incident_id=incident_id,
            target_service=target_service,
            triggered_by=triggered_by,
        )

        async with self._lock:
            self._executions[execution.id] = execution
            self._update_queue_metrics()
        await self._persist_execution(execution)

        # If runbook missing (shouldn’t happen now because hard validation already checked registry.is_allowed,
        # but keep it defensive in case registry changed between calls)
        if not runbook_config:
            execution.complete(
                success=False,
                error=f"Runbook '{runbook_name}' not found in registry",
            )
            async with self._lock:
                self._executions[execution.id] = execution
                self._update_queue_metrics()
            await self._persist_execution(execution)
            return execution

        # ------------------------------------------------------------
        # PENDING flow (confirmation) (no enqueue)
        # ------------------------------------------------------------
        if requires_confirm and triggered_by in ("system", "api", "telegram"):
            execution.mark_pending(
                json.dumps(
                    {
                        "status": "pending",
                        "success": False,
                        "message": f"Runbook '{runbook_name}' requires confirmation",
                    },
                    ensure_ascii=False,
                )
            )
            async with self._lock:
                self._executions[execution.id] = execution
                self._update_queue_metrics()
            await self._persist_execution(execution)

            try:
                audit_logger.log(
                    event_type="runbook_confirmation",
                    actor=triggered_by,
                    resource_type="runbook_execution",
                    resource_id=execution.id,
                    action="pending_created",
                    details={
                        "incident_id": incident_id,
                        "runbook": runbook_name,
                        "target_service": target_service,
                        "target_instance": target_instance,
                    },
                    success=True,
                )
            except Exception:
                pass
            await emit_event(
                event_key=f"exec:{execution.id}:pending_created",
                event_type="runbook.confirmation.pending_created",
                actor=triggered_by,
                source="runbook_engine",
                severity="info",
                message="Pending confirmation created",
                incident_id=incident_id,
                execution_id=execution.id,
                confirmation_id=execution.id,
                details={"runbook": runbook_name, "target_service": target_service},
            )

            return execution

        # ------------------------------------------------------------
        # Durable queue enqueue (safe)
        # ------------------------------------------------------------
        try:
            await self._enqueue_execution(execution)
            await emit_event(
                event_key=f"exec:{execution.id}:enqueued",
                event_type="runbook.queue.enqueued",
                actor=triggered_by,
                source="runbook_engine",
                severity="info",
                message="Execution enqueued",
                incident_id=incident_id,
                execution_id=execution.id,
                queue_execution_id=execution.id,
                details={"runbook": runbook_name, "target_service": target_service},
            )
            try:
                self.kick_queue_worker()
            except Exception:
                pass
        except Exception as e:
            logger.warning(
                "runbook_queue_enqueue_failed",
                execution_id=execution.id,
                error=str(e),
            )

        return execution

    # ============================================================
    # Queue primitives: enqueue/claim/heartbeat/mark-done
    # ============================================================
    async def _enqueue_execution(self, execution: RunbookExecution) -> None:
        """
        Persist an async execution intent into the durable queue.
        Idempotent (ON CONFLICT DO UPDATE).

        IMPORTANT:
        - All writes go through _with_db_write() so we share the global DB_WRITE_LOCK
        and the same retry/backoff policy.
        - Internal callers with an existing tx should prefer _enqueue_execution_on_db().
        """

        async def _op(db: aiosqlite.Connection) -> None:
            await self._enqueue_execution_on_db(db, execution)

        await self._with_db_write(_op)

    async def _queue_claim_one(self) -> Optional[aiosqlite.Row]:
        """
        Atomically claim exactly one queued item by acquiring a lease.
        This prevents two workers from executing the same job.

        Changes vs original:
        - All DB writes happen inside _with_db_write() (=> DB_WRITE_LOCK + BEGIN IMMEDIATE + retry).
        - We keep the DB transaction short (select candidate + claim + fetch row/attempts).
        - emit_event() happens OUTSIDE the DB lock/transaction.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        lease_exp = (now + timedelta(seconds=int(self._lease_seconds))).isoformat()

        claimed: Optional[dict] = None

        async def _op(db: aiosqlite.Connection) -> Optional[dict]:
            # 1) pick candidate
            cur = await db.execute(
                """
                SELECT execution_id
                FROM runbook_queue
                WHERE status='queued'
                AND (available_at IS NULL OR available_at <= ?)
                AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                ORDER BY updated_at ASC
                LIMIT 1
                """,
                (now_iso, now_iso),
            )
            row = await cur.fetchone()
            await cur.close()
            if not row:
                return None

            ex_id = row["execution_id"]

            # 2) try to claim (atomic update)
            res = await db.execute(
                """
                UPDATE runbook_queue
                SET status='running',
                    attempts=attempts+1,
                    last_heartbeat=?,
                    updated_at=?,
                    lease_owner=?,
                    lease_expires_at=?
                WHERE execution_id=?
                AND status='queued'
                AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                AND (available_at IS NULL OR available_at <= ?)
                """,
                (
                    now_iso,
                    now_iso,
                    self._lease_owner,
                    lease_exp,
                    ex_id,
                    now_iso,
                    now_iso,
                ),
            )

            if getattr(res, "rowcount", 0) != 1:
                return None

            # 3) return full job row
            cur3 = await db.execute(
                """
                SELECT execution_id, runbook_name, incident_id, target_service, target_instance,
                    parameters_json, triggered_by
                FROM runbook_queue
                WHERE execution_id=?
                """,
                (ex_id,),
            )
            full = await cur3.fetchone()
            await cur3.close()

            # 4) read attempts + lease_expires_at (same tx, consistent)
            curA = await db.execute(
                "SELECT attempts, lease_expires_at FROM runbook_queue WHERE execution_id=?",
                (ex_id,),
            )
            a = await curA.fetchone()
            await curA.close()

            attempts = int(a["attempts"]) if a and a["attempts"] is not None else None
            lease_expires_at_db = a["lease_expires_at"] if a else None

            return {
                "full": full,
                "attempts": attempts,
                "lease_expires_at": lease_expires_at_db,
            }

        claimed = await self._with_db_write(_op)

        if not claimed:
            return None

        full = claimed["full"]
        attempts = claimed.get("attempts") or 1
        lease_expires_at_db = claimed.get("lease_expires_at")

        # OUTSIDE DB_WRITE_LOCK: emit event best-effort
        try:
            await emit_event(
                event_key=f"exec:{full['execution_id']}:queue_claim:{attempts}",
                event_type="runbook.queue.claimed",
                actor="worker",
                source="runbook_engine",
                severity="info",
                message="Queue item claimed (lease acquired)",
                incident_id=full["incident_id"] if full else None,
                execution_id=full["execution_id"],
                queue_execution_id=full["execution_id"],
                details={
                    "lease_owner": self._lease_owner,
                    "lease_expires_at": lease_expires_at_db,
                    "attempts": attempts,
                },
            )
        except Exception:
            pass

        return full

    async def _queue_worker_loop(self) -> None:
        """
        Hot consumer for the durable queue.
        Ensures lease_owner/lease_expires_at + heartbeat appear without restart.
        """
        while not self._queue_stop.is_set():
            try:
                # Avoid exceeding max concurrency
                async with self._lock:
                    inflight = len(self._tasks)
                if inflight >= int(settings.runbook_max_concurrent):
                    await asyncio.sleep(0.2)
                    continue

                job = await self._queue_claim_one()
                if not job:
                    # sleep or await kick
                    try:
                        await asyncio.wait_for(self._queue_wake.wait(), timeout=0.5)
                    except asyncio.TimeoutError:
                        pass
                    self._queue_wake.clear()
                    continue

                ex_id = job["execution_id"]

                # defensive: do not duplicate task
                async with self._lock:
                    if ex_id in self._tasks:
                        continue

                params = {}
                if job["parameters_json"]:
                    try:
                        params = json.loads(job["parameters_json"])
                    except Exception:
                        params = {}

                # Acquire semaphores like resume path
                await self._semaphore.acquire()
                svc = job["target_service"]
                if svc and svc in self._svc_semaphores:
                    await self._svc_semaphores[svc].acquire()
                    async with self._lock:
                        self._execution_svc_locks[ex_id] = svc

                t = asyncio.create_task(
                    self._run_execution_task(
                        execution_id=ex_id,
                        runbook_name=job["runbook_name"],
                        incident_id=job["incident_id"],
                        target_service=job["target_service"],
                        target_instance=job["target_instance"],
                        parameters=params,
                        triggered_by=job["triggered_by"] or "system",
                        skip_validation=False,
                    ),
                    name=f"runbook:q:{job['runbook_name']}:{ex_id}",
                )
                async with self._lock:
                    self._tasks[ex_id] = t

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("runbook_queue_worker_error", error=str(e))
                await asyncio.sleep(0.5)

    async def _queue_mark_running(self, execution_id: str) -> None:
        """
        Refresh lease/heartbeat for an already-claimed execution.
        IMPORTANT:
        - Does NOT transition queued->running (that's _queue_claim_one()).
        - Does NOT increment attempts (attempts are incremented only on claim).
        - Only refreshes if we still own the lease.
        """
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        lease_exp = (now_dt + timedelta(seconds=int(self._lease_seconds))).isoformat()

        async def _op(db):
            await db.execute(
                """
                UPDATE runbook_queue
                SET last_heartbeat=?,
                    updated_at=?,
                    lease_expires_at=?
                WHERE execution_id=?
                AND lease_owner=?
                AND status='running'
                """,
                (now, now, lease_exp, execution_id, self._lease_owner),
            )

        await self._with_db_write(_op)

    async def _queue_heartbeat(self, execution_id: str, stop: asyncio.Event) -> None:
        """
        Heartbeat/lease refresh loop for an already-claimed execution.

        Changes vs original:
        - Uses _with_db_write() for each heartbeat tick (=> DB_WRITE_LOCK + BEGIN IMMEDIATE + retry).
        - Keeps a short write transaction per tick (no long-lived DB connection).
        - Stops cleanly if the lease is lost (rowcount != 1).
        """
        while not stop.is_set():
            now_dt = datetime.now(timezone.utc)
            now_iso = now_dt.isoformat()
            lease_exp = (
                now_dt + timedelta(seconds=int(self._lease_seconds))
            ).isoformat()

            rowcount: int = 0

            async def _op(db: aiosqlite.Connection) -> int:
                cur = await db.execute(
                    """
                    UPDATE runbook_queue
                    SET last_heartbeat=?,
                        updated_at=?,
                        lease_expires_at=?
                    WHERE execution_id=?
                    AND lease_owner=?
                    AND status='running'
                    """,
                    (now_iso, now_iso, lease_exp, execution_id, self._lease_owner),
                )
                return int(getattr(cur, "rowcount", 0) or 0)

            try:
                rowcount = await self._with_db_write(_op)
            except Exception:
                # If DB is unhappy, don't kill the whole loop; just try again next tick.
                rowcount = 0

            # If we no longer own the lease, stop heartbeating.
            if rowcount != 1:
                break

            try:
                await asyncio.wait_for(
                    stop.wait(), timeout=float(self._queue_heartbeat_interval_s)
                )
            except asyncio.TimeoutError:
                continue

    async def _queue_mark_done(self, execution_id: str, dead: bool = False) -> None:
        now = datetime.now(timezone.utc).isoformat()
        st = "dead" if dead else "done"

        async def _op(db):
            await db.execute(
                """
                UPDATE runbook_queue
                SET status=?,
                    updated_at=?,
                    last_heartbeat=COALESCE(last_heartbeat, ?)
                WHERE execution_id=?
                """,
                (st, now, now, execution_id),
            )

        await self._with_db_write(_op)

    # ============================================================
    # Operator actions
    # ============================================================
    async def cancel_execution(self, execution_id: str, actor_id: str) -> dict:
        # 1) if running in memory, cancel task
        task = None
        async with self._lock:
            task = self._tasks.get(execution_id)
        if task:
            try:
                task.cancel()
            except Exception:
                pass

        # 2) persist "skipped" status (cancelled) and check dead queue
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "status": "skipped",
            "success": False,
            "message": "Execution cancelled by operator",
            "cancelled_by": actor_id,
            "cancelled_at": now,
        }
        ex = await self.get_execution(execution_id)
        if ex:
            ex.mark_skipped(json.dumps(payload, ensure_ascii=False))
            await self._persist_execution(ex)
        try:
            await self._queue_mark_done(execution_id, dead=True)
        except Exception:
            pass
        try:
            audit_logger.log(
                event_type="runbook_execution",
                actor=actor_id,
                resource_type="runbook_execution",
                resource_id=execution_id,
                action="cancel",
                details=payload,
                success=True,
            )
        except Exception:
            pass
        # Events + failure record (best-effort)
        try:
            await emit_event(
                event_key=f"exec:{execution_id}:final:cancelled",
                event_type="runbook.execution.cancelled",
                actor=actor_id,
                source="runbook_engine",
                severity="warning",
                message="Execution cancelled by operator",
                incident_id=(ex.incident_id if ex else None),
                execution_id=execution_id,
                details=payload,
            )
        except Exception:
            pass
        try:
            await record_failure(
                execution_id=execution_id,
                runbook_name=(ex.runbook_name if ex else None) or "unknown",
                failure_kind="cancelled",
                final_status="skipped",
                incident_id=(ex.incident_id if ex else None),
                target_service=(ex.target_service if ex else None),
                target_instance=(ex.target_instance if ex else None),
                execution_origin=getattr(ex, "execution_origin", None) if ex else None,
                retry_of_execution_id=getattr(ex, "retry_of_execution_id", None)
                if ex
                else None,
                error_message="cancelled_by_operator",
                details=payload,
            )
        except Exception:
            pass
        return {"ok": True, "execution_id": execution_id, "cancelled_at": now}

    # ============================================================
    # Execution worker task (actual run)
    # ============================================================
    async def _run_execution_task(
        self,
        execution_id: str,
        runbook_name: str,
        incident_id: Optional[str],
        target_service: Optional[str],
        target_instance: Optional[str],
        parameters: Dict[str, Any],
        triggered_by: str,
        skip_validation: bool,
    ) -> None:
        execution = await self.get_execution(execution_id)

        def ek(suffix: str) -> str:
            # strong idempotence: 1 event per phase per execution
            return f"exec:{execution_id}:{suffix}"

        if not execution:
            logger.warning("runbook_async_execution_missing", execution_id=execution_id)
            return

        # heartbeat handles
        hb_stop: Optional[asyncio.Event] = None
        hb_task: Optional[asyncio.Task] = None
        duration_ms: Optional[int] = None
        # used to build final payload consistently from finally block
        last_error: Optional[str] = None
        try:
            await emit_event(
                event_key=ek("task_started"),
                event_type="runbook.task.started",
                actor=triggered_by,
                source="runbook_engine",
                severity="info",
                message="Runbook async task started",
                incident_id=incident_id,
                execution_id=execution_id,
                queue_execution_id=execution_id,
                details={
                    "runbook": runbook_name,
                    "target_service": target_service,
                    "target_instance": target_instance,
                    "skip_validation": bool(skip_validation),
                },
            )
        except Exception:
            pass
        try:
            runbook_config = registry.get(runbook_name)
            if not runbook_config:
                execution.complete(
                    success=False,
                    error=f"Runbook '{runbook_name}' not found in registry",
                )
                await self._persist_execution(execution)
                try:
                    await emit_event(
                        event_key=ek("validation_registry_missing"),
                        event_type="runbook.validation.failed",
                        actor="system",
                        source="runbook_engine",
                        severity="error",
                        message="Runbook not found in registry",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        details={"runbook": runbook_name},
                    )
                except Exception:
                    pass

                try:
                    await record_failure(
                        execution_id=execution_id,
                        runbook_name=runbook_name,
                        failure_kind="validation",
                        final_status="error",
                        incident_id=incident_id,
                        target_service=target_service,
                        target_instance=target_instance,
                        execution_origin=getattr(execution, "execution_origin", None),
                        retry_of_execution_id=getattr(
                            execution, "retry_of_execution_id", None
                        ),
                        attempt_no=None,
                        is_final=True,
                        error_message=f"Runbook '{runbook_name}' not found in registry",
                        details={"stage": "registry_lookup"},
                    )
                except Exception:
                    pass
                return

            # --- confirmation guardrail ---
            requires_confirm = self.requires_confirmation(runbook_config)
            if requires_confirm and triggered_by not in ALLOWED_CONFIRM_TRIGGERS:
                # system/api should have been cut to PENDING upstream; this is extra defense
                execution.complete(
                    success=False,
                    error=f"Runbook '{runbook_name}' requires confirmation. Use /confirm flow.",
                )
                await self._persist_execution(execution)
                try:
                    await emit_event(
                        event_key=ek("validation_requires_confirmation"),
                        event_type="runbook.validation.failed",
                        actor="system",
                        source="runbook_engine",
                        severity="error",
                        message="Runbook requires confirmation (guardrail)",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        details={"runbook": runbook_name, "triggered_by": triggered_by},
                    )
                except Exception:
                    pass

                try:
                    await record_failure(
                        execution_id=execution_id,
                        runbook_name=runbook_name,
                        failure_kind="validation",  # requires_confirmation_guardrail
                        final_status="error",
                        incident_id=incident_id,
                        target_service=target_service,
                        target_instance=target_instance,
                        execution_origin=getattr(execution, "execution_origin", None),
                        retry_of_execution_id=getattr(
                            execution, "retry_of_execution_id", None
                        ),
                        attempt_no=None,
                        is_final=True,
                        error_message="requires_confirmation_guardrail",
                        details={"triggered_by": triggered_by},
                    )
                except Exception:
                    pass
                return
            # --- HARD validations (ALWAYS) ---
            hard_error = self._hard_validate_execution(
                runbook_name, target_service, triggered_by, incident_id
            )
            if hard_error:
                last_error = hard_error
                execution.complete(success=False, error=hard_error)
                await self._persist_execution(execution)
                try:
                    await emit_event(
                        event_key=ek("validation_hard_failed"),
                        event_type="runbook.validation.failed",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="error",
                        message="Hard validation failed",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        details={"runbook": runbook_name, "error": hard_error},
                    )
                except Exception:
                    pass
                try:
                    await record_failure(
                        execution_id=execution_id,
                        runbook_name=runbook_name,
                        failure_kind="validation",
                        final_status="error",
                        incident_id=incident_id,
                        target_service=target_service,
                        target_instance=target_instance,
                        execution_origin=getattr(execution, "execution_origin", None),
                        retry_of_execution_id=getattr(
                            execution, "retry_of_execution_id", None
                        ),
                        error_message=hard_error,
                        details={"stage": "hard_validation"},
                    )
                except Exception:
                    pass
                return
            # --- SOFT validations (optional) ---
            if not skip_validation:
                soft_error = self._soft_validate_execution(
                    runbook_name, target_service, triggered_by, incident_id
                )
                if soft_error:
                    last_error = soft_error
                    execution.complete(success=False, error=soft_error)
                    await self._persist_execution(execution)
                    try:
                        await emit_event(
                            event_key=ek("validation_soft_failed"),
                            event_type="runbook.validation.failed",
                            actor=triggered_by,
                            source="runbook_engine",
                            severity="warning",
                            message="Soft validation failed",
                            incident_id=incident_id,
                            execution_id=execution_id,
                            details={"runbook": runbook_name, "error": soft_error},
                        )
                    except Exception:
                        pass
                    try:
                        await record_failure(
                            execution_id=execution_id,
                            runbook_name=runbook_name,
                            failure_kind="validation",
                            final_status="error",
                            incident_id=incident_id,
                            target_service=target_service,
                            target_instance=target_instance,
                            execution_origin=getattr(
                                execution, "execution_origin", None
                            ),
                            retry_of_execution_id=getattr(
                                execution, "retry_of_execution_id", None
                            ),
                            error_message=soft_error,
                            details={"stage": "soft_validation"},
                        )
                    except Exception:
                        pass
                    return

            param_error = registry.validate_parameters(runbook_name, parameters)
            if param_error:
                last_error = param_error
                execution.complete(success=False, error=param_error)
                await self._persist_execution(execution)
                try:
                    await emit_event(
                        event_key=ek("validation_params_failed"),
                        event_type="runbook.validation.failed",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="error",
                        message="Parameter validation failed",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        details={"runbook": runbook_name, "error": param_error},
                    )
                except Exception:
                    pass
                try:
                    await record_failure(
                        execution_id=execution_id,
                        runbook_name=runbook_name,
                        failure_kind="validation",
                        final_status="error",
                        incident_id=incident_id,
                        target_service=target_service,
                        target_instance=target_instance,
                        execution_origin=getattr(execution, "execution_origin", None),
                        retry_of_execution_id=getattr(
                            execution, "retry_of_execution_id", None
                        ),
                        error_message=param_error,
                        details={"stage": "param_validation"},
                    )
                except Exception:
                    pass
                return

            # --- mark RUNNING ---
            execution.mark_running()
            await self._persist_execution(execution)
            try:
                await emit_event(
                    event_key=ek("running"),
                    event_type="runbook.execution.running",
                    actor=triggered_by,
                    source="runbook_engine",
                    severity="info",
                    message="Runbook marked RUNNING",
                    incident_id=incident_id,
                    execution_id=execution_id,
                    queue_execution_id=execution_id,
                    details={
                        "runbook": runbook_name,
                        "timeout_seconds": int(
                            runbook_config.timeout or settings.runbook_timeout
                        ),
                    },
                )
            except Exception:
                pass

            # durable queue: ensure row is running + start heartbeat
            try:
                await self._queue_mark_running(execution_id)
            except Exception:
                pass

            hb_stop = asyncio.Event()
            hb_task = asyncio.create_task(
                self._queue_heartbeat(execution_id, hb_stop),
                name=f"rbq-hb:{execution_id}",
            )

            timeout = runbook_config.timeout or settings.runbook_timeout
            start_time = time.time()

            try:
                exec_params = dict(parameters or {})
                if target_service:
                    exec_params["service"] = target_service
                if target_instance:
                    exec_params["instance"] = target_instance

                result = await asyncio.wait_for(
                    runbook_config.handler(**exec_params),
                    timeout=timeout,
                )

                duration_ms = int((time.time() - start_time) * 1000)

                if isinstance(result, dict):
                    rb_status = (result.get("status") or "").lower()
                    if rb_status == "skipped":
                        execution.mark_skipped(json.dumps(result, ensure_ascii=False))

                    else:
                        success = bool(result.get("success", True))
                        execution.complete(
                            success=success,
                            output=json.dumps(result, ensure_ascii=False),
                        )
                else:
                    execution.complete(success=True, output=str(result))

                audit_logger.runbook_executed(
                    runbook_name=runbook_name,
                    triggered_by=triggered_by,
                    incident_id=incident_id,
                    target=target_service,
                    success=execution.status == RunbookStatus.SUCCESS,
                    duration_ms=duration_ms,
                )

            except asyncio.TimeoutError:
                last_error = f"timeout after {timeout}s"
                execution.mark_timeout(f"Execution timed out after {timeout}s")
                audit_logger.runbook_executed(
                    runbook_name=runbook_name,
                    triggered_by=triggered_by,
                    incident_id=incident_id,
                    target=target_service,
                    success=False,
                    duration_ms=int((time.time() - start_time) * 1000),
                )

                await record_failure(
                    execution_id=execution_id,
                    runbook_name=runbook_name,
                    failure_kind="timeout",
                    final_status="timeout",
                    incident_id=incident_id,
                    target_service=target_service,
                    target_instance=target_instance,
                    execution_origin=getattr(execution, "execution_origin", None),
                    retry_of_execution_id=getattr(
                        execution, "retry_of_execution_id", None
                    ),
                    error_message=f"timeout after {timeout}s",
                    details={"timeout_seconds": timeout},
                )

        except Exception as e:
            last_error = str(e)
            execution.complete(success=False, error=str(e))
            logger.exception(
                "runbook_execution_async_exception",
                execution_id=execution_id,
                runbook=runbook_name,
                error=str(e),
            )

            await record_failure(
                execution_id=execution_id,
                runbook_name=runbook_name,
                failure_kind="exception",
                final_status="failed",
                incident_id=incident_id,
                target_service=target_service,
                target_instance=target_instance,
                execution_origin=getattr(execution, "execution_origin", None),
                retry_of_execution_id=getattr(execution, "retry_of_execution_id", None),
                error_message=str(e),
            )

        finally:
            # normalize final status ONCE (avoid undefined st)
            try:
                st = str(getattr(execution.status, "value", execution.status)).lower()

            except Exception:
                st = "failed"
            # Emit exactly ONE terminal event from here (single source of truth)
            try:
                details = {
                    "runbook": runbook_name,
                    "target_service": target_service,
                    "target_instance": target_instance,
                }
                if duration_ms is not None:
                    details["duration_ms"] = duration_ms
                if last_error:
                    details["error"] = last_error

                if st == "success":
                    await emit_event(
                        event_key=ek("final:success"),
                        event_type="runbook.execution.completed",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="info",
                        message="Execution completed",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        queue_execution_id=execution_id,
                        details=details,
                    )
                elif st == "skipped":
                    await emit_event(
                        event_key=ek("final:skipped"),
                        event_type="runbook.execution.skipped",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="warning",
                        message="Execution skipped",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        queue_execution_id=execution_id,
                        details=details,
                    )
                elif st == "timeout":
                    await emit_event(
                        event_key=ek("final:timeout"),
                        event_type="runbook.execution.timeout",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="error",
                        message="Execution timed out",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        queue_execution_id=execution_id,
                        details=details,
                    )
                else:
                    await emit_event(
                        event_key=ek("final:failed"),
                        event_type="runbook.execution.failed",
                        actor=triggered_by,
                        source="runbook_engine",
                        severity="error",
                        message="Execution failed",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        queue_execution_id=execution_id,
                        details=details,
                    )
            except Exception:
                pass

            # stop heartbeat
            if hb_stop is not None:
                try:
                    hb_stop.set()
                except Exception:
                    pass
            if hb_task is not None:
                try:
                    hb_task.cancel()
                    await asyncio.gather(hb_task, return_exceptions=True)
                except Exception:
                    pass

            # rate limit (system)
            try:
                if triggered_by == "system":
                    if runbook_name == "health_check":
                        key = (
                            f"{runbook_name}:incident:{incident_id}"
                            if incident_id
                            else None
                        )
                    else:
                        key = (
                            f"{runbook_name}:{target_service}"
                            if target_service
                            else runbook_name
                        )
                    if key:
                        self._rate_limit[key] = datetime.now(timezone.utc)
            except Exception:
                pass

            # metrics
            try:
                metrics_collector.record_runbook_execution(
                    runbook=execution.runbook_name,
                    status=("error" if st == "failed" else st),
                    triggered_by=triggered_by,
                    duration_seconds=execution.duration_seconds,
                )
            except Exception:
                pass

            # persist final execution
            try:
                await self._persist_execution(execution)
            except Exception:
                pass

            # mark queue done/dead
            try:
                await self._queue_mark_done(
                    execution_id, dead=(st in ("failed", "timeout"))
                )
            except Exception:
                pass

            # ------------------------------------------------------------
            # Retry policy (ONLY for non-confirmable runbooks)
            # - fail-closed: if we can't decide, do NOT retry
            # ------------------------------------------------------------
            retry_allowed = False
            try:
                cfg_retry = registry.get(runbook_name)
                retry_allowed = not self.requires_confirmation(cfg_retry)
            except Exception:
                retry_allowed = False

            scheduled_retry = False

            if retry_allowed and st in ("failed", "timeout"):
                try:
                    # attempts is tracked in queue row (incremented on claim)
                    db = await self._db()
                    try:
                        cur = await db.execute(
                            "SELECT attempts FROM runbook_queue WHERE execution_id=? LIMIT 1",
                            (execution_id,),
                        )
                        row = await cur.fetchone()
                        await cur.close()
                    finally:
                        await db.close()

                    attempts = (
                        int(row["attempts"])
                        if row and row["attempts"] is not None
                        else 1
                    )

                    if attempts <= int(self._max_retries):
                        backoff = self._retry_backoff_seconds(attempts)

                        retry_ex = RunbookExecution(
                            runbook_name=runbook_name,
                            incident_id=incident_id,
                            target_service=target_service,
                            target_instance=target_instance,
                            parameters=parameters or {},
                            triggered_by=triggered_by,
                            execution_origin="recovery",
                            retry_of_execution_id=execution_id,
                        )

                        await self._persist_execution(retry_ex)
                        await self._enqueue_execution(retry_ex)
                        scheduled_retry = True

                        # ensure queue metadata + backoff
                        try:
                            dbm = await self._db()
                            try:
                                now_dt = datetime.now(timezone.utc)
                                avail = (
                                    now_dt + timedelta(seconds=int(backoff))
                                ).isoformat()
                                await dbm.execute(
                                    """
                                    UPDATE runbook_queue
                                    SET retry_of_execution_id=?,
                                        execution_origin=?,
                                        available_at=?,
                                        updated_at=?
                                    WHERE execution_id=?
                                    """,
                                    (
                                        execution_id,
                                        getattr(retry_ex, "execution_origin", None),
                                        avail,
                                        now_dt.isoformat(),
                                        retry_ex.id,
                                    ),
                                )
                                await dbm.commit()
                            finally:
                                await dbm.close()
                        except Exception:
                            pass

                        try:
                            metrics_collector.record_runbook_retried(
                                runbook_name, reason=st
                            )
                        except Exception:
                            pass
                        try:
                            audit_logger.log(
                                event_type="runbook_execution",
                                actor="system",
                                resource_type="runbook_execution",
                                resource_id=retry_ex.id,
                                action="retry_scheduled",
                                details={
                                    "retry_of": execution_id,
                                    "attempts": attempts,
                                    "backoff_seconds": backoff,
                                    "reason": st,
                                },
                                success=True,
                            )
                            await emit_event(
                                event_key=f"exec:{retry_ex.id}:retry_scheduled",
                                event_type="runbook.execution.retry_scheduled",
                                actor="system",
                                source="runbook_engine",
                                severity="warning",
                                message="Retry scheduled",
                                incident_id=incident_id,
                                execution_id=retry_ex.id,
                                details={
                                    "retry_of": execution_id,
                                    "attempts": attempts,
                                    "backoff_seconds": backoff,
                                    "reason": st,
                                },
                            )
                        except Exception:
                            pass

                except Exception:
                    # swallow retry scheduling errors (engine must not crash)
                    pass

                if not scheduled_retry:
                    try:
                        metrics_collector.record_runbook_failed_final(
                            runbook_name, reason=st
                        )
                        try:
                            await emit_event(
                                event_key=ek(f"failed_final:{st}"),
                                event_type="runbook.execution.failed_final",
                                actor="system",
                                source="runbook_engine",
                                severity="error",
                                message="Runbook failed final (no more retries)",
                                incident_id=incident_id,
                                execution_id=execution_id,
                                details={"runbook": runbook_name, "reason": st},
                            )
                        except Exception:
                            pass

                        try:
                            await record_failure(
                                execution_id=execution_id,
                                runbook_name=runbook_name,
                                failure_kind="non_success",  # para failed_final
                                final_status=(
                                    "timeout" if st == "timeout" else "error"
                                ),
                                incident_id=incident_id,
                                target_service=target_service,
                                target_instance=target_instance,
                                execution_origin=getattr(
                                    execution, "execution_origin", None
                                ),
                                retry_of_execution_id=getattr(
                                    execution, "retry_of_execution_id", None
                                ),
                                attempt_no=None,
                                is_final=True,
                                error_message=f"failed_final:{st}",
                                details={"max_retries": int(self._max_retries)},
                            )
                        except Exception:
                            pass

                    except Exception:
                        pass

            # attach to incident (best-effort)
            if incident_id:
                try:
                    from src.incidents.incident_manager import incident_manager

                    await incident_manager.add_execution_to_incident(
                        incident_id, execution
                    )
                except Exception:
                    pass

            # cleanup task bookkeeping
            try:
                async with self._lock:
                    self._tasks.pop(execution_id, None)
            except Exception:
                pass

            # release concurrency slot(s)
            try:
                self._semaphore.release()
            except Exception:
                pass
            try:
                svc = None
                async with self._lock:
                    svc = self._execution_svc_locks.pop(execution_id, None)
                if svc and svc in self._svc_semaphores:
                    self._svc_semaphores[svc].release()
            except Exception:
                pass

    # ============================================================
    # Persistence: execution row UPSERT
    # ============================================================
    async def _persist_execution(self, execution: RunbookExecution) -> None:
        """
        Idempotent UPSERT execution row (source of truth: runbook_executions).
        NOTE: keep schema as-is; if you later add execution_origin / retry_of_execution_id
        columns, you can extend this safely.
        """

        async def _op(db):
            await self._persist_execution_on_db(db, execution)

        await self._with_db_write(_op)

    # ============================================================
    # Sync execution API (legacy path)
    # ============================================================
    async def execute(
        self,
        runbook_name: str,
        incident_id: Optional[str] = None,
        target_service: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        triggered_by: str = "system",
        skip_validation: bool = False,
    ) -> RunbookExecution:
        parameters = parameters or {}

        execution = RunbookExecution(
            runbook_name=runbook_name,
            incident_id=incident_id,
            target_service=target_service,
            parameters=parameters,
            triggered_by=triggered_by,
        )

        logger.info(
            "runbook_execution_started",
            execution_id=execution.id,
            runbook=runbook_name,
            incident_id=incident_id,
            target_service=target_service,
            triggered_by=triggered_by,
        )

        # save the record now so you can consult it as RUNNING
        async with self._lock:
            self._executions[execution.id] = execution
            self._update_queue_metrics()
        await self._persist_execution(execution)

        try:
            runbook_config = registry.get(runbook_name)
            if not runbook_config:
                execution.complete(
                    success=False,
                    error=f"Runbook '{runbook_name}' not found in registry",
                )
                async with self._lock:
                    self._update_queue_metrics()
                await self._persist_execution(execution)
                return execution

            # Guardrail: Block actual execution if it requires confirmation (or dangerous+flag)

            requires_confirm = bool(
                runbook_config.requires_confirmation
                or (
                    getattr(settings, "runbook_require_confirmation", False)
                    and runbook_config.dangerous
                )
            )

            # If it requires confirmation and comes from system or api -> PENDING
            if requires_confirm and triggered_by in ("system", "api"):
                execution.mark_pending(
                    json.dumps(
                        {
                            "status": "pending",
                            "success": False,
                            "message": f"Runbook '{runbook_name}' requires confirmation",
                        },
                        ensure_ascii=False,
                    )
                )
                # Traceability "minute 0" we record audit event when the PENDING is born
                try:
                    audit_logger.log(
                        event_type="runbook_confirmation",
                        actor=triggered_by,
                        resource_type="runbook_execution",
                        resource_id=execution.id,
                        action="pending_created",
                        details={
                            "incident_id": incident_id,
                            "runbook": runbook_name,
                            "target_service": target_service,
                            "target_instance": execution.target_instance,
                        },
                        success=True,
                    )
                except Exception:
                    pass
                async with self._lock:
                    self._executions[execution.id] = execution
                    self._update_queue_metrics()
                await self._persist_execution(execution)
                return execution
            # If it requires confirmation and does NOT come from human flow -> block
            if requires_confirm and triggered_by not in ALLOWED_CONFIRM_TRIGGERS:
                execution.complete(
                    success=False,
                    error=f"Runbook '{runbook_name}' requires confirmation. Use /confirm flow.",
                )
                async with self._lock:
                    self._update_queue_metrics()
                await self._persist_execution(execution)
                return execution

            if not skip_validation:
                validation_error = self._validate_execution(
                    runbook_name, target_service, triggered_by, incident_id
                )
                if validation_error:
                    execution.complete(success=False, error=validation_error)
                    logger.warning(
                        "runbook_validation_failed",
                        runbook=runbook_name,
                        error=validation_error,
                    )
                    async with self._lock:
                        self._update_queue_metrics()
                    await self._persist_execution(execution)
                    return execution

            # Validation of parameters allowed by the registry
            param_error = registry.validate_parameters(runbook_name, parameters)
            if param_error:
                execution.complete(success=False, error=param_error)
                logger.warning(
                    "runbook_parameters_invalid",
                    runbook=runbook_name,
                    error=param_error,
                )
                async with self._lock:
                    self._update_queue_metrics()
                await self._persist_execution(execution)
                return execution
            async with self._lock:
                execution.mark_running()
                self._update_queue_metrics()
            await self._persist_execution(execution)
            timeout = runbook_config.timeout or settings.runbook_timeout

            start_time = time.time()

            try:
                exec_params = dict(parameters)
                if target_service:
                    exec_params["service"] = target_service

                result = await asyncio.wait_for(
                    runbook_config.handler(**exec_params),
                    timeout=timeout,
                )

                duration_ms = int((time.time() - start_time) * 1000)

                # Process result
                if isinstance(result, dict):
                    rb_status = (result.get("status") or "").lower()

                    if rb_status == "skipped":
                        execution.mark_skipped(json.dumps(result, ensure_ascii=False))
                    else:
                        success = bool(result.get("success", True))
                        payload = json.dumps(result, ensure_ascii=False)
                        execution.complete(success=success, output=payload)
                else:
                    execution.complete(success=True, output=str(result))

                logger.info(
                    "runbook_execution_completed",
                    execution_id=execution.id,
                    runbook=runbook_name,
                    success=execution.status == RunbookStatus.SUCCESS,
                    duration_ms=duration_ms,
                )

                audit_logger.runbook_executed(
                    runbook_name=runbook_name,
                    triggered_by=triggered_by,
                    incident_id=incident_id,
                    target=target_service,
                    success=execution.status == RunbookStatus.SUCCESS,
                    duration_ms=duration_ms,
                )

            except asyncio.TimeoutError:
                execution.mark_timeout(f"Execution timed out after {timeout}s")

                logger.error(
                    "runbook_execution_timeout",
                    execution_id=execution.id,
                    runbook=runbook_name,
                    timeout=timeout,
                )

                audit_logger.runbook_executed(
                    runbook_name=runbook_name,
                    triggered_by=triggered_by,
                    incident_id=incident_id,
                    target=target_service,
                    success=False,
                    duration_ms=int((time.time() - start_time) * 1000),
                )

        except Exception as e:
            execution.complete(success=False, error=str(e))
            logger.exception(
                "runbook_execution_exception",
                execution_id=execution.id,
                runbook=runbook_name,
                error=str(e),
            )

        # Update rate limit (solo para auto-ejecución del sistema)
        async with self._lock:
            if triggered_by == "system":
                if runbook_name == "health_check":
                    if incident_id:
                        key = f"{runbook_name}:incident:{incident_id}"
                    else:
                        if runbook_name == "health_check" and not incident_id:
                            logger.warning(
                                "health_check_without_incident_id",
                                triggered_by=triggered_by,
                            )
                        key = None
                else:
                    key = (
                        f"{runbook_name}:{target_service}"
                        if target_service
                        else runbook_name
                    )

                if key:
                    self._rate_limit[key] = datetime.now(timezone.utc)
        async with self._lock:
            self._update_queue_metrics()
        await self._persist_execution(execution)
        return execution

    async def execute_for_incident(
        self,
        incident: Incident,
        suggested_runbooks: Optional[List[str]] = None,
    ) -> List[RunbookExecution]:
        if not settings.runbook_auto_execute:
            logger.info("auto_execute_disabled", incident_id=incident.id)
            return []

        executions: List[RunbookExecution] = []
        runbooks_to_try = list(suggested_runbooks or [])

        if not runbooks_to_try:
            runbooks_to_try.append("health_check")

        for runbook_name in runbooks_to_try:
            cfg = registry.get(runbook_name)
            requires_confirm = bool(
                cfg
                and (
                    cfg.requires_confirmation
                    or (
                        getattr(settings, "runbook_require_confirmation", False)
                        and getattr(cfg, "dangerous", False)
                    )
                )
            )

            target = None if runbook_name == "health_check" else incident.service

            # 1) If confirmation required: We ALWAYS create PENDING (only once)
            if requires_confirm:
                existing = await self._get_existing_pending(
                    incident_id=incident.id,
                    runbook_name=runbook_name,
                    target_service=target,
                )
                if existing:
                    executions.append(existing)
                    continue

                execution = await self.execute_async(
                    runbook_name=runbook_name,
                    incident_id=incident.id,
                    target_service=target,
                    triggered_by="system",
                )
                executions.append(execution)
                continue

            # 2) If you do NOT require confirmation: we respect severity
            if not registry.can_auto_execute(runbook_name, incident.severity):
                logger.debug(
                    "skipping_runbook_severity",
                    runbook=runbook_name,
                    incident_severity=incident.severity.value,
                )
                continue

            execution = await self.execute_async(
                runbook_name=runbook_name,
                incident_id=incident.id,
                target_service=target,
                triggered_by="system",
            )
            executions.append(execution)

        return executions

    # ============================================================
    # Validation (hard/soft + compatibility wrapper)
    # ============================================================
    def _hard_validate_execution(
        self,
        runbook_name: str,
        target_service: Optional[str],
        triggered_by: str,
        incident_id: Optional[str] = None,
    ) -> Optional[str]:
        # 1) runbook allowlist (registry)
        if not registry.is_allowed(runbook_name):
            return f"Runbook '{runbook_name}' is not in the allowlist"

        # 2) target service allowlist (global + per-runbook via registry.can_target_service)
        if target_service and not registry.can_target_service(
            runbook_name, target_service
        ):
            return f"Runbook '{runbook_name}' cannot target service '{target_service}'"

        # 3) confirmation guardrail (hard)
        cfg = registry.get(runbook_name)
        if cfg:
            requires_confirm = self.requires_confirmation(cfg)
            if requires_confirm and triggered_by not in ALLOWED_CONFIRM_TRIGGERS:
                # IMPORTANT:
                # Allow actors that create PENDING reservations (not execution).
                # These actors will be handled by execute_async pending flow.
                actor = (triggered_by or "").lower()

                if actor in ("system", "api", "telegram"):
                    # allow creation of PENDING execution
                    return None

                # other actors must not bypass confirmation
                return (
                    f"Runbook '{runbook_name}' requires confirmation. "
                    "Use /confirm flow."
                )

        return None

    def _soft_validate_execution(
        self,
        runbook_name: str,
        target_service: Optional[str],
        triggered_by: str,
        incident_id: Optional[str] = None,
    ) -> Optional[str]:
        # Rate limiting only for system auto executions
        if triggered_by == "system":
            if runbook_name == "health_check":
                if not incident_id:
                    return None
                key = f"{runbook_name}:incident:{incident_id}"
            else:
                key = (
                    f"{runbook_name}:{target_service}"
                    if target_service
                    else runbook_name
                )

            last_exec = self._rate_limit.get(key)
            if last_exec:
                seconds_since = (datetime.now(timezone.utc) - last_exec).total_seconds()
                if seconds_since < self._rate_limit_seconds:
                    wait_s = int(self._rate_limit_seconds - seconds_since)
                    return f"Rate limited: wait {wait_s}s"

        return None

    def _validate_execution(
        self,
        runbook_name: str,
        target_service: Optional[str],
        triggered_by: str,
        incident_id=None,
    ) -> Optional[str]:
        """
        Compatibility wrapper:
        - Hard guards (security) ALWAYS take precedence.
        - Soft guards (operational) run only if hard passes.
        """
        hard = self._hard_validate_execution(
            runbook_name=runbook_name,
            target_service=target_service,
            triggered_by=triggered_by,
            incident_id=incident_id,
        )
        if hard:
            return hard

        return self._soft_validate_execution(
            runbook_name=runbook_name,
            target_service=target_service,
            triggered_by=triggered_by,
            incident_id=incident_id,
        )

    # ============================================================
    # Queries / listing / stats
    # ============================================================
    async def get_execution(self, execution_id: str) -> Optional[RunbookExecution]:
        # 1) memory (fast path)
        if execution_id in self._executions:
            return self._executions[execution_id]

        # 2) DB (source of truth)
        db = await self._db()
        try:
            cur = await db.execute(
                """
                    SELECT
                    id, incident_id, runbook_name, status, triggered_by,
                    target_service, target_instance, parameters_json,
                    output, error, started_at, completed_at, duration_seconds,
                    confirmed_execution_id, confirmed_by, confirmed_at
                    FROM runbook_executions
                    WHERE id = ?
                    """,
                (execution_id,),
            )
            row = await cur.fetchone()
            await cur.close()
            if not row:
                return None
            return self._row_to_execution(row)
        finally:
            await db.close()

    async def get_recent_executions(
        self,
        limit: int = 20,
        runbook_name: Optional[str] = None,
    ) -> List[RunbookExecution]:
        if limit <= 0:
            limit = 20
        limit = min(limit, 500)

        where = ""
        params: list = []
        if runbook_name:
            where = "WHERE runbook_name = ?"
            params.append(runbook_name)

        db = await self._db()
        try:
            cur = await db.execute(
                f"""
                SELECT
                  id, incident_id, runbook_name, status, triggered_by,
                  target_service, target_instance, parameters_json,
                  output, error, started_at, completed_at, duration_seconds,
                  confirmed_execution_id, confirmed_by, confirmed_at
                FROM runbook_executions
                {where}
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (*params, limit),
            )
            rows = await cur.fetchall()
            await cur.close()
            return [self._row_to_execution(r) for r in rows]
        finally:
            await db.close()

    async def get_statistics(self) -> dict:
        executions = list(self._executions.values())

        today = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today_executions = [e for e in executions if e.started_at >= today]

        by_status = {status.value: 0 for status in RunbookStatus}
        for e in today_executions:
            by_status[e.status.value] = by_status.get(e.status.value, 0) + 1

        by_runbook: Dict[str, int] = {}
        for e in today_executions:
            by_runbook[e.runbook_name] = by_runbook.get(e.runbook_name, 0) + 1

        return {
            "total": len(executions),
            "today": len(today_executions),
            "by_status": by_status,
            "by_runbook": by_runbook,
        }

    async def _get_existing_pending(
        self,
        incident_id: str,
        runbook_name: str,
        target_service: Optional[str] = None,
    ) -> Optional[RunbookExecution]:
        """
        Idempotencia: si ya existe una ejecución PENDING para este (incident, runbook, target),
        la devolvemos en vez de crear otra.
        """
        db = await self._db()
        try:
            cur = await db.execute(
                """
                SELECT
                  id, incident_id, runbook_name, status, triggered_by,
                  target_service, target_instance, parameters_json,
                  output, error, started_at, completed_at, duration_seconds,
                  confirmed_execution_id, confirmed_by, confirmed_at
                FROM runbook_executions
                WHERE incident_id = ?
                  AND runbook_name = ?
                  AND status = 'pending'
                  AND (target_service = ? OR (? IS NULL AND target_service IS NULL))
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (incident_id, runbook_name, target_service, target_service),
            )
            row = await cur.fetchone()
            await cur.close()
            if not row:
                return None
            ex = self._row_to_execution(row)
            # cache in memory for fast-path
            async with self._lock:
                self._executions[ex.id] = ex
                self._update_queue_metrics()
            return ex
        finally:
            await db.close()

    def list_available_runbooks(self) -> List[dict]:
        return [
            {
                "name": rb.name,
                "description": rb.description,
                "category": rb.category,
                "auto_execute": rb.auto_execute,
                "requires_confirmation": rb.requires_confirmation,
                "dangerous": rb.dangerous,
            }
            for rb in registry.list_runbooks()
        ]

    def _update_queue_metrics(self):
        # DB is the source of truth for RUNBOOKS_PENDING/RUNBOOKS_RUNNING.
        # Gauges refresh themselves in MetricsCollector.start_runbook_queue_metrics_loop().
        # leave this method for compatibility, but we do not push metrics from RAM
        return

    async def list_pending_confirmations(
        self,
        *,
        limit: int = 50,
        incident_id: Optional[str] = None,
    ) -> list[dict]:
        limit = max(1, min(int(limit or 50), 200))

        where = "WHERE lower(status)='pending'"
        params: list = []

        if incident_id:
            where += " AND incident_id = ?"
            params.append(incident_id)

        db = await self._db()
        try:
            cur = await db.execute(
                f"""
                SELECT
                    id,
                    incident_id,
                    runbook_name,
                    triggered_by,
                    target_service,
                    target_instance,
                    started_at,
                    output
                FROM runbook_executions
                {where}
                -- SQLite-friendly NULL handling:
                ORDER BY (started_at IS NULL) ASC, started_at ASC
                LIMIT ?
                """,
                (*params, limit),
            )
            rows = await cur.fetchall()
            await cur.close()

            out: list[dict] = []
            for r in rows:
                out.append(
                    {
                        "execution_id": r["id"],
                        "incident_id": r["incident_id"],
                        "runbook": r["runbook_name"],
                        "triggered_by": r["triggered_by"] or "system",
                        "target_service": r["target_service"],
                        "target_instance": r["target_instance"],
                        "started_at": r["started_at"],
                        "output": (r["output"] or ""),
                    }
                )
            return out
        finally:
            await db.close()

    async def reconcile_inflight_confirmations_from_db(self) -> dict:
        """
        Same behavior, but fixed locking/transactions:

        - READ phase: no DB_WRITE_LOCK (cheap, doesn't block writers).
        - WRITE phase: every UPDATE goes through _with_db_write()
        (=> DB_WRITE_LOCK + BEGIN IMMEDIATE + retries + single short tx).
        - No await emit_event / record_failure inside DB_WRITE_LOCK (none here anyway).
        - Avoid holding one connection for the whole loop; we do small atomic writes.
        """

        def _now_iso() -> str:
            return datetime.now(timezone.utc).isoformat()

        def _status_from_execution_status(st: str) -> str:
            s = (st or "").lower()
            if s == "failed":
                return "error"
            if s in ("success", "skipped", "error"):
                return s
            if s == "timeout":
                return "error"
            return "error"

        # -------------------------
        # 1) READ pending confirmations (no lock)
        # -------------------------
        db = await self._db()
        try:
            cur = await db.execute(
                """
                SELECT
                pending_execution_id, incident_id, runbook_name, actor_id,
                status, confirmed_execution_id, created_at, updated_at, result_json
                FROM runbook_confirmations
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 500
                """
            )
            rows = await cur.fetchall()
            await cur.close()
        finally:
            await db.close()

        if not rows:
            return {
                "pending_confirmations": 0,
                "fixed": 0,
                "marked_error": 0,
                "marked_skipped": 0,
                "untouched": 0,
            }

        fixed = 0
        marked_error = 0
        marked_skipped = 0
        untouched = 0

        # helper: fetch one execution row (no lock)
        async def _fetch_execution_row(execution_id: str) -> Optional[aiosqlite.Row]:
            dbx = await self._db()
            try:
                curx = await dbx.execute(
                    """
                    SELECT
                    id, incident_id, runbook_name, status, triggered_by,
                    target_service, target_instance, parameters_json,
                    output, error, started_at, completed_at, duration_seconds,
                    confirmed_execution_id, confirmed_by, confirmed_at
                    FROM runbook_executions
                    WHERE id = ?
                    LIMIT 1
                    """,
                    (execution_id,),
                )
                rx = await curx.fetchone()
                await curx.close()
                return rx
            finally:
                await dbx.close()

        # -------------------------
        # 2) Loop: decide with reads, then apply minimal writes with _with_db_write
        # -------------------------
        for r in rows:
            pending_id = r["pending_execution_id"]
            actor_id = r["actor_id"]
            created_at = r["created_at"]

            # Fetch pending execution row (source of truth)
            pend_row = await _fetch_execution_row(pending_id)

            if not pend_row:
                # orphan confirmation: mark error
                now_iso = _now_iso()
                payload = {
                    "success": False,
                    "already_confirmed": False,
                    "pending_execution_id": pending_id,
                    "confirmed_execution_id": None,
                    "execution": None,
                    "runbook_status": "error",
                    "message": "Recovery: pending execution row missing; cannot reconcile confirmation.",
                    "status": "error",
                }

                async def _op(dbw):
                    await dbw.execute(
                        """
                        UPDATE runbook_confirmations
                        SET status='error', confirmed_execution_id=NULL, updated_at=?, result_json=?
                        WHERE pending_execution_id=? AND status='pending'
                        """,
                        (now_iso, json.dumps(payload, default=str), pending_id),
                    )

                await self._with_db_write(_op)
                marked_error += 1
                continue

            pend_status = (pend_row["status"] or "").lower()
            pend_confirmed_id = pend_row["confirmed_execution_id"]

            # If the pending execution is no longer pending, mark confirmation skipped.
            if pend_status != "pending":
                now_iso = _now_iso()
                payload = {
                    "success": False,
                    "already_confirmed": False,
                    "pending_execution_id": pending_id,
                    "confirmed_execution_id": pend_confirmed_id,
                    "execution": None,
                    "runbook_status": "skipped",
                    "message": (
                        "Recovery: pending execution is no longer pending "
                        f"(status={pend_status}). Confirmation marked as skipped."
                    ),
                    "status": "skipped",
                }

                async def _op(dbw):
                    await dbw.execute(
                        """
                        UPDATE runbook_confirmations
                        SET status='skipped', confirmed_execution_id=?, updated_at=?, result_json=?
                        WHERE pending_execution_id=? AND status='pending'
                        """,
                        (
                            pend_confirmed_id,
                            now_iso,
                            json.dumps(payload, default=str),
                            pending_id,
                        ),
                    )

                await self._with_db_write(_op)
                marked_skipped += 1
                continue

            # Pending is still pending.
            if pend_confirmed_id:
                conf_row = await _fetch_execution_row(pend_confirmed_id)

                if not conf_row:
                    now_iso = _now_iso()
                    payload = {
                        "success": False,
                        "already_confirmed": False,
                        "pending_execution_id": pending_id,
                        "confirmed_execution_id": pend_confirmed_id,
                        "execution": None,
                        "runbook_status": "error",
                        "message": "Recovery: confirmed execution row missing; cannot rebuild confirmation payload.",
                        "status": "error",
                    }

                    async def _op(dbw):
                        await dbw.execute(
                            """
                            UPDATE runbook_confirmations
                            SET status='error', confirmed_execution_id=?, updated_at=?, result_json=?
                            WHERE pending_execution_id=? AND status='pending'
                            """,
                            (
                                pend_confirmed_id,
                                now_iso,
                                json.dumps(payload, default=str),
                                pending_id,
                            ),
                        )

                    await self._with_db_write(_op)
                    marked_error += 1
                    continue

                # Build execution dump
                conf_d = dict(conf_row)
                params_obj = {}
                if conf_d.get("parameters_json"):
                    try:
                        params_obj = json.loads(conf_d["parameters_json"])
                    except Exception:
                        params_obj = {}

                execution_dump = {
                    "id": conf_d["id"],
                    "incident_id": conf_d.get("incident_id"),
                    "runbook_name": conf_d.get("runbook_name"),
                    "status": (conf_d.get("status") or "").lower(),
                    "triggered_by": conf_d.get("triggered_by") or "human",
                    "target_service": conf_d.get("target_service"),
                    "target_instance": conf_d.get("target_instance"),
                    "parameters": params_obj,
                    "output": conf_d.get("output") or "",
                    "error": conf_d.get("error"),
                    "started_at": conf_d.get("started_at"),
                    "completed_at": conf_d.get("completed_at"),
                    "duration_seconds": conf_d.get("duration_seconds"),
                }

                st = _status_from_execution_status(execution_dump["status"])
                is_ok = st in ("success", "skipped")

                now_iso = _now_iso()
                payload = {
                    "success": is_ok,
                    "already_confirmed": True,
                    "pending_execution_id": pending_id,
                    "confirmed_execution_id": pend_confirmed_id,
                    "execution": execution_dump,
                    "runbook_status": st,
                    "message": "Recovery: confirmation reconciled after restart (rebuilt persisted payload).",
                    "status": st,
                }

                # Keep confirmed_* fields consistent on pending execution row too.
                # Use created_at as fallback for confirmed_at.
                conf_at = pend_row["confirmed_at"] or created_at or now_iso
                conf_by = actor_id

                async def _op(dbw):
                    await dbw.execute(
                        """
                        UPDATE runbook_confirmations
                        SET status=?, confirmed_execution_id=?, updated_at=?, result_json=?
                        WHERE pending_execution_id=? AND status='pending'
                        """,
                        (
                            st,
                            pend_confirmed_id,
                            now_iso,
                            json.dumps(payload, default=str),
                            pending_id,
                        ),
                    )

                    # Only set if missing (COALESCE)
                    await dbw.execute(
                        """
                        UPDATE runbook_executions
                        SET confirmed_by = COALESCE(confirmed_by, ?),
                            confirmed_at = COALESCE(confirmed_at, ?)
                        WHERE id = ?
                        """,
                        (conf_by, conf_at, pending_id),
                    )

                await self._with_db_write(_op)

                # invalidate RAM cache to avoid stale fast-path
                try:
                    await self.invalidate_execution_cache(pending_id)
                except Exception:
                    pass

                fixed += 1
                continue

            # No confirmed_execution_id => cannot safely recover, mark confirmation error.
            now_iso = _now_iso()
            payload = {
                "success": False,
                "already_confirmed": False,
                "pending_execution_id": pending_id,
                "confirmed_execution_id": None,
                "execution": None,
                "runbook_status": "error",
                "message": (
                    "Recovery: confirmation was reserved but execution never started (no confirmed_execution_id). "
                    "Requires re-confirm to safely apply parameters."
                ),
                "status": "error",
            }

            async def _op(dbw):
                await dbw.execute(
                    """
                    UPDATE runbook_confirmations
                    SET status='error', confirmed_execution_id=NULL, updated_at=?, result_json=?
                    WHERE pending_execution_id=? AND status='pending'
                    """,
                    (now_iso, json.dumps(payload, default=str), pending_id),
                )

            await self._with_db_write(_op)
            marked_error += 1

        return {
            "pending_confirmations": len(rows),
            "fixed": fixed,
            "marked_error": marked_error,
            "marked_skipped": marked_skipped,
            "untouched": untouched,
        }

    async def resume_durable_queue_from_db(self) -> dict:
        """
        SRE-grade recovery:
        - Re-queues 'running' items whose heartbeat went stale (assume worker died during restart).
        - Starts tasks for 'queued' items up to concurrency limit.

        Changes vs original:
        - All DB writes go through _with_db_write() (=> DB_WRITE_LOCK + BEGIN IMMEDIATE + retry).
        - DB work is split into short transactions:
            (a) read running rows
            (b) write requeue (batched) if needed
            (c) read queued rows
        - Spawning tasks stays outside DB work.
        """
        resumed = 0
        requeued = 0
        queued_found = 0
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        def _parse_iso(s: Optional[str]) -> Optional[datetime]:
            if not s:
                return None
            try:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return None

        # ----------------------------
        # 1) Read running rows (no lock)
        # ----------------------------
        db = await self._db()
        try:
            cur = await db.execute(
                """
                SELECT execution_id, last_heartbeat, updated_at
                FROM runbook_queue
                WHERE status='running'
                """
            )
            running_rows = await cur.fetchall()
            await cur.close()
        finally:
            await db.close()

        # decide stale in Python (no DB open)
        stale_ids: list[str] = []
        for r in running_rows:
            hb = _parse_iso(r["last_heartbeat"]) or _parse_iso(r["updated_at"])
            if not hb:
                continue
            age = (now - hb).total_seconds()
            if age >= float(self._queue_stale_running_seconds):
                stale_ids.append(r["execution_id"])

        # ----------------------------
        # 2) Requeue stale running (write, short tx)
        # ----------------------------
        if stale_ids:

            async def _op_requeue(dbw: aiosqlite.Connection) -> int:
                n = 0
                for ex_id in stale_ids:
                    curu = await dbw.execute(
                        """
                        UPDATE runbook_queue
                        SET status='queued', updated_at=?
                        WHERE execution_id=? AND status='running'
                        """,
                        (now_iso, ex_id),
                    )
                    if int(getattr(curu, "rowcount", 0) or 0) == 1:
                        n += 1
                return n

            try:
                requeued = int(await self._with_db_write(_op_requeue))
            except Exception:
                requeued = 0

        # ----------------------------
        # 3) Fetch queued items (read, no lock)
        # ----------------------------
        db = await self._db()
        try:
            cur = await db.execute(
                """
                SELECT execution_id, runbook_name, incident_id, target_service, target_instance,
                    parameters_json, triggered_by, available_at
                FROM runbook_queue
                WHERE status='queued'
                ORDER BY updated_at ASC
                LIMIT 500
                """
            )
            queued_rows = await cur.fetchall()
            await cur.close()
            queued_found = len(queued_rows)
        finally:
            await db.close()

        # ----------------------------
        # 4) Start tasks (outside DB)
        # ----------------------------
        for r in queued_rows:
            ex_id = r["execution_id"]

            # backoff gate
            av_raw = r["available_at"]
            if av_raw:
                try:
                    av = datetime.fromisoformat(av_raw)
                    if av.tzinfo is None:
                        av = av.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) < av:
                        continue
                except Exception:
                    # corrupt available_at should not block forever
                    pass

            async with self._lock:
                if ex_id in self._tasks:
                    continue

            # Load execution record (source of truth)
            ex = await self.get_execution(ex_id)
            if not ex:
                continue

            # Skip if already completed (defensive)
            st = str(getattr(ex.status, "value", ex.status)).lower()
            if st in ("success", "failed", "timeout", "skipped"):
                try:
                    await self._queue_mark_done(
                        ex_id, dead=(st in ("failed", "timeout"))
                    )
                except Exception:
                    pass
                continue

            # Acquire concurrency and spawn
            await self._semaphore.acquire()
            if r["target_service"] and r["target_service"] in self._svc_semaphores:
                await self._svc_semaphores[r["target_service"]].acquire()
                async with self._lock:
                    self._execution_svc_locks[ex_id] = r["target_service"]

            params = {}
            if r["parameters_json"]:
                try:
                    params = json.loads(r["parameters_json"])
                except Exception:
                    params = {}

            task = asyncio.create_task(
                self._run_execution_task(
                    execution_id=ex_id,
                    runbook_name=r["runbook_name"],
                    incident_id=r["incident_id"],
                    target_service=r["target_service"],
                    target_instance=r["target_instance"],
                    parameters=params,
                    triggered_by=r["triggered_by"] or "system",
                    skip_validation=False,
                ),
                name=f"runbook:resume:{r['runbook_name']}:{ex_id}",
            )
            async with self._lock:
                self._tasks[ex_id] = task
            resumed += 1

        # Wake hot worker after recovery/resume so it consumes remaining queued items
        try:
            self.kick_queue_worker()
        except Exception:
            pass

        logger.info(
            "runbook_queue_recovery",
            queued_found=queued_found,
            requeued_stale_running=requeued,
            resumed=resumed,
        )
        return {"queued_found": queued_found, "requeued": requeued, "resumed": resumed}

    async def load_active_from_db(self) -> dict:
        """
        Rehidrata en memoria ejecuciones activas desde DB.
        - PENDING: se mantiene.
        - RUNNING: se mantiene. (La cola durable + resume_durable_queue_from_db decide requeue/stale.)
        No re-lanza tasks.
        """
        db = await self._db()
        loaded_pending = 0
        loaded_running = 0

        try:
            cur = await db.execute(
                """
                SELECT
                  id, incident_id, runbook_name, status, triggered_by,
                  target_service, target_instance, parameters_json,
                  output, error, started_at, completed_at, duration_seconds,
                  confirmed_execution_id, confirmed_by, confirmed_at
                FROM runbook_executions
                WHERE lower(status) IN ('pending','running')
                ORDER BY started_at ASC
                """
            )
            rows = await cur.fetchall()
            await cur.close()

            for row in rows:
                ex = self._row_to_execution(row)

                st = (
                    ex.status.value if hasattr(ex.status, "value") else str(ex.status)
                ).lower()

                async with self._lock:
                    self._executions[ex.id] = ex

                if st == "pending":
                    loaded_pending += 1
                elif st == "running":
                    loaded_running += 1

            async with self._lock:
                self._update_queue_metrics()

        finally:
            await db.close()

        logger.info(
            "runbook_engine_rehydrated",
            pending=loaded_pending,
            running=loaded_running,
            healed_running=0,
        )
        return {
            "pending": loaded_pending,
            "running": loaded_running,
            "healed_running": 0,
        }

    async def invalidate_execution_cache(self, execution_id: str) -> None:
        """
        Invalida caché RAM para forzar que la próxima lectura venga de DB (source of truth).
        Útil tras cambios directos en DB (p.ej. cancelación de PENDING stale).
        """
        async with self._lock:
            self._executions.pop(execution_id, None)

    # ============================================================
    # SRE-GRADE RECOVERY RECONCILER
    # ============================================================
    async def recover_queue(self) -> None:
        """
        Recovery reconciler (older path).

        Changes vs original:
        - Any DB write on runbook_queue goes through _with_db_write()
        (=> DB_WRITE_LOCK + BEGIN IMMEDIATE + retries).
        - Reading stays lock-free (no DB_WRITE_LOCK) because it doesn't block writers.
        - Keep "self-heal runbook_executions" outside DB lock (already good).
        - Always clears _recovery_running in finally (so a crash doesn't brick recovery forever).
        """
        if self._recovery_running:
            return

        self._recovery_running = True
        logger.info("runbook_queue_recovery_started")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        stale_running_ids: list[str] = []
        queued_ids: list[str] = []

        try:
            # 1) ONLY read + decide (no lock)

            db = await self._db()
            try:
                cur = await db.execute(
                    """
                    SELECT execution_id, status, last_heartbeat
                    FROM runbook_queue
                    WHERE status IN ('queued','running')
                    ORDER BY created_at ASC
                    """
                )
                rows = await cur.fetchall()
                await cur.close()
            finally:
                await db.close()

            # 2) classify without open DB
            for row in rows:
                execution_id = row["execution_id"]
                status = (row["status"] or "").lower()
                last_heartbeat = row["last_heartbeat"]

                if status == "running":
                    stale = True
                    if last_heartbeat:
                        try:
                            hb = datetime.fromisoformat(last_heartbeat)
                            if hb.tzinfo is None:
                                hb = hb.replace(tzinfo=timezone.utc)
                            stale = (now - hb).total_seconds() > float(
                                self._queue_stale_running_seconds
                            )
                        except Exception:
                            stale = True

                    if stale:
                        stale_running_ids.append(execution_id)

                elif status == "queued":
                    queued_ids.append(execution_id)

            # 3) apply updates in short transactions (DB write wrapper)
            if stale_running_ids:

                async def _op_mark_dead(dbw: aiosqlite.Connection) -> int:
                    n = 0
                    for execution_id in stale_running_ids:
                        logger.warning(
                            "runbook_queue_recover_stale_running",
                            execution_id=execution_id,
                        )
                        curu = await dbw.execute(
                            """
                            UPDATE runbook_queue
                            SET status='dead', updated_at=?
                            WHERE execution_id=? AND status='running'
                            """,
                            (now_iso, execution_id),
                        )
                        if int(getattr(curu, "rowcount", 0) or 0) == 1:
                            n += 1
                    return n

                try:
                    await self._with_db_write(_op_mark_dead)
                except Exception:
                    # Best-effort: if we can't mark dead, still attempt self-heal below per execution
                    pass

                # now without locks, self-heal runbook_executions
                for execution_id in stale_running_ids:
                    execution = await self.get_execution(execution_id)
                    if execution:
                        execution.complete(
                            success=False,
                            error="Recovered after restart (stale RUNNING)",
                        )
                        await self._persist_execution(execution)

            # 4) requeue queued
            for execution_id in queued_ids:
                logger.info("runbook_queue_recover_requeue", execution_id=execution_id)
                ex = await self.get_execution(execution_id)
                if ex:
                    await self._resume_execution(ex)

            logger.info(
                "runbook_queue_recovery_completed",
                stale_running=len(stale_running_ids),
                queued=len(queued_ids),
            )

        finally:
            # Important: don't brick recovery forever if something explodes mid-way
            self._recovery_running = False

    async def _resume_execution(
        self,
        execution: RunbookExecution,
    ) -> None:
        """
        Resume execution safely after restart.

        Notes:
        - We keep triggered_by="recovery" for audit/telemetry.
        - skip_validation=True only skips SOFT checks (rate limit),
        because HARD guards run always inside _run_execution_task.
        """

        # Avoid duplicate in-flight tasks
        async with self._lock:
            if execution.id in self._tasks:
                return

        # Defensive: never resume already-finished executions
        st = str(getattr(execution.status, "value", execution.status)).lower()
        if st in ("success", "failed", "timeout", "skipped"):
            try:
                await self._queue_mark_done(
                    execution.id, dead=(st in ("failed", "timeout"))
                )
            except Exception:
                pass
            return

        # Ensure it's queued in durable queue (idempotent UPSERT)
        await self._enqueue_execution(execution)

        # Acquire global concurrency slot
        await self._semaphore.acquire()

        # Acquire per-service concurrency slot (to match other execution paths)
        svc = execution.target_service
        if svc and svc in self._svc_semaphores:
            await self._svc_semaphores[svc].acquire()
            async with self._lock:
                self._execution_svc_locks[execution.id] = svc

        task = asyncio.create_task(
            self._run_execution_task(
                execution_id=execution.id,
                runbook_name=execution.runbook_name,
                incident_id=execution.incident_id,
                target_service=execution.target_service,
                target_instance=execution.target_instance,
                parameters=execution.parameters or {},
                triggered_by="recovery",
                skip_validation=True,  # only skips SOFT checks
            ),
            name=f"runbook-recovery:{execution.id}",
        )

        async with self._lock:
            self._tasks[execution.id] = task


# Global runbook engine instance
runbook_engine = RunbookEngine()
