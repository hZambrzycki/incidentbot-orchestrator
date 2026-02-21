"""
Incident Manager - Core incident handling logic.
Manages incident lifecycle, deduplication, and state tracking.
"""

# ===========================================
# Imports
# ===========================================

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Literal, Optional

import aiosqlite
from fastapi.encoders import jsonable_encoder

from src.core.logging_config import audit_logger, get_logger
from src.core.models import (
    Alert,
    AlertmanagerWebhook,
    Incident,
    IncidentEpisode,
    IncidentStatus,
    RunbookExecution,
    RunbookStatus,
    Severity,
)
from src.db.connection import DB_PATH, DB_WRITE_LOCK
from src.db.event_store import emit_event, record_failure

# ===========================================
# Module-level setup
# ===========================================

logger = get_logger("incident_manager")

AlertProcessResult = Literal[
    "new_incident", "updated", "reopened", "resolved", "ignored"
]


# ===========================================
# Incident Manager
# ===========================================


class IncidentManager:
    """
    Manages the lifecycle of incidents.

    Responsibilities:
    - Create incidents from alerts
    - Deduplicate alerts
    - Track incident state
    - Provide incident queries
    """

    # ---------------------------------------
    # Construction & DB connection
    # ---------------------------------------

    def __init__(self, db_path: str = DB_PATH):
        self._incidents: Dict[str, Incident] = {}
        self._alert_to_incident: Dict[str, str] = {}  # fingerprint -> incident_id
        self._lock = asyncio.Lock()
        self._db_path = db_path

    async def _db(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self._db_path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout = 30000;")
        await db.execute("PRAGMA foreign_keys=ON;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        return db

    # ---------------------------------------
    # Persistence helpers
    # ---------------------------------------

    async def _persist_runbook_execution(self, execution: RunbookExecution) -> None:
        """
        Source of truth: runbook_executions table.
        UPSERT by id (idempotent).
        """
        if not execution.incident_id:
            logger.warning(
                "runbook_execution_skip_persist_no_incident_id",
                execution_id=execution.id,
                runbook=execution.runbook_name,
            )
            return

        db = await self._db()
        try:
            payload = jsonable_encoder(execution)
            params_json = json.dumps(
                payload.get("parameters") or {}, ensure_ascii=False
            )

            async with DB_WRITE_LOCK:
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
                        execution.triggered_by,
                        getattr(execution, "execution_origin", None),
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
                await db.commit()
        finally:
            await db.close()

    async def _persist_incident(self, incident: Incident) -> None:
        """
        UPSERT the full incident (includes episodes in JSON).
        Must be called from within the manager lock.
        """
        db = await self._db()
        try:
            payload = jsonable_encoder(incident)

            cols = [
                "id",
                "title",
                "description",
                "severity",
                "status",
                "source_alert",
                "service",
                "instance",
                "labels_json",
                "annotations_json",
                "diagnosis",
                "reopen_count",
                "error_type",
                "error_summary",
                "created_at",
                "updated_at",
                "resolved_at",
                "last_fired_at",
                "last_processed_at",
                "episodes_json",
            ]
            placeholders = ",".join(["?"] * len(cols))

            sql = f"""
            INSERT INTO incidents({",".join(cols)})
            VALUES ({placeholders})
            ON CONFLICT(id) DO UPDATE SET
              title=excluded.title,
              description=excluded.description,
              severity=excluded.severity,
              status=excluded.status,
              source_alert=excluded.source_alert,
              service=excluded.service,
              instance=excluded.instance,
              labels_json=excluded.labels_json,
              annotations_json=excluded.annotations_json,
              diagnosis=excluded.diagnosis,
              reopen_count=excluded.reopen_count,
              error_type=excluded.error_type,
              error_summary=excluded.error_summary,
              updated_at=excluded.updated_at,
              resolved_at=excluded.resolved_at,
              last_fired_at=excluded.last_fired_at,
              last_processed_at=excluded.last_processed_at,
              episodes_json=excluded.episodes_json
            """

            values_tuple = (
                incident.id,
                incident.title,
                incident.description,
                int(incident.severity),
                incident.status.value
                if hasattr(incident.status, "value")
                else str(incident.status),
                incident.source_alert,
                incident.service,
                incident.instance,
                json.dumps(payload.get("labels") or {}, ensure_ascii=False),
                json.dumps(payload.get("annotations") or {}, ensure_ascii=False),
                payload.get("diagnosis"),
                int(payload.get("reopen_count") or 0),
                payload.get("error_type"),
                payload.get("error_summary"),
                payload.get("created_at"),
                payload.get("updated_at"),
                payload.get("resolved_at"),
                payload.get("last_fired_at"),
                payload.get("last_processed_at"),
                json.dumps(payload.get("episodes") or [], ensure_ascii=False),
            )
            assert len(cols) == len(values_tuple), (len(cols), len(values_tuple))

            async with DB_WRITE_LOCK:
                await db.execute(sql, values_tuple)
                await db.commit()
        finally:
            await db.close()

    async def _persist_fingerprint_map(
        self, fingerprint: str, incident_id: str
    ) -> None:
        db = await self._db()
        try:
            now = datetime.now(timezone.utc).isoformat()
            async with DB_WRITE_LOCK:
                await db.execute(
                    """
                    INSERT INTO incident_fingerprints(fingerprint, incident_id, updated_at)
                    VALUES(?,?,?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                      incident_id=excluded.incident_id,
                      updated_at=excluded.updated_at
                    """,
                    (fingerprint, incident_id, now),
                )
                await db.commit()
        finally:
            await db.close()

    # ---------------------------------------
    # Startup: rehydrate state from DB
    # ---------------------------------------

    async def load_from_db(self) -> None:
        """
        Rehydrates in-memory state from SQLite. Does not change the public API.
        """
        async with self._lock:
            self._incidents.clear()
            self._alert_to_incident.clear()

            db = await self._db()
            try:
                # --- 1) Load runbook executions (SOURCE OF TRUTH) ---
                cur = await db.execute(
                    """
                    SELECT
                      id, incident_id, runbook_name, status, triggered_by,
                      target_service, target_instance, parameters_json, output, error,
                      started_at, completed_at, duration_seconds,
                      execution_origin, retry_of_execution_id
                    FROM runbook_executions
                    ORDER BY started_at ASC
                    """
                )
                exec_rows = await cur.fetchall()
                await cur.close()

                exec_by_incident: Dict[str, List[dict]] = {}
                for r in exec_rows:
                    d = dict(r)
                    params = {}
                    if d.get("parameters_json"):
                        try:
                            params = json.loads(d["parameters_json"])
                        except Exception:
                            params = {}

                    exec_by_incident.setdefault(d["incident_id"], []).append(
                        {
                            "id": d["id"],
                            "runbook_name": d["runbook_name"],
                            "incident_id": d["incident_id"],
                            "status": d["status"],
                            "target_service": d.get("target_service"),
                            "target_instance": d.get("target_instance"),
                            "parameters": params,
                            "started_at": d.get("started_at"),
                            "completed_at": d.get("completed_at"),
                            "duration_seconds": d.get("duration_seconds"),
                            "output": d.get("output") or "",
                            "error": d.get("error"),
                            "triggered_by": d.get("triggered_by") or "system",
                            "execution_origin": d.get("execution_origin"),
                            "retry_of_execution_id": d.get("retry_of_execution_id"),
                        }
                    )

                # --- 2) Load incidents ---
                cur = await db.execute("SELECT * FROM incidents")
                rows = await cur.fetchall()
                await cur.close()

                def _loads(s, default):
                    if not s:
                        return default
                    try:
                        return json.loads(s)
                    except Exception:
                        return default

                for r in rows:
                    inc_dict = dict(r)

                    execs = exec_by_incident.get(inc_dict["id"], [])
                    derived_runbooks_executed = sorted(
                        {e.get("runbook_name") for e in execs if e.get("runbook_name")}
                    )

                    inc_payload = {
                        "id": inc_dict["id"],
                        "title": inc_dict["title"],
                        "description": inc_dict.get("description") or "",
                        "severity": int(inc_dict["severity"]),
                        "status": inc_dict["status"],
                        "source_alert": inc_dict.get("source_alert"),
                        "service": inc_dict.get("service"),
                        "instance": inc_dict.get("instance"),
                        "labels": _loads(inc_dict.get("labels_json"), {}),
                        "annotations": _loads(inc_dict.get("annotations_json"), {}),
                        "diagnosis": inc_dict.get("diagnosis"),
                        "reopen_count": int(inc_dict.get("reopen_count") or 0),
                        "error_type": inc_dict.get("error_type"),
                        "error_summary": inc_dict.get("error_summary"),
                        "created_at": inc_dict["created_at"],
                        "updated_at": inc_dict["updated_at"],
                        "resolved_at": inc_dict.get("resolved_at"),
                        "last_fired_at": inc_dict.get("last_fired_at"),
                        "last_processed_at": inc_dict.get("last_processed_at"),
                        "episodes": _loads(inc_dict.get("episodes_json"), []),
                        "runbooks_executed": derived_runbooks_executed,
                        "runbook_executions": execs,
                    }

                    # Pydantic parse: accepts datetimes if ISO strings
                    incident = Incident.model_validate(inc_payload)
                    self._incidents[incident.id] = incident

                # --- 3) Load fingerprint mappings ---
                cur = await db.execute(
                    "SELECT fingerprint, incident_id FROM incident_fingerprints"
                )
                fps = await cur.fetchall()
                await cur.close()

                for fp in fps:
                    self._alert_to_incident[fp["fingerprint"]] = fp["incident_id"]

                logger.info(
                    "incidents_loaded_from_db",
                    incidents=len(self._incidents),
                    fingerprints=len(self._alert_to_incident),
                )
            finally:
                await db.close()

    # ---------------------------------------
    # Alertmanager webhook processing
    # ---------------------------------------

    async def process_alertmanager_webhook(
        self, webhook: AlertmanagerWebhook
    ) -> List[tuple[Incident, str]]:
        """
        Process an Alertmanager webhook and return affected incidents.
        """
        affected_incidents: List[tuple[Incident, str]] = []

        async with self._lock:
            # Process firing alerts
            for alert in webhook.firing_alerts:
                incident, resolution = await self._handle_firing_alert(alert)
                if incident:
                    affected_incidents.append((incident, resolution))

            # Process resolved alerts
            for alert in webhook.resolved_alerts:
                incident, resolution = await self._handle_resolved_alert(alert)
                if incident:
                    affected_incidents.append((incident, resolution))

        return affected_incidents

    async def _handle_firing_alert(
        self, alert: Alert
    ) -> tuple[Optional[Incident], AlertProcessResult]:
        """Handle a firing alert - create or update incident."""
        fingerprint = alert.fingerprint
        now = datetime.now(timezone.utc)

        # Determine error type (from annotation or by alertname)
        error_type = alert.annotations.get("error_type") or {
            "HighCPU": "high_cpu",
            "HighMemory": "high_memory",
            "DiskSpaceLow": "disk_space_low",
        }.get(alert.alertname, "unknown")

        # If there is no fingerprint, we cannot deduplicate/reopen reliably:
        # treat as a new incident (you could add an alternative key if desired).
        if not fingerprint:
            incident = Incident(
                title=alert.summary,
                description=alert.description,
                severity=alert.severity,
                status=IncidentStatus.FIRING,
                source_alert=None,
                service=alert.service,
                instance=alert.instance,
                labels=dict(alert.labels),
                annotations=dict(alert.annotations),
                error_type=error_type,
                error_summary=alert.summary,
                last_fired_at=now,
                episodes=[
                    IncidentEpisode(
                        started_at=now,
                        error_type=error_type,
                        summary=alert.summary,
                    )
                ],
            )
            self._incidents[incident.id] = incident
            logger.info(
                "incident_created_no_fingerprint",
                incident_id=incident.id,
                title=incident.title,
            )
            audit_logger.incident_created(
                incident_id=incident.id,
                title=incident.title,
                severity=incident.severity.value,
            )
            await self._persist_incident(incident)
            return incident, "new_incident"

        # Check for existing incident mapped by fingerprint
        incident_id = self._alert_to_incident.get(fingerprint)

        if incident_id and incident_id in self._incidents:
            incident = self._incidents[incident_id]

            # If it was resolved -> REOPEN (same id)
            reopened = False
            if incident.status == IncidentStatus.RESOLVED:
                reopened = True
                incident.reopen_count += 1
                incident.resolved_at = None
                incident.status = IncidentStatus.FIRING

                # Safety guard: close any still-open episode (should not happen often)
                if incident.episodes and incident.episodes[-1].resolved_at is None:
                    incident.episodes[-1].resolved_at = now

                # Start a new episode
                incident.episodes.append(
                    IncidentEpisode(
                        started_at=now,
                        error_type=error_type,
                        summary=alert.summary,
                    )
                )

            # If it was active, we do NOT open a new episode; we just refresh.
            incident.updated_at = now
            incident.last_fired_at = now

            # Refresh data
            incident.title = alert.summary
            incident.description = alert.description
            incident.severity = alert.severity
            incident.service = alert.service
            incident.instance = alert.instance
            incident.labels = dict(alert.labels)
            incident.annotations = dict(alert.annotations)
            incident.error_type = error_type
            incident.error_summary = alert.summary

            logger.info(
                "incident_updated_or_reopened",
                incident_id=incident.id,
                fingerprint=fingerprint,
                reopen_count=incident.reopen_count,
                status=incident.status.value,
            )
            await self._persist_incident(incident)

            return incident, ("reopened" if reopened else "updated")

        # No existing incident for this fingerprint -> create a new one and map it
        incident = Incident(
            title=alert.summary,
            description=alert.description,
            severity=alert.severity,
            status=IncidentStatus.FIRING,
            source_alert=fingerprint,
            service=alert.service,
            instance=alert.instance,
            labels=dict(alert.labels),
            annotations=dict(alert.annotations),
            error_type=error_type,
            error_summary=alert.summary,
            last_fired_at=now,
            episodes=[
                IncidentEpisode(
                    started_at=now,
                    error_type=error_type,
                    summary=alert.summary,
                )
            ],
        )
        self._incidents[incident.id] = incident

        await self._persist_incident(incident)
        await self._persist_fingerprint_map(fingerprint, incident.id)

        self._alert_to_incident[fingerprint] = incident.id
        logger.info(
            "incident_created",
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity.value,
            fingerprint=fingerprint,
        )
        audit_logger.incident_created(
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity.value,
        )
        return incident, "new_incident"

    async def _handle_resolved_alert(
        self, alert: Alert
    ) -> tuple[Optional[Incident], AlertProcessResult]:
        """Handle a resolved alert - resolve corresponding incident."""
        fingerprint = alert.fingerprint

        if not fingerprint or fingerprint not in self._alert_to_incident:
            return None, "ignored"

        incident_id = self._alert_to_incident[fingerprint]
        if incident_id not in self._incidents:
            return None, "ignored"

        incident = self._incidents[incident_id]

        if incident.is_active:
            old_status = incident.status
            incident.update_status(IncidentStatus.RESOLVED)
            await self._persist_incident(incident)

            logger.info(
                "incident_resolved",
                incident_id=incident.id,
                duration_seconds=incident.duration_seconds,
            )

            audit_logger.incident_status_changed(
                incident_id=incident.id,
                old_status=old_status.value,
                new_status=incident.status.value,
            )
            return incident, "resolved"

        return incident, "ignored"

    # ---------------------------------------
    # Read APIs (in-memory)
    # ---------------------------------------

    async def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    async def get_active_incidents(self) -> List[Incident]:
        """Get all active (non-resolved) incidents."""
        return [inc for inc in self._incidents.values() if inc.is_active]

    async def get_incidents_by_severity(self, severity: Severity) -> List[Incident]:
        """Get incidents filtered by severity."""
        return [
            inc
            for inc in self._incidents.values()
            if inc.severity == severity and inc.is_active
        ]

    async def get_recent_incidents(
        self, hours: int = 24, include_resolved: bool = True
    ) -> List[Incident]:
        """Get incidents from the last N hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        incidents = [
            inc for inc in self._incidents.values() if inc.created_at >= cutoff
        ]
        if not include_resolved:
            incidents = [inc for inc in incidents if inc.is_active]
        return sorted(incidents, key=lambda x: x.created_at, reverse=True)

    async def get_statistics(self) -> dict:
        """Get incident statistics."""
        all_incidents = list(self._incidents.values())
        active = [i for i in all_incidents if i.is_active]

        today = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today_incidents = [i for i in all_incidents if i.created_at >= today]

        by_severity = {}
        for sev in Severity:
            by_severity[sev.value] = len([i for i in active if i.severity == sev])

        return {
            "total": len(all_incidents),
            "active": len(active),
            "today": len(today_incidents),
            "by_severity": by_severity,
        }

    # ---------------------------------------
    # Mutations: incidents & executions
    # ---------------------------------------

    async def update_incident_status(
        self, incident_id: str, new_status: IncidentStatus, actor: str = "system"
    ) -> Optional[Incident]:
        """Update the status of an incident."""
        async with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            old_status = incident.status
            incident.update_status(new_status)

            logger.info(
                "incident_status_changed",
                incident_id=incident_id,
                old_status=old_status.value,
                new_status=new_status.value,
                actor=actor,
            )

            audit_logger.incident_status_changed(
                incident_id=incident_id,
                old_status=old_status.value,
                new_status=new_status.value,
                actor=actor,
            )

            await self._persist_incident(incident)
            return incident

    async def add_execution_to_incident(
        self, incident_id: str, execution: RunbookExecution
    ):
        async with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return

            # Source of truth: runbook_executions table (idempotent).
            # We persist ALWAYS even if it becomes a duplicate in RAM.
            await self._persist_runbook_execution(execution)

            if any(e.id == execution.id for e in (incident.runbook_executions or [])):
                return

            # Add to in-memory list
            incident.runbook_executions.append(execution)
            incident.updated_at = datetime.now(timezone.utc)

            # Note: we do not persist the incident for execution list changes;
            # runbook_executions is the source of truth. _persist_incident is
            # reserved for status/episodes/diagnosis/etc changes.

    async def set_incident_diagnosis(self, incident_id: str, diagnosis: str):
        """Add diagnostic information to an incident."""
        async with self._lock:
            incident = self._incidents.get(incident_id)
            if incident:
                incident.diagnosis = diagnosis
                incident.updated_at = datetime.now(timezone.utc)
                await self._persist_incident(incident)

    async def set_last_processed_at(self, incident_id: str, ts: datetime):
        """Persist last time the incident was processed by the system."""
        async with self._lock:
            incident = self._incidents.get(incident_id)
            if incident:
                incident.last_processed_at = ts
                incident.updated_at = datetime.now(timezone.utc)
                logger.info(
                    "incident_last_processed_set",
                    incident_id=incident_id,
                    ts=ts.isoformat(),
                )
                await self._persist_incident(incident)

    # ---------------------------------------
    # Maintenance: cleanup old resolved incidents
    # ---------------------------------------

    async def cleanup_old_incidents(self, days: int = 7):
        """Remove resolved incidents older than N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        async with self._lock:
            to_remove = [
                inc_id
                for inc_id, inc in self._incidents.items()
                if inc.status == IncidentStatus.RESOLVED
                and inc.resolved_at
                and inc.resolved_at < cutoff
            ]
            if not to_remove:
                return

            # 1) Memory
            for inc_id in to_remove:
                inc = self._incidents.pop(inc_id, None)
                if inc and inc.source_alert:
                    self._alert_to_incident.pop(inc.source_alert, None)

            # 2) DB (delete all)
            db = await self._db()
            try:
                async with DB_WRITE_LOCK:
                    await db.executemany(
                        "DELETE FROM incident_fingerprints WHERE incident_id = ?",
                        [(i,) for i in to_remove],
                    )
                    await db.executemany(
                        "DELETE FROM runbook_executions WHERE incident_id = ?",
                        [(i,) for i in to_remove],
                    )
                    await db.executemany(
                        "DELETE FROM runbook_confirmations WHERE incident_id = ?",
                        [(i,) for i in to_remove],
                    )
                    await db.executemany(
                        "DELETE FROM incidents WHERE id = ?",
                        [(i,) for i in to_remove],
                    )
                    await db.commit()
            finally:
                await db.close()

            logger.info("cleaned_old_incidents", count=len(to_remove))

    # ---------------------------------------
    # Maintenance: replace pending execution (mark as skipped)
    # ---------------------------------------

    async def replace_pending_execution(
        self,
        incident_id: str,
        execution_id: str,
        replaced_by: str = "human",
    ) -> bool:
        async with self._lock:
            incident = self._incidents.get(incident_id)
            target = None
            if incident:
                target = next(
                    (
                        e
                        for e in (incident.runbook_executions or [])
                        if e.id == execution_id
                    ),
                    None,
                )

            payload = {
                "status": "replaced",
                "success": False,
                "message": "Pending execution replaced by confirmation",
                "replaced_by": replaced_by,
            }
            now_iso = datetime.now(timezone.utc).isoformat()
            output_json = json.dumps(payload, ensure_ascii=False)

            # 1) In-memory path (if present)
            if target:
                if target.status != RunbookStatus.PENDING:
                    return False
                target.mark_skipped(output_json)
                await self._persist_runbook_execution(target)
                incident.updated_at = datetime.now(timezone.utc)
                await self._persist_incident(incident)
                return True

            # 2) DB fallback (if not in memory)
            db = await self._db()
            try:
                cur = await db.execute(
                    """
                    SELECT status, runbook_name, target_service, target_instance, parameters_json
                    FROM runbook_executions
                    WHERE id = ? AND incident_id = ?
                    """,
                    (execution_id, incident_id),
                )
                row = await cur.fetchone()
                await cur.close()

                if not row:
                    return False
                if (row["status"] or "").lower() != RunbookStatus.PENDING.value:
                    return False

                async with DB_WRITE_LOCK:
                    await db.execute(
                        """
                        UPDATE runbook_executions
                        SET status = ?, output = ?, completed_at = ?
                        WHERE id = ? AND incident_id = ?
                        """,
                        (
                            RunbookStatus.SKIPPED.value,
                            output_json,
                            now_iso,
                            execution_id,
                            incident_id,
                        ),
                    )
                    await db.commit()

                # If the incident exists in memory, mirror the change in RAM as well
                if incident:
                    # Create a minimal shadow execution so the dashboard stays truthful
                    try:
                        shadow = RunbookExecution(
                            id=execution_id,
                            incident_id=incident_id,
                            runbook_name=row["runbook_name"],
                            target_service=row["target_service"],
                            target_instance=row["target_instance"],
                            parameters=json.loads(row["parameters_json"] or "{}"),
                            status=RunbookStatus.SKIPPED,
                            output=output_json,
                            completed_at=datetime.fromisoformat(now_iso),
                            triggered_by="human",
                        )
                        incident.runbook_executions.append(shadow)
                        incident.updated_at = datetime.now(timezone.utc)
                        await self._persist_incident(incident)
                    except Exception:
                        pass

                return True
            finally:
                await db.close()

    # ---------------------------------------
    # Maintenance: auto-cancel stale pending executions (TTL policy)
    # ---------------------------------------

    async def auto_cancel_stale_pending(self, max_age_seconds: int = 86400) -> int:
        """
        Auto-cancel pending runbooks older than max_age_seconds.
        Returns number of cancelled executions.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        db = await self._db()
        cancelled = 0

        try:
            # Robust: compute age in Python (SQLite strftime does NOT parse ISO well with
            # microseconds/offset)
            cur = await db.execute(
                """
                SELECT id, incident_id, started_at, runbook_name, target_service, target_instance
                FROM runbook_executions
                WHERE status = 'pending'
                  AND started_at IS NOT NULL
                ORDER BY started_at ASC
                """
            )
            rows = await cur.fetchall()
            await cur.close()

            stale: list[tuple[str, Optional[str], Optional[str]]] = []
            for r in rows:
                raw = r["started_at"]
                if not raw:
                    continue
                try:
                    started = datetime.fromisoformat(raw)
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=timezone.utc)
                except Exception:
                    continue

                age_s = (now - started).total_seconds()
                if age_s >= float(max_age_seconds):
                    stale.append((r["id"], r["incident_id"], r["runbook_name"]))

            post_actions: list[dict[str, object]] = []

            async with DB_WRITE_LOCK:
                for execution_id, incident_id, runbook_name in stale:
                    output_payload = {
                        "status": "skipped",
                        "success": False,
                        "reason": "stale_pending_ttl",
                        "message": "Auto-cancelled stale pending execution (TTL policy)",
                        "timeout_seconds": max_age_seconds,
                        "canceled_at": now_iso,
                    }
                    output = json.dumps(output_payload, ensure_ascii=False)

                    res = await db.execute(
                        """
                        UPDATE runbook_executions
                        SET status = 'skipped',
                            output = ?,
                            completed_at = ?
                        WHERE id = ?
                          AND status = 'pending'
                        """,
                        (output, now_iso, execution_id),
                    )

                    if getattr(res, "rowcount", 0) == 1:
                        cancelled += 1

                        try:
                            await db.execute(
                                """
                                UPDATE runbook_confirmations
                                SET status = 'skipped',
                                    updated_at = ?,
                                    result_json = ?
                                WHERE pending_execution_id = ?
                                  AND status = 'pending'
                                """,
                                (now_iso, output, execution_id),
                            )
                        except Exception:
                            pass

                        post_actions.append(
                            {
                                "execution_id": execution_id,
                                "incident_id": incident_id,  # may be None
                                "runbook_name": runbook_name or "unknown",
                                "output": output,
                            }
                        )

                await db.commit()

            # Outside locks
            for it in post_actions:
                execution_id = str(it["execution_id"])
                incident_id = it.get("incident_id")  # Optional[str]
                runbook_name = str(it.get("runbook_name") or "unknown")

                try:
                    audit_logger.log(
                        event_type="runbook_confirmation",
                        actor="system",
                        resource_type="runbook_execution",
                        resource_id=execution_id,
                        action="pending_auto_skipped_ttl",
                        details={
                            "reason": "stale_pending_ttl",
                            "timeout_seconds": max_age_seconds,
                            "canceled_at": now_iso,
                        },
                        success=True,
                    )
                except Exception:
                    pass

                try:
                    await emit_event(
                        event_key=f"exec:{execution_id}:ttl_skipped",
                        event_type="runbook.confirmation.auto_skipped_ttl",
                        actor="system",
                        source="incident_manager",
                        severity="warning",
                        message="Auto-cancelled stale pending (TTL)",
                        incident_id=incident_id,
                        execution_id=execution_id,
                        confirmation_id=execution_id,
                        details={
                            "runbook": runbook_name,
                            "timeout_seconds": max_age_seconds,
                            "canceled_at": now_iso,
                        },
                    )
                except Exception:
                    pass

                try:
                    await record_failure(
                        execution_id=execution_id,
                        runbook_name=runbook_name,
                        failure_kind="ttl_skipped",
                        final_status="skipped",
                        incident_id=incident_id,
                        is_final=True,
                        error_message="stale_pending_ttl",
                        details={"timeout_seconds": max_age_seconds},
                    )
                except Exception:
                    pass

            if cancelled > 0:
                logger.info(
                    "auto_cancelled_stale_runbooks",
                    count=cancelled,
                    max_age_seconds=max_age_seconds,
                )

            return cancelled

        finally:
            await db.close()


# ===========================================
# Singleton
# ===========================================

incident_manager = IncidentManager()
