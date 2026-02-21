"""
Metrics Collector - Prometheus metrics for the incident bot.
Exposes metrics about incidents, runbooks, and system health.
"""

import asyncio
import os
import threading
import time
from datetime import datetime, timezone
from typing import Dict

import aiosqlite
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

from src.core.config import settings

# ============================================================
# INCIDENT METRICS
# ============================================================

INCIDENTS_TOTAL = Counter(
    "incident_bot_incidents_total",
    "Total number of incidents received",
    ["severity", "status"],
)

INCIDENTS_ACTIVE = Gauge(
    "incident_bot_incidents_active",
    "Number of currently active incidents",
    ["severity"],
)

INCIDENT_DURATION = Histogram(
    "incident_bot_incident_duration_seconds",
    "Duration of incidents from firing to resolution",
    ["severity"],
    buckets=[60, 300, 600, 1800, 3600, 7200, 14400, 28800],
)

# ============================================================
# RUNBOOK METRICS
# ============================================================

RUNBOOKS_EXECUTED = Counter(
    "incident_bot_runbooks_executed_total",
    "Total number of runbook executions",
    ["runbook", "status", "triggered_by"],
)

# Recovery / retry hardening metrics
RUNBOOKS_RECOVERED = Counter(
    "incident_bot_runbooks_recovered_total",
    "Total runbook executions recovered by the recovery reconciler",
    ["reason"],
)

RUNBOOKS_RETRIED = Counter(
    "incident_bot_runbooks_retried_total",
    "Total number of retry attempts scheduled",
    ["runbook", "reason"],
)

RUNBOOKS_FAILED = Counter(
    "incident_bot_runbooks_failed_total",
    "Total number of runbook executions that ended failed/timeout (final)",
    ["runbook", "reason"],
)

RUNBOOK_CONFIRMATIONS_TOTAL = Counter(
    "incident_bot_runbook_confirmations_total",
    "Total number of runbook confirmations",
    ["runbook", "status", "actor"],
)

RUNBOOK_DURATION = Histogram(
    "incident_bot_runbook_duration_seconds",
    "Duration of runbook executions",
    ["runbook"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600],
)

RUNBOOKS_PENDING = Gauge(
    "incident_bot_runbooks_pending",
    "Number of runbooks pending execution",
)

RUNBOOKS_RUNNING = Gauge(
    "incident_bot_runbooks_running",
    "Number of runbooks currently running",
)

RUNBOOKS_PENDING_OLDEST_SECONDS = Gauge(
    "incident_bot_runbooks_pending_oldest_seconds",
    "Age in seconds of the oldest pending runbook execution (0 if none)",
)

RUNBOOKS_PENDING_STALE_TOTAL = Gauge(
    "incident_bot_runbooks_pending_stale_total",
    "Number of pending runbook executions older than the given threshold (seconds)",
    ["threshold"],
)

RUNBOOK_CONFIRMATION_LATENCY = Histogram(
    "incident_bot_runbook_confirmation_latency_seconds",
    "Latency between runbook pending started_at and confirmation confirmed_at",
    ["runbook"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 14400, 28800],
)

RUNBOOKS_RUNNING_OLDEST_SECONDS = Gauge(
    "incident_bot_runbooks_running_oldest_seconds",
    "Age in seconds of the oldest running runbook execution (0 if none)",
)

# ============================================================
# ALERT METRICS
# ============================================================

ALERTS_RECEIVED = Counter(
    "incident_bot_alerts_received_total",
    "Total alerts received from Alertmanager",
    ["alertname", "severity"],
)

ALERTS_PROCESSED = Counter(
    "incident_bot_alerts_processed_total",
    "Total alerts processed (deduplicated)",
    ["result"],  # 'new_incident', 'updated', 'resolved', 'ignored'
)

# ============================================================
# SYSTEM METRICS
# ============================================================

SYSTEM_STATUS = Gauge(
    "incident_bot_system_status",
    "Current system status (1=healthy, 0.5=degraded, 0=unhealthy)",
)

BOT_INFO = Info(
    "incident_bot",
    "Information about the incident bot",
)

# ============================================================
# CONTAINER MAPPING METRICS (Docker -> Human names)
# ============================================================

CONTAINER_INFO = Gauge(
    "incident_bot_container_info",
    "Mapping from Docker container full id to a human service name",
    ["cadvisor_id", "service"],
)

# ============================================================
# WEBHOOK METRICS
# ============================================================

WEBHOOK_REQUESTS = Counter(
    "incident_bot_webhook_requests_total",
    "Total webhook requests received",
    ["source", "status"],
)

WEBHOOK_LATENCY = Histogram(
    "incident_bot_webhook_latency_seconds",
    "Webhook processing latency",
    ["source"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)

# ============================================================
# NOTIFICATION METRICS
# ============================================================

NOTIFICATIONS_SENT = Counter(
    "incident_bot_notifications_sent_total",
    "Total notifications sent",
    ["channel", "type", "status"],
)

# ============================================================
# FAULT INJECTION (Synthetic Alerts)
# ============================================================

FAULT_INJECTOR = Gauge(
    "incident_bot_fault",
    "Synthetic fault injector (0/1)",
    ["type"],
)

# ============================================================
# AUDIT SNAPSHOT METRICS
# ============================================================

AUDIT_SNAPSHOT_DURATION = Histogram(
    "audit_snapshot_duration_seconds",
    "Time to build audit snapshot",
    buckets=[0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
)

AUDIT_SNAPSHOT_ERRORS_TOTAL = Counter(
    "audit_snapshot_errors_total",
    "Total errors while building audit snapshot",
    ["type", "block"],
)

AUDIT_SNAPSHOT_CACHE_HITS_TOTAL = Counter(
    "audit_snapshot_cache_hits_total",
    "Total cache hits for audit snapshot",
    ["kind"],  # fresh, stale, miss
)

AUDIT_SNAPSHOT_MODE_TOTAL = Counter(
    "audit_snapshot_mode_total",
    "Total snapshots built by mode (full/mini/unknown)",
    ["mode"],
)

# ============================================================
# RUNBOOK STALE THRESHOLDS (config) + SEED SERIES
# ============================================================


def _parse_stale_thresholds_seconds() -> list[int]:
    """
    Read thresholds from env (comma-separated seconds), fallback to 6h.
    Example: PENDING_STALE_THRESHOLDS_SECONDS=60,300,21600
    """
    raw = (os.getenv("PENDING_STALE_THRESHOLDS_SECONDS") or "").strip()
    if not raw:
        return [21600]  # 6h default

    out: list[int] = []
    for part in raw.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            v = int(p)
            if v > 0:
                out.append(v)
        except Exception:
            continue

    # unique + sorted for stable metric series
    out = sorted(set(out))
    return out or [21600]


# Thresholds (seconds) for stale pending volume metric (configurable).
PENDING_STALE_THRESHOLDS_SECONDS = _parse_stale_thresholds_seconds()

# Seed gauge series so it exists even when 0
for _t in PENDING_STALE_THRESHOLDS_SECONDS:
    RUNBOOKS_PENDING_STALE_TOTAL.labels(threshold=str(_t)).set(0)

# ============================================================
# AUDIT METRICS: SEED SERIES (so they exist before first snapshot)
# ============================================================

AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="fresh").inc(0)
AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="stale").inc(0)
AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="miss").inc(0)

AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_timeout", block="host").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_timeout", block="incidents").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_timeout", block="containers").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_timeout", block="containers_mini").inc(0)

AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_failed", block="host").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_failed", block="incidents").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_failed", block="containers").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="block_failed", block="containers_mini").inc(0)

AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="refresh_failed", block="refresh").inc(0)
AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(type="compute_failed", block="compute").inc(0)

AUDIT_SNAPSHOT_MODE_TOTAL.labels(mode="full").inc(0)
AUDIT_SNAPSHOT_MODE_TOTAL.labels(mode="mini").inc(0)
AUDIT_SNAPSHOT_MODE_TOTAL.labels(mode="unknown").inc(0)

# ============================================================
# METRICS COLLECTOR
# ============================================================


class MetricsCollector:
    """
    Collector and updater for Prometheus metrics.
    """

    def __init__(self):
        self._container_map: Dict[str, str] = {}  # cadvisor_id -> human

        # Initialize bot info
        BOT_INFO.info(
            {
                "version": "1.0.0",
                "app_name": settings.app_name,
                "environment": settings.app_env,
            }
        )

    # --------------------------------------------------------
    # RUNBOOK RECORDERS
    # --------------------------------------------------------

    def record_runbook_confirmation_latency(
        self,
        runbook: str,
        started_at_iso: str,
        confirmed_at_iso: str,
    ):
        """
        Record latency from pending started_at to confirmation confirmed_at.
        """
        try:
            if not started_at_iso or not confirmed_at_iso:
                return

            start = datetime.fromisoformat(started_at_iso)
            end = datetime.fromisoformat(confirmed_at_iso)

            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)

            latency = (end - start).total_seconds()
            if latency >= 0:
                RUNBOOK_CONFIRMATION_LATENCY.labels(runbook=str(runbook)).observe(
                    latency
                )
        except Exception:
            pass

    def record_runbook_execution(
        self,
        runbook: str,
        status: str,  # 'success', 'failed', 'timeout'
        triggered_by: str,
        duration_seconds: float,
    ):
        """Record a runbook execution."""
        RUNBOOKS_EXECUTED.labels(
            runbook=runbook, status=status, triggered_by=triggered_by
        ).inc()
        RUNBOOK_DURATION.labels(runbook=runbook).observe(duration_seconds)

    def record_runbook_recovered(self, reason: str):
        try:
            RUNBOOKS_RECOVERED.labels(reason=str(reason or "unknown")).inc()
        except Exception:
            pass

    def record_runbook_retried(self, runbook: str, reason: str):
        try:
            RUNBOOKS_RETRIED.labels(
                runbook=str(runbook or "unknown"),
                reason=str(reason or "unknown"),
            ).inc()
        except Exception:
            pass

    def record_runbook_failed_final(self, runbook: str, reason: str):
        try:
            RUNBOOKS_FAILED.labels(
                runbook=str(runbook or "unknown"),
                reason=str(reason or "unknown"),
            ).inc()
        except Exception:
            pass

    def record_runbook_confirmation(self, runbook: str, status: str, actor: str):
        """Record a runbook confirmation (human approval)."""
        try:
            RUNBOOK_CONFIRMATIONS_TOTAL.labels(
                runbook=str(runbook or "unknown"),
                status=str(status or "unknown"),
                actor=str(actor or "unknown"),
            ).inc()
        except Exception:
            # Never break requests due to metrics
            pass

    # --------------------------------------------------------
    # INCIDENT RECORDERS
    # --------------------------------------------------------

    def record_incident_created(self, severity: str):
        """Record a new incident."""
        sev = str(severity).lower()
        sev = {"0": "info", "1": "warning", "2": "critical"}.get(sev, sev)
        INCIDENTS_TOTAL.labels(severity=sev, status="created").inc()

    def record_incident_resolved(self, severity: str, duration_seconds: float):
        """Record an incident resolution."""
        sev = str(severity).lower()
        sev = {"0": "info", "1": "warning", "2": "critical"}.get(sev, sev)
        INCIDENTS_TOTAL.labels(severity=sev, status="resolved").inc()
        INCIDENT_DURATION.labels(severity=sev).observe(duration_seconds)

    def set_active_incidents(self, severity: str, count: int):
        sev = str(severity).lower()
        sev = {"0": "info", "1": "warning", "2": "critical"}.get(sev, sev)
        INCIDENTS_ACTIVE.labels(severity=sev).set(count)

    # --------------------------------------------------------
    # ALERT RECORDERS
    # --------------------------------------------------------

    def record_alert_received(self, alertname: str, severity: str):
        """Record an alert received from Alertmanager."""
        ALERTS_RECEIVED.labels(alertname=alertname, severity=severity).inc()

    def record_alert_processed(self, result: str):
        """Record how an alert was processed."""
        ALERTS_PROCESSED.labels(result=result).inc()

    # --------------------------------------------------------
    # WEBHOOK RECORDERS
    # --------------------------------------------------------

    def record_webhook_request(self, source: str, status: str, latency_seconds: float):
        """Record a webhook request."""
        WEBHOOK_REQUESTS.labels(source=source, status=status).inc()
        WEBHOOK_LATENCY.labels(source=source).observe(latency_seconds)

    # --------------------------------------------------------
    # NOTIFICATION RECORDERS
    # --------------------------------------------------------

    def record_notification_sent(
        self,
        channel: str,  # 'telegram'
        notification_type: str,  # 'incident', 'runbook', 'status'
        success: bool,
    ):
        """Record a notification sent."""
        NOTIFICATIONS_SENT.labels(
            channel=channel,
            type=notification_type,
            status="success" if success else "failed",
        ).inc()

    # --------------------------------------------------------
    # SYSTEM STATUS
    # --------------------------------------------------------

    def update_system_status(self, status: str):
        """Update current system status."""
        status_values = {
            "healthy": 1.0,
            "degraded": 0.5,
            "critical": 0.1,
            "unhealthy": 0.0,
        }
        SYSTEM_STATUS.set(status_values.get(status, 0.0))

    # --------------------------------------------------------
    # RUNBOOK QUEUE GAUGES
    # --------------------------------------------------------

    def set_pending_runbooks(self, count: int):
        """Set the count of pending runbooks."""
        RUNBOOKS_PENDING.set(count)

    def set_running_runbooks(self, count: int):
        """Set the count of running runbooks."""
        RUNBOOKS_RUNNING.set(count)

    async def refresh_runbook_queue_metrics_from_db(self, db_path: str) -> None:
        """
        Source of truth: DB.
        Updates RUNBOOKS_PENDING and RUNBOOKS_RUNNING from runbook_executions.status.
        """
        try:
            async with aiosqlite.connect(db_path) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("PRAGMA journal_mode=WAL;")
                await db.execute("PRAGMA busy_timeout = 5000;")
                await db.execute("PRAGMA foreign_keys=ON;")
                await db.execute("PRAGMA synchronous=NORMAL;")

                pending = 0
                running = 0
                pending_oldest = 0.0
                running_oldest = 0.0

                # Stale totals by threshold (volume/backlog signal)
                stale_counts = {t: 0 for t in PENDING_STALE_THRESHOLDS_SECONDS}

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

                # Pending oldest + stale volume (computed in Python for robustness)
                now = datetime.now(timezone.utc)
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
                    try:
                        dt = datetime.fromisoformat(raw)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)

                        age_s = (now - dt).total_seconds()

                        if age_s < 0:
                            # Clock skew or invalid timestamps; ignore negatives
                            continue

                        ages.append(age_s)

                        for t in stale_counts.keys():
                            if age_s >= float(t):
                                stale_counts[t] += 1

                    except Exception:
                        continue

                pending_oldest = float(max(ages)) if ages else 0.0

                # Oldest running age (seconds)
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
                    try:
                        dt = datetime.fromisoformat(raw)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)

                        age_s = (now - dt).total_seconds()

                        if age_s >= 0:
                            run_ages.append(age_s)

                    except Exception:
                        continue

                running_oldest = float(max(run_ages)) if run_ages else 0.0

            # Set gauges
            self.set_pending_runbooks(pending)
            self.set_running_runbooks(running)
            RUNBOOKS_PENDING_OLDEST_SECONDS.set(pending_oldest)
            RUNBOOKS_RUNNING_OLDEST_SECONDS.set(running_oldest)

            # Set stale totals
            try:
                for t, c in stale_counts.items():
                    RUNBOOKS_PENDING_STALE_TOTAL.labels(threshold=str(t)).set(int(c))
            except Exception:
                pass

        except Exception:
            # Do not break the app because of metrics
            return

    def start_runbook_queue_metrics_loop(
        self,
        db_path: str,
        interval_seconds: int = 5,
    ):
        """
        Background loop (async) that keeps runbook pending/running gauges in sync with DB.
        Returns an asyncio.Task (to cancel on shutdown).
        """

        async def _loop():
            while True:
                await self.refresh_runbook_queue_metrics_from_db(db_path)
                await asyncio.sleep(interval_seconds)

        return asyncio.create_task(_loop(), name="runbook-queue-metrics-db")

    # --------------------------------------------------------
    # PROMETHEUS EXPORT
    # --------------------------------------------------------

    def get_metrics(self) -> bytes:
        """Generate current metrics in Prometheus format."""
        return generate_latest()

    @property
    def content_type(self) -> str:
        """Get the Prometheus content type."""
        return CONTENT_TYPE_LATEST

    # --------------------------------------------------------
    # CONTAINER MAPPING (Docker)
    # --------------------------------------------------------

    def resolve_container_name(self, cadvisor_id: str) -> str:
        return self._container_map.get(cadvisor_id, "")

    def _docker_client(self):
        """
        Lazy import docker client to avoid dependency issues at import time.
        Requires: docker (pip install docker)
        """
        try:
            import docker  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "Docker SDK not available. Install with: pip install docker"
            ) from e
        return docker.from_env()

    def update_container_mapping(self) -> Dict[str, str]:
        """
        Publish mapping: cadvisor_id (/docker/<full_id>) -> human service name (incidentbot.<service>).
        Returns dict {cadvisor_id: human}
        """
        client = self._docker_client()

        mapping: Dict[str, str] = {}
        containers = client.containers.list(all=True)

        # Clear old series
        try:
            CONTAINER_INFO.clear()
        except Exception:
            pass

        for c in containers:
            full_id = getattr(c, "id", None)
            if not full_id:
                continue

            labels = getattr(c, "labels", {}) or {}
            service = labels.get("com.docker.compose.service") or getattr(
                c, "name", "unknown"
            )
            project = labels.get("com.docker.compose.project") or "incidentbot"

            human = f"{project}.{service}"  # -> incidentbot.prometheus, etc.
            cadvisor_id = f"/docker/{full_id}"

            CONTAINER_INFO.labels(cadvisor_id=cadvisor_id, service=human).set(1)
            mapping[cadvisor_id] = human

        self._container_map = mapping
        return mapping

    def start_container_mapper_loop(self, interval_seconds: int = 30):
        def _loop():
            while True:
                try:
                    _ = self.update_container_mapping()
                except Exception as e:
                    print("container_mapper_error:", repr(e))
                time.sleep(interval_seconds)

        t = threading.Thread(target=_loop, daemon=True, name="container-mapper")
        t.start()

    # --------------------------------------------------------
    # FAULT INJECTION
    # --------------------------------------------------------

    def set_fault(self, fault_type: str, active: bool):
        FAULT_INJECTOR.labels(type=fault_type).set(1 if active else 0)


# ============================================================
# GLOBAL INSTANCE
# ============================================================

metrics_collector = MetricsCollector()
