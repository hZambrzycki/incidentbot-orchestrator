from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(IntEnum):
    """Alert/Incident severity levels."""

    INFO = 0
    WARNING = 1
    CRITICAL = 2


class IncidentStatus(str, Enum):
    """Status of an incident."""

    FIRING = "firing"
    INVESTIGATING = "investigating"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class RunbookStatus(str, Enum):
    """Status of a runbook execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


# ===========================================
# Runbook Models (moved up so Incident can reference)
# ===========================================


class RunbookDefinition(BaseModel):
    """Definition of an available runbook."""

    name: str
    description: str
    category: str = "general"
    severity_threshold: Severity = Severity.WARNING  # Minimum severity to auto-execute
    auto_execute: bool = True
    requires_confirmation: bool = False
    timeout: int = 300  # seconds
    allowed_services: List[str] = Field(
        default_factory=lambda: ["*"]
    )  # Services this runbook can target
    parameters: Dict[str, Any] = Field(default_factory=dict)  # Expected parameters


ExecutionOrigin = Literal["alert", "human", "api", "recovery", "system"]
TriggeredBy = Literal["system", "telegram", "api", "human"]


class RunbookExecution(BaseModel):
    """Record of a runbook execution."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    runbook_name: str
    incident_id: Optional[str] = None
    status: RunbookStatus = RunbookStatus.PENDING
    target_service: Optional[str] = None
    target_instance: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    output: str = ""
    error: Optional[str] = None

    triggered_by: TriggeredBy = "system"
    execution_origin: ExecutionOrigin = "system"

    # -------------------------------------------------
    # Validators
    # -------------------------------------------------
    @field_validator("triggered_by", mode="before")
    @classmethod
    def _normalize_triggered_by(cls, v: Any):
        """
        Legacy-proof triggered_by:
        - NULL/""/unknown values won't crash pydantic validation
        - "recovery" is NOT a TriggeredBy (it's an ExecutionOrigin) -> coerce to "system"
        """
        if v is None:
            return "system"
        if isinstance(v, str):
            vv = v.strip().lower()
            if not vv:
                return "system"
            if vv == "recovery":
                return "system"
            if vv in ("system", "telegram", "api", "human"):
                return vv
            return "system"
        return "system"

    retry_of_execution_id: Optional[str] = None
    confirmed_execution_id: Optional[str] = None
    confirmed_by: Optional[str] = None

    confirmed_at: Optional[datetime] = None

    @field_validator("confirmed_at", mode="before")
    @classmethod
    def _compat_confirmed_at(cls, v, info):
        if v is not None:
            return v
        if isinstance(info.data, dict) and info.data.get("onfirmed_at"):
            return info.data.get("onfirmed_at")
        return None

    @field_validator("execution_origin", mode="before")
    @classmethod
    def _normalize_execution_origin(cls, v, info):
        # 1) legacy DB: null/"" -> derive from triggered_by if possible
        if v is None or (isinstance(v, str) and not v.strip()):
            tb = None
            if isinstance(info.data, dict):
                tb = info.data.get("triggered_by")
            # decide mapping
            if tb in ("human", "api", "system"):
                return tb
            if tb == "telegram":
                # telegram is channel, not "origin" > system by default
                return "system"
            return "system"

        if isinstance(v, str):
            vv = v.strip().lower()
            if vv == "manual":
                return "human"
            if vv in ("alert", "human", "api", "recovery", "system"):
                return vv
            # unknown -> system
            return "system"

        return "system"

    def complete(self, success: bool, output: str = "", error: Optional[str] = None):
        self.completed_at = utcnow()
        self.status = RunbookStatus.SUCCESS if success else RunbookStatus.FAILED
        self.output = output
        self.error = error

    def mark_pending(self, message: str):
        self.status = RunbookStatus.PENDING
        self.output = message
        self.error = None
        self.completed_at = None

    def mark_running(self):
        self.status = RunbookStatus.RUNNING
        self.error = None

    def mark_timeout(self, error: str):
        self.status = RunbookStatus.TIMEOUT
        self.error = error
        self.completed_at = utcnow()

    def mark_skipped(self, output: str = ""):
        self.status = RunbookStatus.SKIPPED
        self.output = output
        self.completed_at = utcnow()

    @property
    def duration_seconds(self) -> float:
        end_time = self.completed_at or utcnow()
        return (end_time - self.started_at).total_seconds()


# ===========================================
# Alertmanager Models
# ===========================================


class AlertLabel(BaseModel):
    """Labels from Prometheus alert."""

    alertname: str
    severity: str = "warning"
    instance: Optional[str] = None
    job: Optional[str] = None
    service: Optional[str] = None

    # Allow extra labels
    class Config:
        extra = "allow"


class AlertAnnotation(BaseModel):
    """Annotations from Prometheus alert."""

    summary: Optional[str] = None
    description: Optional[str] = None
    runbook: Optional[str] = None  # Suggested runbook to execute

    class Config:
        extra = "allow"


class Alert(BaseModel):
    """Single alert from Alertmanager."""

    status: str  # "firing" or "resolved"
    labels: Dict[str, str]
    annotations: Dict[str, str] = Field(default_factory=dict)
    startsAt: str
    endsAt: Optional[str] = None
    generatorURL: Optional[str] = None
    fingerprint: Optional[str] = None

    @property
    def alertname(self) -> str:
        return self.labels.get("alertname", "unknown")

    @property
    def severity(self) -> Severity:
        sev = (self.labels.get("severity") or "warning").lower()

        mapping = {
            "info": Severity.INFO,
            "0": Severity.INFO,
            "warning": Severity.WARNING,
            "warn": Severity.WARNING,
            "1": Severity.WARNING,
            "critical": Severity.CRITICAL,
            "crit": Severity.CRITICAL,
            "error": Severity.CRITICAL,
            "2": Severity.CRITICAL,
        }

        return mapping.get(sev, Severity.WARNING)

    @property
    def instance(self) -> Optional[str]:
        return self.labels.get("instance")

    @property
    def service(self) -> Optional[str]:
        return self.labels.get("service")

    @property
    def summary(self) -> str:
        return self.annotations.get("summary", self.alertname)

    @property
    def description(self) -> str:
        return self.annotations.get("description", "No description available")

    @property
    def suggested_runbook(self) -> Optional[str]:
        return self.annotations.get("runbook")


class AlertmanagerWebhook(BaseModel):
    """Webhook payload from Alertmanager."""

    version: str = "4"
    groupKey: str
    status: str  # "firing" or "resolved"
    receiver: str
    groupLabels: Dict[str, str] = Field(default_factory=dict)
    commonLabels: Dict[str, str] = Field(default_factory=dict)
    commonAnnotations: Dict[str, str] = Field(default_factory=dict)
    externalURL: Optional[str] = None
    alerts: List[Alert]

    @property
    def is_firing(self) -> bool:
        return self.status == "firing"

    @property
    def firing_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if a.status == "firing"]

    @property
    def resolved_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if a.status == "resolved"]


# ===========================================
# Incident Models
# ===========================================


class IncidentEpisode(BaseModel):
    started_at: datetime
    resolved_at: Optional[datetime] = None
    error_type: Optional[str] = None
    summary: Optional[str] = None


class Incident(BaseModel):
    """An incident tracked by the system."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    description: str = ""
    severity: Severity = Severity.WARNING
    status: IncidentStatus = IncidentStatus.FIRING
    source_alert: Optional[str] = None  # Alert fingerprint
    service: Optional[str] = None
    instance: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    resolved_at: Optional[datetime] = None
    last_fired_at: datetime = Field(default_factory=utcnow)
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    runbooks_executed: List[str] = Field(default_factory=list)
    runbook_executions: List[RunbookExecution] = Field(default_factory=list)

    diagnosis: Optional[str] = None
    reopen_count: int = 0
    episodes: List[IncidentEpisode] = Field(default_factory=list)
    error_type: Optional[str] = None
    error_summary: Optional[str] = None
    last_processed_at: Optional[datetime] = None

    def update_status(self, new_status: IncidentStatus):
        self.status = new_status
        self.updated_at = utcnow()
        if new_status == IncidentStatus.RESOLVED:
            # idempotence: do not rewrite if it was already resolved
            if self.resolved_at is None:
                self.resolved_at = utcnow()
            # close open episode (if any)
            if self.episodes:
                last = self.episodes[-1]
                if last.resolved_at is None:
                    last.resolved_at = self.resolved_at

    @property
    def is_active(self) -> bool:
        return self.status not in [IncidentStatus.RESOLVED]

    @property
    def duration_seconds(self) -> float:
        end_time = self.resolved_at or utcnow()
        return (end_time - self.created_at).total_seconds()

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        emoji = {Severity.INFO: "ℹ️", Severity.WARNING: "⚠️", Severity.CRITICAL: "🔴"}
        status_emoji = {
            IncidentStatus.FIRING: "🔥",
            IncidentStatus.INVESTIGATING: "🔍",
            IncidentStatus.REMEDIATING: "🔧",
            IncidentStatus.RESOLVED: "✅",
            IncidentStatus.ESCALATED: "📢",
        }
        return (
            f"{emoji.get(self.severity, '❓')} {status_emoji.get(self.status, '❓')} "
            f"[{self.id}] {self.title}\n"
            f"Severity: {self.severity.value} | Status: {self.status.value}\n"
            f"Service: {self.service or 'N/A'} | Instance: {self.instance or 'N/A'}"
        )


# ===========================================
# System Status Models
# ===========================================


class SystemMetrics(BaseModel):
    """Current system metrics."""

    cpu_percent: float
    memory_percent: float
    disk_percent: float
    load_average: List[float]
    uptime_seconds: float
    collected_at: datetime = Field(default_factory=utcnow)


class SystemStatus(BaseModel):
    """Overall system status."""

    status: str = "healthy"  # healthy, degraded, critical
    active_incidents: int = 0
    total_incidents_today: int = 0
    runbooks_executed_today: int = 0
    last_incident_at: Optional[datetime] = None
    metrics: Optional[SystemMetrics] = None


# ===========================================
# API Response Models
# ===========================================


class APIResponse(BaseModel):
    """Standard API response."""

    success: bool
    message: str
    data: Optional[Any] = None


class IncidentListResponse(BaseModel):
    """Response for listing incidents."""

    total: int
    active: int
    incidents: List[Incident]


class RunbookListResponse(BaseModel):
    """Response for listing available runbooks."""

    runbooks: List[RunbookDefinition]


# ===========================================
# Audit Log Models
# ===========================================


class AuditLogEntry(BaseModel):
    """Entry in the audit log."""

    timestamp: datetime = Field(default_factory=utcnow)
    event_type: str
    actor: str  # Who triggered the action
    resource_type: str  # incident, runbook, etc.
    resource_id: Optional[str] = None
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    success: bool = True
