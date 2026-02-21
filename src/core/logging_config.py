"""
Structured logging configuration for Incident Bot.
Uses structlog for JSON-formatted, context-rich logging.
"""

# ===========================================
# Imports
# ===========================================

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from structlog.processors import TimeStamper

from .config import settings

# ===========================================
# Structlog setup
# ===========================================


def setup_logging(log_file: Optional[str] = None):
    """Configure structured logging for the application."""

    # Create log directory if needed (note: stdout logging by default)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        TimeStamper(fmt="iso"),
    ]

    if settings.log_format == "json":
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = shared_processors + [structlog.dev.ConsoleRenderer(colors=True)]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Standard logging (third-party libs)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level),
    )

    # Reduce noise from http clients / servers (keeps structlog output cleaner)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    return structlog.get_logger()


def get_logger(name: Optional[str] = None):
    """Get a logger instance."""
    logger = structlog.get_logger()
    if name:
        logger = logger.bind(component=name)
    return logger


# ===========================================
# Audit logger
# ===========================================


class AuditLogger:
    """
    Dedicated logger for audit events.
    Writes to a separate audit log file with structured data.
    """

    def __init__(self, audit_file: Optional[str] = None):
        self.audit_file = audit_file or settings.audit_log_file
        self.logger = get_logger("audit")

        if self.audit_file:
            Path(self.audit_file).parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event_type: str,
        actor: str,
        resource_type: str,
        action: str,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
    ):
        """Log an audit event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "details": details or {},
            "ip_address": ip_address,
            "success": success,
        }

        self.logger.info("audit_event", **entry)

        # Also write to dedicated audit file
        if self.audit_file:
            try:
                import json

                with open(self.audit_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception as e:
                self.logger.error("failed_to_write_audit_log", error=str(e))

    def runbook_executed(
        self,
        runbook_name: str,
        triggered_by: str,
        incident_id: Optional[str] = None,
        target: Optional[str] = None,
        success: bool = True,
        duration_ms: Optional[int] = None,
    ):
        """Log a runbook execution."""
        self.log(
            event_type="runbook_execution",
            actor=triggered_by,
            resource_type="runbook",
            resource_id=runbook_name,
            action="execute",
            details={
                "incident_id": incident_id,
                "target": target,
                "duration_ms": duration_ms,
            },
            success=success,
        )

    def incident_created(
        self, incident_id: str, title: str, severity: str, source: str = "alertmanager"
    ):
        """Log incident creation."""
        self.log(
            event_type="incident_lifecycle",
            actor=source,
            resource_type="incident",
            resource_id=incident_id,
            action="create",
            details={"title": title, "severity": severity},
        )

    def incident_status_changed(
        self, incident_id: str, old_status: str, new_status: str, actor: str = "system"
    ):
        """Log incident status change."""
        self.log(
            event_type="incident_lifecycle",
            actor=actor,
            resource_type="incident",
            resource_id=incident_id,
            action="status_change",
            details={"old_status": old_status, "new_status": new_status},
        )

    def api_request(
        self,
        endpoint: str,
        method: str,
        ip_address: str,
        success: bool = True,
        actor: str = "api_client",
    ):
        """Log API request."""
        self.log(
            event_type="api_access",
            actor=actor,
            resource_type="api",
            resource_id=endpoint,
            action=method,
            ip_address=ip_address,
            success=success,
        )


# ===========================================
# Singletons
# ===========================================

audit_logger = AuditLogger()
