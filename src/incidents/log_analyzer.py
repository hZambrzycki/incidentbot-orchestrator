"""
Log Analyzer - System diagnostics and log analysis.
Provides automated analysis of system logs and metrics.
"""

# ===========================================
# Imports
# ===========================================

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.core.logging_config import get_logger
from src.core.models import Incident, SystemMetrics
from src.observability.metrics_collector import metrics_collector

# ===========================================
# Module-level setup
# ===========================================

logger = get_logger("log_analyzer")


# ===========================================
# Data models
# ===========================================


@dataclass
class LogEntry:
    """Parsed log entry."""

    timestamp: Optional[datetime]
    level: str
    message: str
    source: str
    raw: str


@dataclass
class DiagnosisResult:
    """Result of diagnostic analysis."""

    summary: str
    details: List[str]
    suggested_actions: List[str]
    error_patterns: List[str]
    metrics: Optional[SystemMetrics]


# ===========================================
# Log analyzer
# ===========================================


class LogAnalyzer:
    """
    Analyzes system logs and provides diagnostic information.

    Features:
    - Query journalctl for system/service logs
    - Parse and filter log entries
    - Identify error patterns
    - Collect system metrics
    """

    # Common error patterns to look for
    ERROR_PATTERNS = [
        (r"out of memory", "OOM - System out of memory"),
        (r"connection refused", "Connection refused"),
        (r"connection timeout", "Connection timeout"),
        (r"disk.*full|no space left", "Disk full"),
        (r"permission denied", "Permission denied"),
        (r"segmentation fault|segfault", "Segmentation fault"),
        (r"killed process", "Process killed (OOM killer)"),
        (r"failed to start", "Failed to start service"),
        (r"cpu.*high|high.*cpu", "High CPU"),
        (r"too many open files", "Too many open files"),
    ]

    # ---------------------------------------
    # Construction
    # ---------------------------------------

    def __init__(self):
        self._command_timeout = 30  # seconds

    # ---------------------------------------
    # Public API: incident diagnosis
    # ---------------------------------------

    async def diagnose_incident(self, incident: Incident) -> DiagnosisResult:
        """
        Perform full diagnosis for an incident.
        Collects logs, metrics, and identifies potential issues.
        """
        details: List[str] = []
        error_patterns: List[str] = []
        suggested_actions: List[str] = []

        # 1) Collect system metrics
        metrics = await self.get_system_metrics()
        if metrics:
            details.append(f"CPU: {metrics.cpu_percent:.1f}%")
            details.append(f"Memory: {metrics.memory_percent:.1f}%")
            details.append(f"Disk: {metrics.disk_percent:.1f}%")

            # Check for resource issues
            if metrics.cpu_percent > 90:
                error_patterns.append("CPU very high")
                suggested_actions.append("restart_service")
            if metrics.memory_percent > 90:
                error_patterns.append("Critical memory")
                suggested_actions.append("restart_service")
            if metrics.disk_percent > 90:
                error_patterns.append("Disk almost full")
                suggested_actions.append("cleanup_disk")

        # 2) Get service logs if service is known
        svc = (incident.service or "").strip()
        if svc and svc not in {"disk", "system", "incident-bot"}:
            logs = await self.get_service_logs(svc, lines=50)
            if logs:
                # Analyze logs for errors
                for entry in logs:
                    for pattern, desc in self.ERROR_PATTERNS:
                        if re.search(pattern, entry.message, re.IGNORECASE):
                            if desc not in error_patterns:
                                error_patterns.append(desc)

                # Add recent errors to details
                errors = [l for l in logs if l.level in ["ERROR", "CRIT", "ALERT"]]
                if errors:
                    details.append(f"Recent errors: {len(errors)}")
                    for err in errors[:3]:  # Show first 3
                        details.append(f"  - {err.message[:100]}")

        # 2b) Docker logs if the alert includes id=/docker/<hash>
        cid = (incident.labels or {}).get("id") or ""
        m = re.match(r"^/docker/([0-9a-f]{64})$", cid)
        if m:
            full_id = m.group(1)
            human = metrics_collector.resolve_container_name(f"/docker/{full_id}")
            if human:
                details.append(f"Container: {human}")

            docker_logs = await self.get_docker_logs(full_id, lines=80)
            if docker_logs:
                details.append(f"Docker logs (tail {len(docker_logs)}):")
                interesting = [
                    e
                    for e in docker_logs
                    if re.search(r"error|fail|exception", e.message, re.I)
                ]
                for e in interesting[:3] or docker_logs[-3:]:
                    details.append(f"  - {e.message[:120]}")

                for entry in docker_logs:
                    for pattern, desc in self.ERROR_PATTERNS:
                        if re.search(pattern, entry.message, re.IGNORECASE):
                            if desc not in error_patterns:
                                error_patterns.append(desc)

        # 3) Get system logs
        system_logs = await self.get_system_logs(lines=20)
        for entry in system_logs:
            for pattern, desc in self.ERROR_PATTERNS:
                if re.search(pattern, entry.message, re.IGNORECASE):
                    if desc not in error_patterns:
                        error_patterns.append(desc)

        # Generate summary
        if error_patterns:
            summary = f"Detected issues: {', '.join(error_patterns[:3])}"
        else:
            summary = "No known error patterns detected"

        # Add default action if none suggested
        if not suggested_actions:
            suggested_actions.append("health_check")

        return DiagnosisResult(
            summary=summary,
            details=details,
            suggested_actions=suggested_actions,
            error_patterns=error_patterns,
            metrics=metrics,
        )

    # ---------------------------------------
    # Public API: metrics
    # ---------------------------------------

    async def get_system_metrics(self) -> Optional[SystemMetrics]:
        """Collect current system metrics."""
        try:
            import psutil

            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            load_avg = list(psutil.getloadavg())
            boot_time = psutil.boot_time()
            uptime = datetime.now().timestamp() - boot_time

            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_percent=disk.percent,
                load_average=load_avg,
                uptime_seconds=uptime,
            )
        except Exception as e:
            logger.error("failed_to_get_metrics", error=str(e))
            return None

    # ---------------------------------------
    # Public API: log retrieval
    # ---------------------------------------

    async def get_service_logs(
        self, service: str, lines: int = 50, since: str = "1h ago"
    ) -> List[LogEntry]:
        """Get logs for a specific service using journalctl."""
        service = self._sanitize_input(service)

        cmd = [
            "journalctl",
            "-u",
            service,
            "-n",
            str(lines),
            "--since",
            since,
            "--no-pager",
            "-o",
            "short-iso",
        ]

        return await self._run_journalctl(cmd)

    async def get_system_logs(
        self, lines: int = 50, priority: str = "err"
    ) -> List[LogEntry]:
        """Get system-wide logs with specified priority."""
        cmd = [
            "journalctl",
            "-p",
            priority,
            "-n",
            str(lines),
            "--no-pager",
            "-o",
            "short-iso",
        ]

        return await self._run_journalctl(cmd)

    async def get_docker_logs(self, container: str, lines: int = 80) -> List[LogEntry]:
        """Get logs for a Docker container (via Docker SDK)."""
        container = self._sanitize_input(container)
        try:
            import docker  # type: ignore

            client = docker.from_env()
            c = client.containers.get(container)
            raw = c.logs(tail=lines).decode(errors="replace").splitlines()
            return [
                LogEntry(
                    timestamp=None,
                    level="INFO",
                    message=line,
                    source=f"docker:{container}",
                    raw=line,
                )
                for line in raw
                if line.strip()
            ]
        except asyncio.TimeoutError:
            logger.error("docker_logs_timeout", container=container)
            return []
        except Exception as e:
            logger.error("docker_logs_failed", container=container, error=str(e))
            return []

    async def search_logs(
        self, pattern: str, service: Optional[str] = None, lines: int = 20
    ) -> List[LogEntry]:
        """Search logs for a specific pattern."""
        pattern = self._sanitize_input(pattern)

        cmd = ["journalctl", "-n", str(lines), "--no-pager", "-o", "short-iso"]
        if service:
            cmd.extend(["-u", self._sanitize_input(service)])
        cmd.extend(["--grep", pattern])

        return await self._run_journalctl(cmd)

    async def get_disk_usage(self) -> Dict[str, Any]:
        """Get detailed disk usage information."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "df",
                "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self._command_timeout
            )

            lines = stdout.decode().strip().split("\n")
            result: Dict[str, Any] = {"filesystems": []}

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    result["filesystems"].append(
                        {
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_percent": parts[4],
                            "mounted_on": parts[5],
                        }
                    )

            return result

        except Exception as e:
            logger.error("disk_usage_failed", error=str(e))
            return {"filesystems": [], "error": str(e)}

    # ---------------------------------------
    # Internals: journalctl execution/parsing
    # ---------------------------------------

    async def _run_journalctl(self, cmd: List[str]) -> List[LogEntry]:
        """Execute a journalctl command and parse output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._command_timeout
            )

            if proc.returncode != 0:
                logger.warning(
                    "journalctl_warning",
                    cmd=" ".join(cmd),
                    stderr=stderr.decode()[:200],
                )

            return self._parse_journalctl_output(stdout.decode())

        except asyncio.TimeoutError:
            logger.error("journalctl_timeout", cmd=" ".join(cmd))
            return []
        except FileNotFoundError:
            logger.warning("journalctl_not_found")
            return []
        except Exception as e:
            logger.error("journalctl_failed", error=str(e))
            return []

    def _parse_journalctl_output(self, output: str) -> List[LogEntry]:
        """Parse journalctl output into LogEntry objects."""
        entries: List[LogEntry] = []

        for line in output.split("\n"):
            if not line.strip():
                continue

            # Try to parse timestamp and level
            # Format: 2024-01-15T10:30:00+0000 hostname service[pid]: message
            timestamp: Optional[datetime] = None
            level = "INFO"
            message = line
            source = "system"

            # Try ISO timestamp format
            iso_match = re.match(
                r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$",
                line,
            )
            if iso_match:
                try:
                    timestamp = datetime.fromisoformat(
                        iso_match.group(1).replace("+0000", "+00:00")
                    )
                except Exception:
                    pass
                source = iso_match.group(3)
                message = iso_match.group(4)

            # Detect log level from message
            if re.search(r"\b(ERROR|ERR)\b", message, re.IGNORECASE):
                level = "ERROR"
            elif re.search(r"\b(WARN|WARNING)\b", message, re.IGNORECASE):
                level = "WARNING"
            elif re.search(r"\b(CRIT|CRITICAL|FATAL)\b", message, re.IGNORECASE):
                level = "CRIT"
            elif re.search(r"\bDEBUG\b", message, re.IGNORECASE):
                level = "DEBUG"

            entries.append(
                LogEntry(
                    timestamp=timestamp,
                    level=level,
                    message=message,
                    source=source,
                    raw=line,
                )
            )

        return entries

    # ---------------------------------------
    # Internals: sanitization
    # ---------------------------------------

    def _sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent command injection."""
        # Remove dangerous characters
        return re.sub(r'[;&|`$(){}[\]<>\'"\\\n\r]', "", value)[:100]


# ===========================================
# Singleton
# ===========================================

log_analyzer = LogAnalyzer()
