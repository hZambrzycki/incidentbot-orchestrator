"""
Runbook: Restart Service
Safely restarts a systemd or Docker service.
"""

# ===========================================
# Imports
# ===========================================

import asyncio
import re
import sys
from dataclasses import dataclass
from typing import Optional

from src.core.logging_config import get_logger
from src.core.models import Severity
from src.runbooks.registry import runbook

# ===========================================
# Logger
# ===========================================

logger = get_logger("runbook.restart_service")


# ===========================================
# Result Model
# ===========================================


@dataclass
class RestartResult:
    """Result of a service restart."""

    success: bool
    status: str  # "ok", "failed", "skipped", "degraded"
    message: str
    service_type: str  # "systemd" or "docker"
    previous_state: Optional[str] = None
    current_state: Optional[str] = None


# ===========================================
# Allowlist Configuration
# ===========================================

ALLOWED_SYSTEMD_SERVICES = [
    "nginx",
    "apache2",
    "httpd",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "memcached",
    "rabbitmq-server",
    "elasticsearch",
    "kibana",
    "grafana-server",
    "prometheus",
    "alertmanager",
    "node_exporter",
    "docker",
]

ALLOWED_DOCKER_CONTAINERS = [
    "nginx",
    "redis",
    "postgres",
    "mysql",
    "prometheus",
    "alertmanager",
    "grafana",
    "elasticsearch",
    "kibana",
    "app",
    "api",
    "web",
    "worker",
]


# ===========================================
# Helper Functions
# ===========================================


def _sanitize_service_name(name: str) -> str:
    """Sanitize service name to prevent injection."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", name)[:50]


async def _get_systemd_status(service: str) -> Optional[str]:
    """Get the current status of a systemd service."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl",
            "is-active",
            service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return stdout.decode().strip()
    except FileNotFoundError:
        return "__SYSTEMCTL_MISSING__"
    except (asyncio.TimeoutError, OSError, ValueError) as e:
        logger.debug("systemd_status_failed", service=service, error=str(e))
        return None


async def _get_docker_status(container: str) -> Optional[str]:
    """Get the current status of a Docker container."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "inspect",
            "-f",
            "{{.State.Status}}",
            container,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return stdout.decode().strip()
    except FileNotFoundError:
        return None
    except (asyncio.TimeoutError, OSError, ValueError) as e:
        logger.debug("docker_status_failed", container=container, error=str(e))
        return None


# ===========================================
# Core Restart Implementations
# ===========================================


async def _restart_systemd_service(service: str) -> RestartResult:
    """Restart a systemd service."""
    service = _sanitize_service_name(service)

    if service not in ALLOWED_SYSTEMD_SERVICES:
        return RestartResult(
            success=False,
            status="failed",
            message=f"Service '{service}' not in allowlist",
            service_type="systemd",
        )

    previous_state = await _get_systemd_status(service)

    if previous_state == "__SYSTEMCTL_MISSING__":
        return RestartResult(
            success=False,
            status="skipped",
            message="systemctl not available (skipped)",
            service_type="systemd",
        )

    if previous_state is None:
        return RestartResult(
            success=False,
            status="failed",
            message="Unable to read systemd status",
            service_type="systemd",
        )

    logger.info(
        "restarting_systemd_service",
        service=service,
        previous_state=previous_state,
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl",
            "restart",
            service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        if proc.returncode != 0:
            err = stderr.decode().strip()
            return RestartResult(
                success=False,
                status="failed",
                message=f"Failed to restart: {err}",
                service_type="systemd",
                previous_state=previous_state,
            )

        await asyncio.sleep(2)

        current_state = await _get_systemd_status(service)

        if current_state == "active":
            return RestartResult(
                success=True,
                status="ok",
                message=f"Service {service} restarted successfully",
                service_type="systemd",
                previous_state=previous_state,
                current_state=current_state,
            )

        return RestartResult(
            success=False,
            status="failed",
            message=f"Service restarted but state is: {current_state}",
            service_type="systemd",
            previous_state=previous_state,
            current_state=current_state,
        )

    except Exception as e:
        logger.error("systemd_restart_exception", service=service, error=str(e))
        return RestartResult(
            success=False,
            status="failed",
            message=str(e),
            service_type="systemd",
        )


async def _restart_docker_container(container: str) -> RestartResult:
    """Restart a Docker container."""
    container = _sanitize_service_name(container)

    if container not in ALLOWED_DOCKER_CONTAINERS:
        return RestartResult(
            success=False,
            status="failed",
            message=f"Container '{container}' not in allowlist",
            service_type="docker",
        )

    previous_state = await _get_docker_status(container)

    logger.info(
        "restarting_docker_container",
        container=container,
        previous_state=previous_state,
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "restart",
            container,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)

        await asyncio.sleep(3)

        current_state = await _get_docker_status(container)

        if current_state == "running":
            return RestartResult(
                success=True,
                status="ok",
                message=f"Container {container} restarted successfully",
                service_type="docker",
                previous_state=previous_state,
                current_state=current_state,
            )

        return RestartResult(
            success=False,
            status="failed",
            message=f"Container restarted but state is: {current_state}",
            service_type="docker",
            previous_state=previous_state,
            current_state=current_state,
        )

    except Exception as e:
        logger.error("docker_restart_exception", container=container, error=str(e))
        return RestartResult(
            success=False,
            status="failed",
            message=str(e),
            service_type="docker",
        )


# ===========================================
# Runbook Entrypoint
# ===========================================


@runbook(
    name="restart_service",
    description="Restart a systemd service or Docker container",
    category="service",
    severity_threshold=Severity.WARNING,
    auto_execute=True,
    requires_confirmation=True,
    timeout=120,
    allowed_services=["*"],
    allowed_parameters=["service", "service_type"],
    dangerous=True,
)
async def restart_service(service: str, service_type: str = "auto", **kwargs) -> dict:
    service = _sanitize_service_name(service)

    if sys.platform.startswith("win"):
        return {
            "success": False,
            "status": "skipped",
            "message": "Not supported on Windows",
            "service": service,
            "service_type": service_type,
        }

    if service_type == "docker":
        result = await _restart_docker_container(service)

    elif service_type == "systemd":
        result = await _restart_systemd_service(service)

    else:
        docker_attempt = await _restart_docker_container(service)

        if docker_attempt.status in ("ok", "failed"):
            result = docker_attempt
        else:
            result = await _restart_systemd_service(service)

    return {
        "success": result.success,
        "status": result.status,
        "message": result.message,
        "service": service,
        "service_type": result.service_type,
        "previous_state": result.previous_state,
        "current_state": result.current_state,
    }
