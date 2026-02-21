"""
Runbook: Health Check
Performs comprehensive system health checks.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from dataclasses import dataclass
from typing import Any

from src.core.logging_config import get_logger
from src.core.models import Severity
from src.runbooks.registry import runbook

logger = get_logger("runbook.health_check")

DEFAULT_PING_HOSTS = ["8.8.8.8", "1.1.1.1"]
DEFAULT_DNS_DOMAINS = ["google.com", "github.com", "cloudflare.com"]
DEFAULT_SYSTEMD_SERVICES = ["docker", "sshd", "cron"]
DEFAULT_PORTS = [22, 80, 443]


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    name: str
    status: str  # "healthy", "degraded", "unhealthy", "skipped"
    message: str
    details: dict[str, Any] | None = None


async def _run_cmd(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode,
            stdout_b.decode(errors="ignore"),
            stderr_b.decode(errors="ignore"),
        )
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"


async def _check_cpu() -> HealthCheckResult:
    """Check CPU usage."""
    try:
        import psutil

        def _cpu_sync():
            cpu_percent = psutil.cpu_percent(interval=1)
            load_avg = psutil.getloadavg()
            return cpu_percent, load_avg

        cpu_percent, load_avg = await asyncio.to_thread(_cpu_sync)

        if cpu_percent > 95:
            status = "unhealthy"
            message = f"CPU critical: {cpu_percent}%"
        elif cpu_percent > 80:
            status = "degraded"
            message = f"CPU high: {cpu_percent}%"
        else:
            status = "healthy"
            message = f"CPU normal: {cpu_percent}%"

        return HealthCheckResult(
            name="cpu",
            status=status,
            message=message,
            details={"cpu_percent": cpu_percent, "load_average": list(load_avg)},
        )
    except Exception as e:
        return HealthCheckResult(
            name="cpu", status="unhealthy", message=f"Failed to check: {e}"
        )


async def _check_memory() -> HealthCheckResult:
    """Check memory usage."""
    try:
        import psutil

        def _mem_sync():
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            return memory, swap

        memory, swap = await asyncio.to_thread(_mem_sync)

        if memory.percent > 95:
            status = "unhealthy"
            message = f"Memory critical: {memory.percent}%"
        elif memory.percent > 85:
            status = "degraded"
            message = f"Memory high: {memory.percent}%"
        else:
            status = "healthy"
            message = f"Memory normal: {memory.percent}%"

        return HealthCheckResult(
            name="memory",
            status=status,
            message=message,
            details={
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "swap_percent": swap.percent,
            },
        )
    except Exception as e:
        return HealthCheckResult(
            name="memory", status="unhealthy", message=f"Failed to check: {e}"
        )


async def _check_disk() -> HealthCheckResult:
    """Check disk usage."""
    try:
        import psutil

        def _disk_sync():
            return psutil.disk_usage("/")

        disk = await asyncio.to_thread(_disk_sync)

        if disk.percent > 95:
            status = "unhealthy"
            message = f"Disk critical: {disk.percent}%"
        elif disk.percent > 85:
            status = "degraded"
            message = f"Disk high: {disk.percent}%"
        else:
            status = "healthy"
            message = f"Disk normal: {disk.percent}%"

        return HealthCheckResult(
            name="disk",
            status=status,
            message=message,
            details={
                "disk_percent": disk.percent,
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
            },
        )
    except Exception as e:
        return HealthCheckResult(
            name="disk", status="unhealthy", message=f"Failed to check: {e}"
        )


async def _check_network_connectivity(
    hosts: list[str] | None = None,
) -> HealthCheckResult:
    """Check network connectivity to common endpoints (via ping)."""
    hosts = hosts or DEFAULT_PING_HOSTS
    reachable: list[str] = []
    unreachable: list[str] = []
    ping_missing = False

    for host in hosts:
        rc, _out, err = await _run_cmd("ping", "-c", "1", "-W", "2", host, timeout=5)
        if rc == 0:
            reachable.append(host)
            continue

        err_l = (err or "").lower()
        # Typical container case: missing CAP_NET_RAW
        if rc == 127 or "command not found" in err_l:
            ping_missing = True
            break
        if "operation not permitted" in err_l or "permission denied" in err_l:
            ping_missing = True
            logger.debug("ping_not_permitted", host=host, stderr=err_l.strip())
            break

        unreachable.append(host)

    if ping_missing:
        return HealthCheckResult(
            name="network",
            status="skipped",
            message="Ping not available or not permitted (skipped)",
            details={"reachable": reachable, "unreachable": unreachable},
        )

    if not reachable:
        return HealthCheckResult(
            name="network",
            status="unhealthy",
            message="No network connectivity",
            details={"reachable": reachable, "unreachable": unreachable},
        )

    if unreachable:
        return HealthCheckResult(
            name="network",
            status="degraded",
            message=f"Partial connectivity ({len(reachable)}/{len(hosts)})",
            details={"reachable": reachable, "unreachable": unreachable},
        )

    return HealthCheckResult(
        name="network",
        status="healthy",
        message="Network connectivity OK",
        details={"reachable": reachable, "unreachable": unreachable},
    )


async def _check_dns(domains: list[str] | None = None) -> HealthCheckResult:
    """Check DNS resolution."""
    test_domains = domains or DEFAULT_DNS_DOMAINS
    resolved: list[str] = []
    failed: list[str] = []

    async def _resolve(domain: str) -> None:
        def _sync():
            socket.gethostbyname(domain)

        try:
            await asyncio.to_thread(_sync)
            resolved.append(domain)
        except (socket.gaierror, UnicodeError, OSError) as e:
            logger.debug("dns_failed", domain=domain, error=str(e))
            failed.append(domain)

    await asyncio.gather(*[_resolve(d) for d in test_domains])

    if not resolved:
        status = "unhealthy"
        message = "DNS resolution failing"
    elif failed:
        status = "degraded"
        message = f"DNS partial ({len(resolved)}/{len(test_domains)})"
    else:
        status = "healthy"
        message = "DNS resolution OK"

    return HealthCheckResult(
        name="dns",
        status=status,
        message=message,
        details={"resolved": resolved, "failed": failed},
    )


async def _check_systemd_services(
    services: list[str] | None = None,
) -> HealthCheckResult:
    """Check status of critical systemd services."""
    services = services or DEFAULT_SYSTEMD_SERVICES
    running: list[str] = []
    stopped: list[str] = []

    # Quick detection
    rc, _, _ = await _run_cmd("systemctl", "--version", timeout=3)
    if rc != 0:
        return HealthCheckResult(
            name="systemd_services",
            status="skipped",
            message="systemctl not available (skipped)",
            details={"running": [], "stopped": []},
        )

    for service in services:
        rc, out, _err = await _run_cmd("systemctl", "is-active", service, timeout=5)
        if rc == 0 and out.strip() == "active":
            running.append(service)
        else:
            stopped.append(service)

    if stopped:
        return HealthCheckResult(
            name="systemd_services",
            status="degraded",
            message=f"Services stopped: {', '.join(stopped)}",
            details={"running": running, "stopped": stopped},
        )

    return HealthCheckResult(
        name="systemd_services",
        status="healthy",
        message=f"All {len(running)} services running",
        details={"running": running, "stopped": stopped},
    )


async def _check_docker_containers(
    containers: list[str] | None = None,
) -> HealthCheckResult:
    """Check status of Docker containers."""
    rc, out, err = await _run_cmd(
        "docker",
        "ps",
        "--format",
        "{{.Names}}:{{.Status}}",
        timeout=10,
    )

    if rc != 0:
        return HealthCheckResult(
            name="docker",
            status="skipped",
            message=f"Docker not accessible (skipped): {(err or '').strip()}",
        )

    container_status: dict[str, str] = {}
    healthy: list[str] = []
    unhealthy: list[str] = []

    for line in out.strip().splitlines():
        if ":" not in line:
            continue
        name, status_s = line.split(":", 1)
        container_status[name] = status_s
        if "up" in status_s.lower() and "unhealthy" not in status_s.lower():
            healthy.append(name)
        else:
            unhealthy.append(name)

    if containers:
        for c in containers:
            if c not in container_status:
                unhealthy.append(f"{c} (not found)")

    if unhealthy:
        status = "degraded"
        message = f"Unhealthy containers: {', '.join(unhealthy[:3])}"
    else:
        status = "healthy"
        message = f"{len(healthy)} containers running"

    return HealthCheckResult(
        name="docker",
        status=status,
        message=message,
        details={
            "healthy": healthy,
            "unhealthy": unhealthy,
            "all_containers": container_status,
        },
    )


async def _check_ports(ports: list[int] | None = None) -> HealthCheckResult:
    """Check if expected ports are listening on 127.0.0.1."""
    ports = ports or DEFAULT_PORTS

    def _ports_sync():
        listening: list[int] = []
        not_listening: list[int] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex(("127.0.0.1", port))
                if result == 0:
                    listening.append(port)
                else:
                    not_listening.append(port)
            except (OSError, ValueError):
                not_listening.append(port)
        return listening, not_listening

    listening, not_listening = await asyncio.to_thread(_ports_sync)

    if not_listening:
        return HealthCheckResult(
            name="ports",
            status="degraded",
            message=f"Ports not listening: {not_listening}",
            details={"listening": listening, "not_listening": not_listening},
        )

    return HealthCheckResult(
        name="ports",
        status="healthy",
        message=f"All {len(listening)} ports OK",
        details={"listening": listening, "not_listening": not_listening},
    )


@runbook(
    name="health_check",
    description="Perform comprehensive system health check",
    category="diagnostic",
    severity_threshold=Severity.INFO,
    auto_execute=True,
    requires_confirmation=False,
    timeout=120,
    allowed_services=["*"],
    allowed_parameters=[
        "check_cpu",
        "check_memory",
        "check_disk",
        "check_network",
        "check_dns",
        "check_services",
        "check_docker",
        "check_ports",
        "services",
        "containers",
        "ports",
        "ping_hosts",
        "dns_domains",
    ],
    dangerous=False,
)
async def health_check(
    check_cpu: bool = True,
    check_memory: bool = True,
    check_disk: bool = True,
    check_network: bool = True,
    check_dns: bool = True,
    check_services: bool = True,
    check_docker: bool = True,
    check_ports: bool = True,
    services: list[str] | None = None,
    containers: list[str] | None = None,
    ports: list[int] | None = None,
    ping_hosts: list[str] | None = None,
    dns_domains: list[str] | None = None,
    **kwargs,
) -> dict:
    """
    Perform comprehensive system health check.
    """
    if sys.platform.startswith("win"):
        return {
            "success": False,
            "status": "skipped",
            "message": "Health check skipped on Windows (Linux tooling not available).",
            "overall_status": "skipped",
            "status_counts": {
                "healthy": 0,
                "degraded": 0,
                "unhealthy": 0,
                "skipped": 1,
            },
            "checks": {},
        }

    logger.info("starting_health_check")

    tasks: list[tuple[str, asyncio.Future]] = []

    if check_cpu:
        tasks.append(("cpu", _check_cpu()))
    if check_memory:
        tasks.append(("memory", _check_memory()))
    if check_disk:
        tasks.append(("disk", _check_disk()))
    if check_network:
        tasks.append(("network", _check_network_connectivity(ping_hosts)))
    if check_dns:
        tasks.append(("dns", _check_dns(dns_domains)))
    if check_services:
        tasks.append(("systemd_services", _check_systemd_services(services)))
    if check_docker:
        tasks.append(("docker", _check_docker_containers(containers)))
    if check_ports:
        tasks.append(("ports", _check_ports(ports)))

    async def _run_one(name: str, coro):
        try:
            return await asyncio.wait_for(coro, timeout=30)
        except asyncio.TimeoutError:
            return HealthCheckResult(
                name=name, status="unhealthy", message="Check timed out"
            )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Check failed: {type(e).__name__}: {e}",
            )

    results: list[HealthCheckResult] = await asyncio.gather(
        *[_run_one(name, coro) for name, coro in tasks]
    )

    statuses = [r.status for r in results]
    effective = [s for s in statuses if s != "skipped"]

    if not effective:
        overall_status = "skipped"
    elif "unhealthy" in effective:
        overall_status = "unhealthy"
    elif "degraded" in effective:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    status_counts = {
        "healthy": statuses.count("healthy"),
        "degraded": statuses.count("degraded"),
        "unhealthy": statuses.count("unhealthy"),
        "skipped": statuses.count("skipped"),
    }

    logger.info(
        "health_check_complete",
        overall_status=overall_status,
        checks_run=len(results),
        **status_counts,
    )

    effective_total = len(effective)
    passed_part = (
        f"{status_counts['healthy']}/{effective_total} checks passed"
        if effective_total > 0
        else "no checks executed"
    )

    return {
        "success": overall_status not in ("unhealthy",),
        "message": f"Health check: {overall_status} ({passed_part}, {status_counts['skipped']} skipped)",
        "overall_status": overall_status,
        "status_counts": status_counts,
        "checks": {
            r.name: {"status": r.status, "message": r.message, "details": r.details}
            for r in results
        },
    }
