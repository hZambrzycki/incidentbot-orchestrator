from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import httpx
from fastapi import HTTPException

from src.core.config import settings
from src.core.logging_config import get_logger

from .metrics_collector import (
    AUDIT_SNAPSHOT_CACHE_HITS_TOTAL,
    AUDIT_SNAPSHOT_DURATION,
    AUDIT_SNAPSHOT_ERRORS_TOTAL,
    AUDIT_SNAPSHOT_MODE_TOTAL,
)

# ============================================================
# LOGGER
# ============================================================

logger = get_logger("audit")

# ============================================================
# TYPES
# ============================================================

Number = float
PromSeries = Dict[str, Any]  # {"labels": {...}, "value": float}
PromResult = Union[Number, List[PromSeries], None]

# ============================================================
# CACHE (stale-while-revalidate)
# ============================================================

_snapshot_cache: Dict[str, Any] = {"ts": 0.0, "data": None}
_snapshot_lock = asyncio.Lock()

# avoid multiple concurrent refreshes
_refreshing = False
_refresh_flag_lock = asyncio.Lock()

CACHE_TTL_SECONDS = 15
CACHE_STALE_SECONDS = 120  # serves cache “old” while refreshing in background

# ============================================================
# TIMEOUTS PER BLOCK
# ============================================================

HOST_BLOCK_TIMEOUT_SECONDS = 2.0
INCIDENTS_BLOCK_TIMEOUT_SECONDS = 1.5
CONTAINERS_BLOCK_TIMEOUT_SECONDS = 5.0
CONTAINERS_MINI_BLOCK_TIMEOUT_SECONDS = 1.5


# ============================================================
# HELPERS
# ============================================================


def _prometheus_url() -> str:
    return getattr(settings, "prometheus_url", "http://prometheus:9090")


def _short_service(name: str) -> str:
    """
    Convierte FQDN-style service names:
    foo.bar.service -> service
    """
    if not name:
        return name
    return name.split(".")[-1]


def _normalize_series_list(data: PromResult, label_key: str = "service") -> PromResult:
    """
    Normaliza listas de series de Prometheus
    """
    if not isinstance(data, list):
        return data

    out: List[PromSeries] = []

    for item in data:
        labels = dict(item.get("labels") or {})

        if label_key in labels:
            labels[label_key] = _short_service(str(labels[label_key]))

        out.append(
            {
                "labels": labels,
                "value": float(item["value"]),
            }
        )

    return out


# ============================================================
# PROMETHEUS CLIENT
# ============================================================


async def promql(
    client: httpx.AsyncClient,
    query: str,
    ts: Optional[float] = None,
) -> PromResult:
    """
    Ejecuta query Prometheus instantánea
    """

    url = f"{_prometheus_url()}/api/v1/query"

    params: Dict[str, Any] = {"query": query}

    if ts is not None:
        params["time"] = ts

    r = await client.get(url, params=params)

    r.raise_for_status()

    data = r.json()

    if data.get("status") != "success":
        raise HTTPException(
            status_code=502,
            detail={"prometheus_error": data},
        )

    results = data["data"]["result"]

    if not results:
        return None

    # scalar
    if len(results) == 1 and "value" in results[0]:
        try:
            return float(results[0]["value"][1])

        except Exception:
            return None

    # vector
    out: List[PromSeries] = []

    for item in results:
        if "value" not in item:
            continue

        out.append(
            {
                "labels": item.get("metric", {}) or {},
                "value": float(item["value"][1]),
            }
        )

    return out or None


async def safe_promql(
    client: httpx.AsyncClient,
    query: str,
    t: float,
    name: str,
) -> PromResult:
    """
    PromQL best-effort
    """

    try:
        return await promql(client, query, t)

    except Exception as e:
        logger.warning(
            "audit_promql_failed",
            name=name,
            error=str(e),
        )

        return None


# ============================================================
# PUBLIC API
# ============================================================


async def build_audit_snapshot() -> Dict[str, Any]:
    """
    Stale-while-revalidate cache strategy
    """

    global _refreshing

    now = time.time()

    cached = _snapshot_cache["data"]
    age = now - _snapshot_cache["ts"]

    # --------------------------------------------
    # CACHE FRESH
    # --------------------------------------------

    if cached and age < CACHE_TTL_SECONDS:
        AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="fresh").inc()

        return cached

    # --------------------------------------------
    # CACHE STALE -> RETURN + BACKGROUND REFRESH
    # --------------------------------------------

    if cached and age < CACHE_STALE_SECONDS:
        AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="stale").inc()

        async with _refresh_flag_lock:
            if not _refreshing:
                _refreshing = True

                asyncio.create_task(_refresh_snapshot())

        return cached

    # --------------------------------------------
    # CACHE MISS
    # --------------------------------------------

    AUDIT_SNAPSHOT_CACHE_HITS_TOTAL.labels(kind="miss").inc()

    return await _refresh_snapshot()


# ============================================================
# SNAPSHOT REFRESH
# ============================================================


async def _refresh_snapshot() -> Dict[str, Any]:
    """
    Refresh exclusivo con lock
    """

    global _refreshing

    async with _snapshot_lock:
        start = time.perf_counter()

        cached_before = _snapshot_cache["data"]

        try:
            # double-check
            now = time.time()

            cached = _snapshot_cache["data"]

            if cached and (now - _snapshot_cache["ts"]) < CACHE_TTL_SECONDS:
                return cached

            snapshot = await _compute_snapshot()

            _snapshot_cache["ts"] = time.time()
            _snapshot_cache["data"] = snapshot

            return snapshot

        except Exception as e:
            logger.exception(
                "audit_snapshot_refresh_failed",
                error=str(e),
            )

            AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(
                type="refresh_failed",
                block="refresh",
            ).inc()

            _snapshot_cache["ts"] = time.time()

            if cached_before:
                return cached_before

            # snapshot mínimo
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prometheus_base": _prometheus_url(),
                "window": "5m",
                "host": {
                    "cpu_pct": None,
                    "mem_pct": None,
                    "disk_max_pct": None,
                },
                "incidents": {
                    "active_total": None,
                    "by_severity": None,
                },
                "containers": {
                    "containers_total": None,
                    "containers_mapped_total": None,
                    "containers_joinable_total": None,
                    "containers_rate_ready_total": None,
                    "cpu_top5_pct": None,
                    "mem_top5_mb": None,
                    "cpu_total_pct": None,
                    "cpu_by_service_pct": None,
                },
                "errors": [
                    {
                        "name": "refresh_failed",
                        "error": str(e),
                    }
                ],
            }

        finally:
            AUDIT_SNAPSHOT_DURATION.observe(time.perf_counter() - start)

            _refreshing = False


# ============================================================
# BLOCK RUNNER
# ============================================================


async def _run_block(
    name: str,
    awaitable,
    timeout: float,
    errors: list,
):
    """
    Ejecuta bloque con timeout
    """

    task = asyncio.ensure_future(awaitable)

    try:
        return await asyncio.wait_for(
            task,
            timeout=timeout,
        )

    except asyncio.TimeoutError:
        task.cancel()

        try:
            await asyncio.wait_for(task, timeout=0.1)

        except Exception:
            pass

        AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(
            type="block_timeout",
            block=name,
        ).inc()

        logger.warning(
            "audit_block_timeout",
            block=name,
            timeout=timeout,
        )

        errors.append(
            {
                "block": name,
                "error": "timeout",
            }
        )

        return None

    except Exception as e:
        AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(
            type="block_failed",
            block=name,
        ).inc()

        logger.exception(
            "audit_block_failed",
            block=name,
            error=str(e),
        )

        errors.append(
            {
                "block": name,
                "error": str(e),
            }
        )

        return None


# ============================================================
# SNAPSHOT COMPUTE
# ============================================================


async def _compute_snapshot() -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []

    ts_dt = datetime.now(timezone.utc)

    ts = ts_dt.isoformat()
    t = ts_dt.timestamp()

    window = "5m"

    # ========================================================
    # MAPPER
    # ========================================================

    mapper = (
        "max by (id, service) ("
        "label_replace("
        "max by (cadvisor_id, service) (incident_bot_container_info),"
        '"id", "$1",'
        '"cadvisor_id", "(.+)"'
        ")"
        ")"
    )

    # ========================================================
    # HOST QUERIES
    # ========================================================

    host_cpu_q = f'100 - (avg(rate(node_cpu_seconds_total{{job="node",mode="idle"}}[{window}])) * 100)'

    host_mem_q = (
        '(1 - (node_memory_MemAvailable_bytes{job="node"} / '
        'node_memory_MemTotal_bytes{job="node"})) * 100'
    )

    host_disk_q = (
        'max((1 - (node_filesystem_avail_bytes{job="node",fstype!~"tmpfs|overlay|squashfs"} / '
        'node_filesystem_size_bytes{job="node",fstype!~"tmpfs|overlay|squashfs"})) * 100)'
    )

    # ========================================================
    # INCIDENT QUERIES
    # ========================================================

    active_incidents_q = "sum(incident_bot_incidents_active)"

    incidents_by_sev_q = "incident_bot_incidents_active"

    # ========================================================
    # CONTAINER QUERIES
    # ========================================================

    containers_total_q = 'count(count by (id) (container_cpu_usage_seconds_total{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{64}$"}))'

    containers_mapped_total_q = "count(incident_bot_container_info)"

    containers_joinable_total_q = (
        "count(count by (id) ("
        '  container_cpu_usage_seconds_total{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{64}$"} '
        "  * on(id) group_left(service) "
        f"  {mapper}"
        "))"
    )

    containers_rate_ready_total_q = (
        "count("
        f'  rate(container_cpu_usage_seconds_total{{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{{64}}$"}}[{window}]) '
        "  * on(id) group_left(service) "
        f"  {mapper}"
        ")"
    )

    cpu_top5_q = (
        "topk(5, "
        "sum by (service) ("
        f'  rate(container_cpu_usage_seconds_total{{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{{64}}$"}}[{window}]) '
        "  * on (id) group_left(service) "
        f"  {mapper}"
        ") * 100)"
    )

    mem_working_q = (
        "topk(5, "
        "sum by (service) ("
        '  container_memory_working_set_bytes{job="cadvisor", id=~"^/docker/[0-9a-f]{64}$"} '
        "  * on (id) group_left(service) "
        f"  {mapper}"
        ") / 1024 / 1024)"
    )

    cpu_by_service_q = (
        "sort_desc("
        "sum by (service) ("
        f'  rate(container_cpu_usage_seconds_total{{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{{64}}$"}}[{window}]) '
        "  * on (id) group_left(service) "
        f"  {mapper}"
        ") * 100)"
    )

    cpu_total_global_q = (
        "sum("
        f'  rate(container_cpu_usage_seconds_total{{job="cadvisor", cpu="total", id=~"^/docker/[0-9a-f]{{64}}$"}}[{window}]) '
        "  * on(id) group_left(service) "
        f"  {mapper}"
        ") * 100"
    )

    containers_result = None
    mini_ok = False
    containers_mode = "unknown"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # ====================================================
            # HOST BLOCK
            # ====================================================

            host_block = asyncio.gather(
                safe_promql(client, host_cpu_q, t, "host_cpu"),
                safe_promql(client, host_mem_q, t, "host_mem"),
                safe_promql(client, host_disk_q, t, "host_disk"),
            )

            host_result = await _run_block(
                "host",
                host_block,
                HOST_BLOCK_TIMEOUT_SECONDS,
                errors,
            )

            if host_result:
                host_cpu, host_mem, host_disk = host_result
            else:
                host_cpu = host_mem = host_disk = None

            # ====================================================
            # INCIDENT BLOCK
            # ====================================================

            inc_block = asyncio.gather(
                safe_promql(client, active_incidents_q, t, "active_incidents"),
                safe_promql(client, incidents_by_sev_q, t, "incidents_by_sev"),
            )

            inc_result = await _run_block(
                "incidents",
                inc_block,
                INCIDENTS_BLOCK_TIMEOUT_SECONDS,
                errors,
            )

            if inc_result:
                active_incidents, incidents_by_sev = inc_result
            else:
                active_incidents = incidents_by_sev = None

            # ====================================================
            # CONTAINER BLOCK FULL
            # ====================================================

            containers_block = asyncio.gather(
                safe_promql(client, containers_total_q, t, "containers_total"),
                safe_promql(
                    client, containers_mapped_total_q, t, "containers_mapped_total"
                ),
                safe_promql(
                    client, containers_joinable_total_q, t, "containers_joinable_total"
                ),
                safe_promql(
                    client,
                    containers_rate_ready_total_q,
                    t,
                    "containers_rate_ready_total",
                ),
                safe_promql(client, cpu_top5_q, t, "cpu_top5"),
                safe_promql(client, mem_working_q, t, "mem_top5_working"),
                safe_promql(client, cpu_by_service_q, t, "cpu_by_service"),
                safe_promql(client, cpu_total_global_q, t, "cpu_total_global"),
            )

            containers_result = await _run_block(
                "containers",
                containers_block,
                CONTAINERS_BLOCK_TIMEOUT_SECONDS,
                errors,
            )

            if containers_result:
                (
                    containers_total,
                    containers_mapped_total,
                    containers_joinable_total,
                    containers_rate_ready_total,
                    cpu_top5,
                    mem_top5,
                    cpu_total_by_service,
                    cpu_total_global,
                ) = containers_result

            else:
                # ====================================================
                # CONTAINER BLOCK MINI FALLBACK
                # ====================================================

                mini_block = asyncio.gather(
                    safe_promql(client, containers_total_q, t, "containers_total_mini"),
                    safe_promql(
                        client,
                        containers_mapped_total_q,
                        t,
                        "containers_mapped_total_mini",
                    ),
                    safe_promql(
                        client,
                        containers_joinable_total_q,
                        t,
                        "containers_joinable_total_mini",
                    ),
                    safe_promql(
                        client,
                        containers_rate_ready_total_q,
                        t,
                        "containers_rate_ready_total_mini",
                    ),
                    safe_promql(client, cpu_total_global_q, t, "cpu_total_global_mini"),
                )

                mini_result = await _run_block(
                    "containers_mini",
                    mini_block,
                    CONTAINERS_MINI_BLOCK_TIMEOUT_SECONDS,
                    errors,
                )

                if mini_result:
                    mini_ok = True

                    (
                        containers_total,
                        containers_mapped_total,
                        containers_joinable_total,
                        containers_rate_ready_total,
                        cpu_total_global,
                    ) = mini_result

                else:
                    containers_total = None
                    containers_mapped_total = None
                    containers_joinable_total = None
                    containers_rate_ready_total = None
                    cpu_total_global = None

                cpu_top5 = None
                mem_top5 = None
                cpu_total_by_service = None

            # ====================================================
            # MEMORY FALLBACK
            # ====================================================

            if mem_top5 is None and containers_result:
                mem_usage_q = (
                    "topk(5,"
                    "sum by(service)("
                    'container_memory_usage_bytes{job="cadvisor", id=~"^/docker/[0-9a-f]{64}$"}'
                    "* on(id) group_left(service)"
                    f"{mapper}"
                    ")/1024/1024)"
                )

                mem_top5 = await safe_promql(
                    client,
                    mem_usage_q,
                    t,
                    "mem_top5_usage",
                )

    except Exception as e:
        logger.exception(
            "audit_snapshot_compute_failed",
            error=str(e),
        )

        AUDIT_SNAPSHOT_ERRORS_TOTAL.labels(
            type="compute_failed",
            block="compute",
        ).inc()

        errors.append(
            {
                "name": "compute_failed",
                "error": str(e),
            }
        )

        host_cpu = None
        host_mem = None
        host_disk = None

        active_incidents = None
        incidents_by_sev = None

        containers_total = None
        containers_mapped_total = None
        containers_joinable_total = None
        containers_rate_ready_total = None

        cpu_top5 = None
        mem_top5 = None
        cpu_total_by_service = None
        cpu_total_global = None

    # ========================================================
    # NORMALIZE
    # ========================================================

    cpu_top5 = _normalize_series_list(cpu_top5, "service")
    mem_top5 = _normalize_series_list(mem_top5, "service")
    cpu_total_by_service = _normalize_series_list(cpu_total_by_service, "service")

    if containers_result:
        containers_mode = "full"
    elif mini_ok:
        containers_mode = "mini"
    else:
        containers_mode = "unknown"

    AUDIT_SNAPSHOT_MODE_TOTAL.labels(mode=containers_mode).inc()

    snapshot = {
        "timestamp": ts,
        "prometheus_base": _prometheus_url(),
        "window": window,
        "host": {
            "cpu_pct": host_cpu,
            "mem_pct": host_mem,
            "disk_max_pct": host_disk,
        },
        "incidents": {
            "active_total": active_incidents,
            "by_severity": incidents_by_sev,
        },
        "containers": {
            "containers_total": containers_total,
            "containers_mapped_total": containers_mapped_total,
            "containers_joinable_total": containers_joinable_total,
            "containers_rate_ready_total": containers_rate_ready_total,
            "cpu_top5_pct": cpu_top5,
            "mem_top5_mb": mem_top5,
            "cpu_total_pct": cpu_total_global,
            "cpu_by_service_pct": cpu_total_by_service,
        },
        "errors": errors,
        "meta": {"containers_mode": containers_mode},
    }

    logger.info(
        "audit_snapshot",
        ts=ts,
        host_cpu=host_cpu,
        active_incidents=active_incidents,
        containers_total=containers_total,
        containers_mode=containers_mode,
        errors=len(errors),
    )

    return snapshot
