# ---------------------------
# Reliability (runbook failures)
# ---------------------------

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends

from ...core.security import require_admin
from ...db.connection import get_db

router = APIRouter(tags=["reliability"])


@router.get("/api/reliability/runbook_failures")
async def runbook_failures(
    hours: int = 24,
    runbook: Optional[str] = None,
    service: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = 200,
    actor_id: str = Depends(require_admin),
    db=Depends(get_db),
):
    if hours <= 0:
        hours = 24
    hours = min(hours, 24 * 30)  # cap 30 días

    if limit <= 0:
        limit = 200
    limit = min(limit, 2000)

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    where = ["created_at >= ?"]
    params: list[Any] = [since]

    if runbook:
        where.append("runbook_name = ?")
        params.append(runbook)

    if service:
        where.append("target_service = ?")
        params.append(service)

    if incident_id:
        where.append("incident_id = ?")
        params.append(incident_id)

    where_sql = "WHERE " + " AND ".join(where)

    cur = await db.execute(
        f"""
        SELECT
          id, created_at,
          incident_id, execution_id, runbook_name,
          target_service, target_instance,
          failure_kind, final_status,
          execution_origin, retry_of_execution_id,
          attempt_no, is_final,
          error_message, error_hash, details_json
        FROM runbook_failures
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = await cur.fetchall()
    await cur.close()

    items: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("details_json"):
            try:
                d["details"] = json.loads(d["details_json"])
            except Exception:
                d["details"] = {"raw": d["details_json"]}
        else:
            d["details"] = None
        d.pop("details_json", None)
        items.append(d)

    # “Top groupings” para UI: por error_hash y por runbook
    # (best-effort in-memory; si quieres, lo pasamos a SQL luego)
    top_by_hash: dict[str, int] = {}
    top_by_runbook: dict[str, int] = {}
    for it in items:
        h = it.get("error_hash") or "no_hash"
        top_by_hash[h] = top_by_hash.get(h, 0) + 1
        rb = it.get("runbook_name") or "unknown"
        top_by_runbook[rb] = top_by_runbook.get(rb, 0) + 1

    def _top(dct: dict[str, int], n: int = 10):
        return sorted(
            [{"key": k, "count": v} for k, v in dct.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:n]

    return {
        "window_hours": hours,
        "since": since,
        "total": len(items),
        "top_error_hash": _top(top_by_hash, 10),
        "top_runbooks": _top(top_by_runbook, 10),
        "failures": items,
        "filters": {
            "runbook": runbook,
            "service": service,
            "incident_id": incident_id,
            "limit": limit,
        },
    }
