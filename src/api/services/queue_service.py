import json
from typing import Any, Dict, Optional

from ..helpers import _execute_retry


# ------------------------------------------------------------
# Helper: enqueue into durable queue (DB source of truth)
# ------------------------------------------------------------
async def _enqueue_runbook_execution_db(
    *,
    db,
    execution_id: str,
    incident_id: Optional[str],
    runbook_name: str,
    target_service: Optional[str],
    target_instance: Optional[str],
    parameters: Dict[str, Any],
    triggered_by: str,
    execution_origin: str,
    now_iso: str,
) -> None:
    params_json = json.dumps(parameters or {}, ensure_ascii=False)

    # runbook_queue is the control-plane queue
    await _execute_retry(
        db=db,
        sql="""
        INSERT OR REPLACE INTO runbook_queue(
          execution_id, runbook_name, incident_id,
          target_service, target_instance,
          parameters_json, triggered_by, execution_origin, retry_of_execution_id,
          status, attempts, last_heartbeat,
          available_at, lease_owner, lease_expires_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'queued', 0, NULL, ?, NULL, NULL, ?, ?)
        """,
        params=(
            execution_id,
            runbook_name,
            incident_id,
            target_service,
            target_instance,
            params_json,
            triggered_by,
            execution_origin,
            now_iso,  # available_at
            now_iso,  # created_at
            now_iso,  # updated_at
        ),
    )
