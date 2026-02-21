# ---------------------------
# Audit
# ---------------------------
from fastapi import APIRouter, Depends

from ...core.security import require_admin
from ...observability.audit import build_audit_snapshot

router = APIRouter(tags=["audit"])


@router.get("/api/audit/snapshot")
async def audit_snapshot(
    actor_id: str = Depends(require_admin),
):
    return await build_audit_snapshot()
