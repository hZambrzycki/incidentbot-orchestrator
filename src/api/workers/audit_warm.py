# ---------------------------
# Worker: warm /api/audit/snapshot cache
# ---------------------------
import asyncio

from ...observability.audit import build_audit_snapshot


#  self-warming loop for /api/audit/snapshot
async def audit_snapshot_warm_loop(*, logger, **_):
    await asyncio.sleep(2)
    interval_s = 15
    while True:
        try:
            await build_audit_snapshot()
        except Exception as e:
            logger.warning("audit_snapshot_warm_failed", error=str(e))
        await asyncio.sleep(interval_s)
