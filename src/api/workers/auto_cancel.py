# ---------------------------
# Worker: auto-cancel stale pending confirmations (TTL policy)
# ---------------------------

import asyncio

from ...core.config import settings
from ...incidents.incident_manager import incident_manager


async def auto_cancel_loop(*, logger, **_):
    while True:
        try:
            # TTL global
            await incident_manager.auto_cancel_stale_pending(
                max_age_seconds=int(getattr(settings, "confirm_ttl_seconds", 86400))
            )
        except Exception as e:
            logger.warning("auto_cancel_loop_failed", error=str(e))

        await asyncio.sleep(3600)  #  1h
        await asyncio.sleep(3600)  #  1h
