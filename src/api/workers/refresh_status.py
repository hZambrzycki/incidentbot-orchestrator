# ---------------------------
# Worker: refresh active incidents (self-warming /status)
# ---------------------------

import asyncio

from ..status_core import get_system_status_core


async def refresh_active_incidents_loop():
    while True:
        try:
            await get_system_status_core()
        except Exception:
            pass
        await asyncio.sleep(5)
