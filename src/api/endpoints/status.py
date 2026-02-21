from __future__ import annotations

from fastapi import APIRouter

from ..status_core import get_system_status_core

router = APIRouter(tags=["status"])


@router.get("/api/status")
async def status():
    return await get_system_status_core()
