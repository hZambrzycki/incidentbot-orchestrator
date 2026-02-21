# src/api/debug.py

from fastapi import APIRouter, HTTPException

from src.observability.metrics_collector import metrics_collector

router = APIRouter(prefix="/debug", tags=["debug"])

# Allowlist of injectable synthetic faults
ALLOWED_FAULTS = {
    "synthetic_disk",
    "synthetic_cpu",
    "synthetic_service",
    "synthetic_container",
}


# ---------------------------------------
# Crash testing endpoint
# ---------------------------------------
@router.get("/boom")
async def boom():
    """
    Intentional crash endpoint for testing alerting and runbooks.
    """
    raise RuntimeError("boom")


# ---------------------------------------
# Enable fault injection
# ---------------------------------------
@router.post("/fault/{fault_type}/on")
async def fault_on(fault_type: str):
    if fault_type not in ALLOWED_FAULTS:
        raise HTTPException(status_code=400, detail="fault_type not allowed")

    metrics_collector.set_fault(fault_type, True)

    return {
        "fault": fault_type,
        "active": True,
    }


# ---------------------------------------
# Disable fault injection
# ---------------------------------------
@router.post("/fault/{fault_type}/off")
async def fault_off(fault_type: str):
    if fault_type not in ALLOWED_FAULTS:
        raise HTTPException(status_code=400, detail="fault_type not allowed")

    metrics_collector.set_fault(fault_type, False)

    return {
        "fault": fault_type,
        "active": False,
    }
