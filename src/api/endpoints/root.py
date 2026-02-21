# ---------------------------
# Root → dashboard redirect
# ---------------------------

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["root"])


@router.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(
        content=(
            "<meta http-equiv='refresh' content='0; url=/static/dashboard.html' />"
        )
    )
