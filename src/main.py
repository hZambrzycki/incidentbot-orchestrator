# src/api/main.py

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.endpoints.audit import router as audit_router
from .api.endpoints.dashboard import router as dashboard_router
from .api.endpoints.health import router as health_router
from .api.endpoints.incidents import router as incidents_router
from .api.endpoints.metrics import router as metrics_router
from .api.endpoints.reliability import router as reliability_router
from .api.endpoints.root import router as root_router
from .api.endpoints.runbooks import router as runbooks_router
from .api.endpoints.status import router as status_router
from .api.endpoints.webhook_alertmanager import router as alertmanager_router
from .api.lifespan import lifespan
from .api.middleware import access_log_mw, request_context_mw
from .core.debug_faults import router as debug_router
from .core.errors import unhandled_exception_handler

"""
 FastAPI Application - Incident Bot (boot check).

"""

app = FastAPI(
    title="Incident Bot API",
    version="0.1.0",
    lifespan=lifespan,
)

# Routers
app.include_router(debug_router)
app.include_router(health_router)
app.include_router(status_router)
app.include_router(incidents_router)
app.include_router(runbooks_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(reliability_router)
app.include_router(alertmanager_router)
app.include_router(metrics_router)
app.include_router(root_router)

# Global exception handler
app.add_exception_handler(Exception, unhandled_exception_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTTP middlewares
app.middleware("http")(access_log_mw)
app.middleware("http")(request_context_mw)

# Static
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    pass
