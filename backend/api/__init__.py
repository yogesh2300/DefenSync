"""API router aggregation for CloudSync."""

from __future__ import annotations

from fastapi import APIRouter

from backend.api.auth import router as auth_router
from backend.api.dashboard import router as dashboard_router
from backend.api.events import router as events_router
from backend.api.health import router as health_router


# =============================================================================
# Root API Router
# =============================================================================

api_router = APIRouter()

# -------------------------------------------------------------------------
# Health Endpoints
# -------------------------------------------------------------------------

api_router.include_router(
    health_router,
    tags=["Health"],
)

# -------------------------------------------------------------------------
# Authentication Endpoints
# -------------------------------------------------------------------------

api_router.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# -------------------------------------------------------------------------
# Security Events Endpoints
# -------------------------------------------------------------------------

api_router.include_router(
    events_router,
    prefix="/api/v1/events",
    tags=["Events"],
)

# -------------------------------------------------------------------------
# Dashboard Endpoints
# -------------------------------------------------------------------------

api_router.include_router(
    dashboard_router,
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)

__all__ = ["api_router"]