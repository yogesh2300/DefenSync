"""Health check API endpoint for CloudSync service readiness."""
from __future__ import annotations

from backend.core.logging import get_logger
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db

logger = get_logger(__name__)

router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK, summary="Service Health Check")
def health_check(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Verify backend live status and database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as exc:
        logger.error("Health check database verification failed: %s", exc)
        db_status = "disconnected"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "unhealthy", "database": db_status},
        ) from exc

    return {
        "status": "healthy",
        "service": "CloudSync Behavioral Log Intelligence System",
        "database": db_status,
    }