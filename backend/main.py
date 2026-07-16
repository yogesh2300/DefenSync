"""FastAPI application entry point for DefenSync."""

from __future__ import annotations

from contextlib import asynccontextmanager
import time
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.api import api_router
from backend.core.config import get_settings
from backend.core.exceptions import register_exception_handlers
from backend.core.logging import configure_logging, get_logger

from backend.bootstrap.default_admin import ensure_default_admin
from backend.services.scheduler_service import start_scheduler, stop_scheduler
from backend.services.health_engine import start_health_engine, stop_health_engine
from backend.database.connection import get_engine
from backend.database.models import Base

# -------------------------------------------------------------------------
# Configure logging
# -------------------------------------------------------------------------

configure_logging()
logger = get_logger(__name__)

settings = get_settings()


# -------------------------------------------------------------------------
# Application lifespan
# -------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info("Starting DefenSync API...")

    # -------------------------------------------------------------------------
    # Database startup: verify connection, then ensure schema is up to date
    # -------------------------------------------------------------------------
    engine = get_engine()
    try:
        from sqlalchemy import text as _text, inspect as _inspect
        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))
        logger.info("Database connection verified successfully.")
    except Exception as _db_exc:
        logger.critical(
            "Database connection FAILED at startup: %s — "
            "check DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD in .env.",
            _db_exc,
        )
        raise

    expected_tables = sorted(Base.metadata.tables.keys())
    logger.info("Expected ORM tables: %s", expected_tables)

    Base.metadata.create_all(bind=engine)

    # Verify all expected tables now exist in the database
    inspector = _inspect(engine)
    existing_tables = sorted(inspector.get_table_names())
    missing = [t for t in expected_tables if t not in existing_tables]
    if missing:
        logger.error("The following tables are MISSING from the database after create_all: %s", missing)
    else:
        logger.info("All required tables present in database: %s", expected_tables)

    ensure_default_admin()

    start_scheduler()
    start_health_engine()

    yield

    stop_health_engine()
    stop_scheduler()
    logger.info("Stopping DefenSync API...")

# -------------------------------------------------------------------------
# FastAPI Application Factory
# -------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title=settings.APP_NAME,
        version="2.0.0",
        description=(
            "Behavioral Log Intelligence Platform for collecting, "
            "normalizing and analysing Linux security events."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        debug=settings.DEBUG,
        lifespan=lifespan,
    )

    # ---------------------------------------------------------------------
    # Register Exception Handlers
    # ---------------------------------------------------------------------

    register_exception_handlers(app)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started = time.perf_counter()
        logger.info("Incoming API request: %s %s", request.method, request.url.path)
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            logger.exception(
                "Unhandled API exception: %s %s after %sms",
                request.method,
                request.url.path,
                elapsed_ms,
            )
            raise
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "Completed API request: %s %s status=%s duration_ms=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    # ---------------------------------------------------------------------
    # Configure CORS
    # ---------------------------------------------------------------------

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------------------------------------------------------------------
    # Register API Routes
    # ---------------------------------------------------------------------

    app.include_router(api_router)

    return app


app = create_app()


# -------------------------------------------------------------------------
# Local Development Entry Point
# -------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting Uvicorn development server...")

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )