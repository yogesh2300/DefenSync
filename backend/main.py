"""FastAPI application entry point for CloudSync."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import api_router
from backend.core.config import get_settings
from backend.core.exceptions import register_exception_handlers
from backend.core.logging import configure_logging, get_logger

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

    logger.info("Starting CloudSync API...")

    # Create all database tables
    Base.metadata.create_all(bind=get_engine())

    logger.info("Database tables verified.")

    yield

    logger.info("Stopping CloudSync API...")

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

    # ---------------------------------------------------------------------
    # Configure CORS
    # ---------------------------------------------------------------------

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
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