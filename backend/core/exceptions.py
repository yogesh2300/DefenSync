"""
CloudSync Centralized Exception Handling.

Provides:
- Custom application exceptions
- Global FastAPI exception handlers
- Consistent JSON error responses
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from backend.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Base Exception
# ==============================================================================

class CloudSyncException(Exception):
    """Base exception for the CloudSync application."""

    def __init__(self, message: str = "An unexpected error occurred.") -> None:
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        return self.message


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class AuthenticationError(CloudSyncException):
    def __init__(self, message: str = "Authentication failed.") -> None:
        super().__init__(message)


class AuthorizationError(CloudSyncException):
    def __init__(self, message: str = "Not authorized.") -> None:
        super().__init__(message)


class ResourceNotFoundError(CloudSyncException):
    def __init__(self, message: str = "Resource not found.") -> None:
        super().__init__(message)


class ValidationException(CloudSyncException):
    def __init__(self, message: str = "Validation failed.") -> None:
        super().__init__(message)


class DatabaseException(CloudSyncException):
    def __init__(self, message: str = "Database operation failed.") -> None:
        super().__init__(message)


# ==============================================================================
# Exception Handlers
# ==============================================================================

async def cloudsync_exception_handler(
    request: Request,
    exc: CloudSyncException,
) -> JSONResponse:

    mapping = {
        AuthenticationError: status.HTTP_401_UNAUTHORIZED,
        AuthorizationError: status.HTTP_403_FORBIDDEN,
        ResourceNotFoundError: status.HTTP_404_NOT_FOUND,
        ValidationException: status.HTTP_422_UNPROCESSABLE_ENTITY,
        DatabaseException: status.HTTP_500_INTERNAL_SERVER_ERROR,
    }

    status_code = mapping.get(type(exc), status.HTTP_400_BAD_REQUEST)

    if isinstance(exc, DatabaseException):
        logger.exception(exc)

    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": str(exc),
            "type": exc.__class__.__name__,
        },
    )


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "type": "HTTPException",
        },
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": exc.errors(),
            "type": "ValidationError",
        },
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    logger.exception("Unhandled exception", exc_info=exc)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": "Internal server error.",
            "type": "UnhandledException",
        },
    )


# ==============================================================================
# Registration
# ==============================================================================

def register_exception_handlers(app: FastAPI) -> None:
    """Register all application exception handlers."""

    app.add_exception_handler(
        CloudSyncException,
        cloudsync_exception_handler,
    )

    app.add_exception_handler(
        HTTPException,
        http_exception_handler,
    )

    app.add_exception_handler(
        RequestValidationError,
        validation_exception_handler,
    )

    app.add_exception_handler(
        Exception,
        generic_exception_handler,
    )