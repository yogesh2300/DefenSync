"""
DefenSync Centralized Exception Handling.
"""

from __future__ import annotations

import json

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from backend.core.logging import get_logger

logger = get_logger(__name__)


class DefenSyncException(Exception):
    """Base exception for the DefenSync application."""

    def __init__(self, message: str = "An unexpected error occurred.") -> None:
        self.message = message
        super().__init__(message)


class AuthenticationError(DefenSyncException):
    def __init__(self, message: str = "Authentication failed.") -> None:
        super().__init__(message)


class AuthorizationError(DefenSyncException):
    def __init__(self, message: str = "Not authorized.") -> None:
        super().__init__(message)


class ResourceNotFoundError(DefenSyncException):
    def __init__(self, message: str = "Resource not found.") -> None:
        super().__init__(message)


class ValidationException(DefenSyncException):
    def __init__(self, message: str = "Validation failed.") -> None:
        super().__init__(message)


class DatabaseException(DefenSyncException):
    def __init__(self, message: str = "Database operation failed.") -> None:
        super().__init__(message)


class DuplicateResourceError(DefenSyncException):
    def __init__(self, message: str = "Resource already exists.") -> None:
        super().__init__(message)


class MFAError(DefenSyncException):
    """Second-factor failure with a stable `code` for clients. Never carries OTP values."""

    def __init__(self, code: str, message: str, *, status_code: int = 401, **details: object) -> None:
        self.code = code
        self.status_code = status_code
        self.details = {"code": code, **{key: value for key, value in details.items() if value is not None}}
        super().__init__(message)


class DeviceTrustError(DefenSyncException):
    """Trusted-device enrollment/proof failure. Never carries private keys, OTPs, or passwords."""

    def __init__(self, code: str, message: str, *, status_code: int = 403, **details: object) -> None:
        self.code = code
        self.status_code = status_code
        self.details = {"code": code, **{key: value for key, value in details.items() if value is not None}}
        super().__init__(message)


class CollectionProcessingError(DefenSyncException):
    """Logs were retrieved over SSH but could not be processed or stored. Never carries credentials."""

    status_code = 500

    def __init__(self, message: str, **details: object) -> None:
        self.details = {
            "code": "COLLECTION_PROCESSING_FAILED",
            **{key: value for key, value in details.items() if value is not None},
        }
        super().__init__(message)


async def defensync_exception_handler(
    request: Request,
    exc: DefenSyncException,
) -> JSONResponse:

    mapping = {
        AuthenticationError: status.HTTP_401_UNAUTHORIZED,
        AuthorizationError: status.HTTP_403_FORBIDDEN,
        ResourceNotFoundError: status.HTTP_404_NOT_FOUND,
        DuplicateResourceError: status.HTTP_409_CONFLICT,
        ValidationException: status.HTTP_422_UNPROCESSABLE_ENTITY,
        DatabaseException: status.HTTP_500_INTERNAL_SERVER_ERROR,
    }

    status_code = getattr(exc, "status_code", None) or mapping.get(type(exc), status.HTTP_400_BAD_REQUEST)

    if isinstance(exc, DatabaseException):
        logger.exception("Database exception on %s %s: %s", request.method, request.url.path, exc)
    else:
        logger.warning("Application exception on %s %s: %s", request.method, request.url.path, exc)

    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": str(exc),
            "type": exc.__class__.__name__,
            **getattr(exc, "details", {}),
        },
    )


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    logger.warning("HTTP exception on %s %s: status=%s detail=%s", request.method, request.url.path, exc.status_code, exc.detail)

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
    logger.warning("Validation exception on %s %s: %s", request.method, request.url.path, exc.errors())

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": json.loads(json.dumps(exc.errors(), default=str)),
            "type": "ValidationError",
        },
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    if isinstance(exc, RequestValidationError):
        return await validation_exception_handler(request, exc)
    try:
        from pydantic import ValidationError
        if isinstance(exc, ValidationError):
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={"success": False, "error": exc.errors(), "type": "ValidationError"},
            )
    except Exception:
        pass
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": "Internal server error.",
            "type": "UnhandledException",
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all application exception handlers."""

    app.add_exception_handler(
        DefenSyncException,
        defensync_exception_handler,
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
