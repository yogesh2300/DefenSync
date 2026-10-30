"""Symmetric encryption for stored SSH credentials."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from backend.core.config import get_settings


CREDENTIAL_DECRYPT_MESSAGE = (
    "Stored SSH credential cannot be decrypted with the current SECRET_KEY. "
    "SECRET_KEY changed after the credential was saved; re-enter the server "
    "password or private key to re-encrypt it."
)


class CredentialDecryptionError(ValueError):
    """Stored ciphertext does not match the active SECRET_KEY."""

    def __init__(self, message: str = CREDENTIAL_DECRYPT_MESSAGE) -> None:
        super().__init__(message)


def _fernet() -> Fernet:
    secret = get_settings().SECRET_KEY.get_secret_value().encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    """Encrypt a plaintext secret for database storage."""
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    """Decrypt a stored secret. Raises CredentialDecryptionError on failure."""
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialDecryptionError() from exc
