"""SSH connection configuration for the log collector."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class SSHConfig:
    """Credentials and connection settings for a CentOS Stream VM.

    Stored keys are passed as private_key (content, parsed in memory) and never written
    to disk; private_key_path is only for keys that already exist as files.
    """

    host: str
    username: str
    port: int = 22
    password: Optional[str] = field(default=None, repr=False)
    private_key_path: Optional[Path] = None
    timeout: float = 30.0
    private_key: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.password and not self.private_key_path and not self.private_key:
            raise ValueError("Either password, private_key or private_key_path must be provided.")
