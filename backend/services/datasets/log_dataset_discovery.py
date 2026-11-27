"""Shared discovery helpers for repository log datasets."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from backend.core.config import get_settings
from backend.services.datasets.openstack_discovery import DatasetFile, _is_relative_to


LabelFn = Callable[[str], dict[str, Any]]


class LogDatasetDiscoveryService:
    """Discover .log files under one dataset subdirectory of DATASET_ROOT."""

    def __init__(
        self,
        *,
        relative_dir: str,
        dataset_name: str,
        dataset_root: str | Path | None = None,
        suffixes: set[str] | None = None,
        skip_name_contains: tuple[str, ...] = ("label", "template", "readme"),
        label_fn: LabelFn | None = None,
    ) -> None:
        settings = get_settings()
        self._dataset_root = Path(dataset_root or settings.DATASET_ROOT)
        self._relative_dir = relative_dir
        self._dataset_name = dataset_name
        self._suffixes = suffixes or {".log"}
        self._skip_name_contains = skip_name_contains
        self._label_fn = label_fn

    @property
    def dataset_dir(self) -> Path:
        root = self._dataset_root
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        else:
            root = root.resolve()
        candidate = (root / self._relative_dir).resolve()
        if not _is_relative_to(candidate, root):
            raise ValueError("Dataset path must resolve inside DATASET_ROOT.")
        return candidate

    def discover_files(self) -> list[DatasetFile]:
        base = self.dataset_dir
        if not base.exists() or not base.is_dir():
            return []
        files: list[DatasetFile] = []
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            name_lower = path.name.lower()
            if any(token in name_lower for token in self._skip_name_contains):
                continue
            if path.suffix.lower() not in self._suffixes:
                continue
            rel = path.relative_to(base).as_posix()
            label = self._label_fn(rel) if self._label_fn else {
                "original_label": None,
                "label_source": "unknown",
                "label_confidence": 0.0,
            }
            files.append(
                DatasetFile(
                    file_id=self.file_id_for_relative_path(rel),
                    relative_path=rel,
                    filename=path.name,
                    size_bytes=path.stat().st_size,
                    estimated_line_count=self._estimate_line_count(path),
                    split="unknown",
                    label=label.get("original_label"),
                    label_source=str(label.get("label_source") or "unknown"),
                    label_confidence=float(label.get("label_confidence") or 0.0),
                )
            )
        return files

    def resolve_file_id(self, file_id: str) -> Path:
        for item in self.discover_files():
            if item.file_id == file_id:
                path = (self.dataset_dir / item.relative_path).resolve()
                if not _is_relative_to(path, self.dataset_dir.resolve()):
                    raise ValueError("Resolved file escapes dataset directory.")
                return path
        raise FileNotFoundError("Dataset file_id was not found.")

    def status(self) -> dict[str, Any]:
        files = self.discover_files()
        return {
            "dataset": self._dataset_name,
            "dataset_path_configured": self._relative_dir,
            "files_discovered": len(files),
            "available": bool(files),
        }

    @staticmethod
    def file_id_for_relative_path(relative_path: str) -> str:
        digest = hashlib.sha256(relative_path.replace("\\", "/").encode("utf-8")).hexdigest()
        return digest[:24]

    @staticmethod
    def _estimate_line_count(path: Path) -> int | None:
        size = path.stat().st_size
        if size > 32 * 1024 * 1024:
            return None
        count = 0
        with path.open("rb") as handle:
            for count, _line in enumerate(handle, start=1):
                pass
        return count or None
