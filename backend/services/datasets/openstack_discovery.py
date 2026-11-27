"""Safe discovery of OpenStack public dataset files."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.core.config import get_settings
from backend.parser.openstack_parser import DATASET_NAME, infer_label_from_path

SUPPORTED_SUFFIXES = {".log", ".txt"}
IGNORED_SUFFIXES = {".zip", ".gz", ".tar", ".tgz", ".bz2", ".7z", ".xz", ".npz", ".xlsx", ".csv"}


@dataclass(slots=True)
class DatasetFile:
    file_id: str
    relative_path: str
    filename: str
    size_bytes: int
    estimated_line_count: int | None
    split: str
    label: str | None
    label_source: str
    label_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "relative_path": self.relative_path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "estimated_line_count": self.estimated_line_count,
            "split": self.split,
            "label": self.label,
            "label_source": self.label_source,
            "label_confidence": self.label_confidence,
        }


class OpenStackDiscoveryService:
    """Discover supported OpenStack dataset log files under configured paths only."""

    def __init__(
        self,
        *,
        dataset_root: str | Path | None = None,
        openstack_path: str | Path | None = None,
    ) -> None:
        settings = get_settings()
        self._dataset_root = Path(dataset_root or settings.DATASET_ROOT)
        self._openstack_path = Path(openstack_path or settings.OPENSTACK_DATASET_PATH)

    @property
    def dataset_dir(self) -> Path:
        root = self._resolve_root()
        candidate = (root / self._openstack_path).resolve()
        if not _is_relative_to(candidate, root):
            raise ValueError("OPENSTACK_DATASET_PATH must resolve inside DATASET_ROOT.")
        return candidate

    def discover_files(self) -> list[DatasetFile]:
        base = self.dataset_dir
        if not base.exists() or not base.is_dir():
            return []

        files: list[DatasetFile] = []
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            if path.suffix.lower() in IGNORED_SUFFIXES:
                continue
            if path.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            if "label" in path.name.lower():
                continue
            rel = path.relative_to(base).as_posix()
            label = infer_label_from_path(rel)
            files.append(
                DatasetFile(
                    file_id=self.file_id_for_relative_path(rel),
                    relative_path=rel,
                    filename=path.name,
                    size_bytes=path.stat().st_size,
                    estimated_line_count=self._estimate_line_count(path),
                    split=_infer_split(rel),
                    label=label["original_label"],
                    label_source=label["label_source"],
                    label_confidence=float(label["label_confidence"]),
                )
            )
        return files

    def resolve_file_id(self, file_id: str) -> Path:
        for item in self.discover_files():
            if item.file_id == file_id:
                path = (self.dataset_dir / item.relative_path).resolve()
                if not _is_relative_to(path, self.dataset_dir.resolve()):
                    raise ValueError("Resolved file escapes OpenStack dataset directory.")
                return path
        raise FileNotFoundError("OpenStack dataset file_id was not found.")

    @staticmethod
    def file_id_for_relative_path(relative_path: str) -> str:
        digest = hashlib.sha256(relative_path.replace("\\", "/").encode("utf-8")).hexdigest()
        return digest[:24]

    def status(self) -> dict[str, Any]:
        files = self.discover_files()
        return {
            "dataset": DATASET_NAME,
            "dataset_path_configured": self._openstack_path.as_posix(),
            "files_discovered": len(files),
            "available": bool(files),
        }

    def _resolve_root(self) -> Path:
        root = self._dataset_root
        if not root.is_absolute():
            root = Path.cwd() / root
        return root.resolve()

    @staticmethod
    def _estimate_line_count(path: Path) -> int | None:
        size = path.stat().st_size
        if size > 100 * 1024 * 1024:
            return None
        count = 0
        with path.open("rb") as handle:
            for count, _line in enumerate(handle, start=1):
                pass
        return count


def _infer_split(relative_path: str) -> str:
    lowered = relative_path.lower()
    if "abnormal" in lowered or "anomal" in lowered:
        return "abnormal"
    if "normal" in lowered:
        return "normal"
    if "train" in lowered:
        return "train"
    if "test" in lowered:
        return "test"
    return "unknown"


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False
