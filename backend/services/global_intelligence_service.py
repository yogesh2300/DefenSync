"""Global security-intelligence counts. Never treats corpus rows as account telemetry."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.models import DATA_SCOPE_GLOBAL, SecurityEvent


class GlobalIntelligenceService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def summary(self) -> dict[str, Any]:
        openstack = self._count(
            source_type="CLOUD",
            provider="OPENSTACK",
            data_origin="PUBLIC_DATASET",
        )
        hdfs = self._count(source_type="CLOUD", provider="HDFS", data_origin="PUBLIC_DATASET")
        bgl = self._count(source_type="HPC", provider="BGL", data_origin="PUBLIC_DATASET")
        behavioral = self._count(source_type="BEHAVIORAL", data_origin="SYNTHETIC")
        demo = self._count(data_origin="SYNTHETIC_CLOUD_DEMO")
        return {
            "scope": "GLOBAL",
            "note": "Shared security-intelligence corpora. These events are not owned by any account.",
            "openstack": {
                "events": openstack,
                "scope": "GLOBAL",
                "type": "CLOUD",
                "dataset": "LOGHUB_OPENSTACK",
                "origin": "PUBLIC_DATASET",
            },
            "hdfs": {
                "events": hdfs,
                "scope": "GLOBAL",
                "type": "CLOUD",
                "dataset": "LOGHUB_HDFS",
                "origin": "PUBLIC_DATASET",
            },
            "bgl": {
                "events": bgl,
                "scope": "GLOBAL",
                "type": "HPC",
                "dataset": "LOGHUB_BGL",
                "origin": "PUBLIC_DATASET",
                "label": "BGL/HPC supercomputer log (not cloud)",
            },
            "behavioral": {
                "events": behavioral,
                "scope": "GLOBAL",
                "type": "BEHAVIORAL",
                "dataset": "DEFENSYNC_BEHAVIORAL_TELEMETRY",
                "origin": "SYNTHETIC",
            },
            "synthetic_openstack_demo": {
                "events": demo,
                "scope": "GLOBAL",
                "type": "CLOUD",
                "synthetic": True,
                "label": "Synthetic Cloud Demo",
                "dataset": "DEFENSYNC_OPENSTACK_DEMO",
                "origin": "SYNTHETIC_CLOUD_DEMO",
            },
            "public_openstack_events": openstack,
            "hdfs_events": hdfs,
            "bgl_hpc_events": bgl,
            "behavioral_events": behavioral,
            "synthetic_openstack_demo_events": demo,
        }

    def _count(
        self,
        *,
        source_type: str | None = None,
        provider: str | None = None,
        data_origin: str | None = None,
    ) -> int:
        clauses = [SecurityEvent.data_scope == DATA_SCOPE_GLOBAL]
        if source_type:
            clauses.append(SecurityEvent.source_type == source_type)
        if provider:
            clauses.append(SecurityEvent.provider == provider)
        if data_origin:
            clauses.append(SecurityEvent.data_origin == data_origin)
        return int(self._session.scalar(select(func.count(SecurityEvent.id)).where(*clauses)) or 0)
