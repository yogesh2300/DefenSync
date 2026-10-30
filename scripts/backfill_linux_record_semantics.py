"""Targeted backfill of live Linux events to the current record semantics.

Dry run by default; writes only with --apply (single transaction). Touches only rows with
source_type=LINUX, data_origin=LIVE_LINUX and a server_id. Nothing is deleted.

Per row, derived exactly as a collection today would derive it:
  * snapshot outputs (ps, w, who, df, ...) -> System Snapshot, timestamp = collection time
    when the stored time was synthetic; `w` header lines kept and marked OUTPUT_HEADER
  * `last` reboot/shutdown rows -> System Event (not a user login)
  * `last`/`lastb` wall-clock times -> re-interpreted in the host timezone, hash recomputed
    so later collections deduplicate against the corrected row
  * `wtmp begins` footers kept and marked OUTPUT_FOOTER
  * sshd logins by the configured SSH user from the collector's source IP -> COLLECTOR_GENERATED
Rows whose source time carries an explicit offset/epoch are not re-timed.

The host timezone and collector IP are read live (read-only, no root) from each server and
are assumed to have been the same when the historical rows were collected.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import uuid
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import func, select, text

from backend.collector.ssh_client import ssh_session
from backend.core.timestamps import (
    SOURCE_EVENT,
    SOURCE_SNAPSHOT,
    TZ_COLLECTION_CLOCK,
    TZ_HOST,
    login_hour_from,
    parse_occurrence,
    resolve_host_timezone,
)
from backend.database import crud
from backend.database.connection import get_session
from backend.database.models import Event, Server
from backend.normalizer.event_types import (
    RECORD_ORIGIN_COLLECTOR,
    RECORD_ORIGIN_SOURCE_OBSERVED,
    RECORD_SECURITY_EVENT,
    RECORD_SYSTEM_EVENT,
    RECORD_SYSTEM_SNAPSHOT,
    EventType,
)
from backend.risk.levels import risk_level_from_score
from backend.services.collector_service import CollectorService
from backend.services.pipeline_service import (
    COLLECTOR_ORIGIN_BASIS,
    LOGIN_HISTORY_SOURCES,
    NON_RECORD_LINES,
    SNAPSHOT_SOURCES,
    PipelineService,
)
from backend.services.ssh_service import SSHService
from backend.services.transform_service import TransformService

BACKFILL_TAG = "linux_record_semantics_v1"
LOGIN_TYPES = {EventType.SUCCESSFUL_LOGIN.value, EventType.FAILED_LOGIN.value}
FOOTER = NON_RECORD_LINES["last"]


def db_timezone(session) -> tzinfo:
    if session.get_bind().dialect.name != "postgresql":
        return timezone.utc
    return ZoneInfo(session.execute(text("SHOW TimeZone")).scalar())


def to_utc(value: datetime | None, db_tz: tzinfo) -> datetime | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=db_tz)).astimezone(timezone.utc)


def host_context_for(server: Server) -> dict[str, str]:
    try:
        with ssh_session(SSHService.config_from_server(server)) as client:
            return CollectorService._host_context(client, server.host)
    except Exception as exc:
        print(f"  host context unavailable for server {server.id}: {type(exc).__name__}")
        return {}


def derive(source: str, line: str, *, hostname: str, host_tz: tzinfo | None) -> dict | None:
    """The persistence payload today's pipeline would produce for this line (or None)."""
    events = PipelineService._generic_events_from_sources({source: [line]}, hostname=hostname, host_tz=host_tz)
    if not events:
        return None
    scored = TransformService().enrich_events(events, failed_login_count=0)
    return scored[0].to_persistence_dict()


class Backfill:
    def __init__(self, session):
        self.session = session
        self.db_tz = db_timezone(session)
        self.counts = collections.Counter()
        self.uncorrectable = collections.Counter()
        self.samples: dict[str, tuple] = {}
        self.hash_updates: dict[str, str] = {}
        self.claimed: dict[str, str] = {}

    def run(self, apply: bool) -> None:
        rows = self.session.scalars(
            select(Event)
            .where(Event.source_type == "LINUX", Event.data_origin == "LIVE_LINUX", Event.server_id.is_not(None))
            .order_by(Event.created_at, Event.id)
        ).all()
        servers = {s.id: s for s in self.session.scalars(select(Server).where(Server.id.in_({r.server_id for r in rows})))}
        contexts = {sid: host_context_for(server) for sid, server in servers.items()}
        for sid, ctx in contexts.items():
            print(f"  server {sid}: timezone={ctx.get('timezone')} utc_offset={ctx.get('utc_offset')} "
                  f"collector_ip={'captured' if ctx.get('collector_ip') else 'unavailable'}")
        self.existing_hashes = {h: i for i, h in self.session.execute(select(Event.id, Event.hash).where(Event.id.in_([r.id for r in rows])))}
        print(f"LIVE_LINUX rows examined: {len(rows)}")

        changed_rows = []
        for row in rows:
            server = servers.get(row.server_id)
            if server is None:
                self.uncorrectable["server record missing"] += 1
                continue
            before = self.snapshot(row)
            self.apply_row(row, server, contexts.get(row.server_id) or {})
            if self.snapshot(row) != before:
                changed_rows.append(row)
        self.assign_hashes(changed_rows)
        self.counts["rows changed"] = len(changed_rows)
        self.counts["rows unchanged"] = len(rows) - len(changed_rows)

        self.report()
        if apply:
            self.session.commit()
            print("APPLIED: changes committed.")
        else:
            self.session.rollback()
            print("DRY RUN: no changes written. Re-run with --apply to commit.")

    @staticmethod
    def snapshot(row: Event) -> tuple:
        return (row.event_type, row.category, row.severity, row.risk_score, row.risk_level, row.username,
                row.source_ip, row.actor_id, row.timestamp, row.timestamp_source, row.login_hour, row.normalized_data)

    def apply_row(self, row: Event, server: Server, ctx: dict[str, str]) -> None:
        nd = json.loads(row.normalized_data or "{}")
        source = nd.get("source")
        host_tz = resolve_host_timezone(ctx.get("timezone"), ctx.get("utc_offset"))
        if source in SNAPSHOT_SOURCES:
            self.apply_snapshot(row, nd, source)
        elif source in LOGIN_HISTORY_SOURCES:
            self.apply_login_history(row, nd, source, server, host_tz)
        else:
            self.apply_parser_event(row, nd, server, ctx, host_tz)
        nd.setdefault("record_origin", RECORD_ORIGIN_SOURCE_OBSERVED)
        nd["event_time_utc"] = to_utc(row.timestamp, self.db_tz).isoformat()
        if row.collection_timestamp and not nd.get("first_collection_time_utc"):
            # The column is refreshed on every re-observation; the earliest value still known is kept here.
            nd["first_collection_time_utc"] = to_utc(row.collection_timestamp, self.db_tz).isoformat()
        for key, value in (("host_timezone", ctx.get("timezone")), ("host_utc_offset", ctx.get("utc_offset"))):
            if value:
                nd[key] = value
        candidate = json.dumps({k: v for k, v in nd.items() if k != "backfill"}, default=str)
        current = json.dumps({k: v for k, v in json.loads(row.normalized_data or "{}").items() if k != "backfill"}, default=str)
        if candidate != current:
            nd["backfill"] = BACKFILL_TAG
            row.normalized_data = json.dumps(nd, default=str)

    def apply_snapshot(self, row: Event, nd: dict, source: str) -> None:
        category = "w header artifact" if source == "w" and NON_RECORD_LINES["w"].match(row.raw_log) else "snapshot"
        self.counts[f"{category} rows"] += 1
        if category == "w header artifact":
            if row.username:
                nd["parsed_username_artifact"] = row.username
            nd["artifact"] = "OUTPUT_HEADER"
            if row.actor_id == row.username:
                row.actor_id = None
            row.username = None
        if row.timestamp_source != SOURCE_SNAPSHOT:
            if row.collection_timestamp is None:
                self.uncorrectable["snapshot without collection_timestamp (time left as stored)"] += 1
            else:
                if row.timestamp != row.collection_timestamp:
                    self.counts["snapshot timestamp reset to collection time"] += 1
                    self.sample("snapshot timestamp reset", row, row.timestamp, row.collection_timestamp)
                row.timestamp = row.collection_timestamp
                row.timestamp_source = SOURCE_SNAPSHOT
        if row.event_type != EventType.SYSTEM_SNAPSHOT.value:
            self.counts[f"snapshot reclassified from '{row.event_type}'"] += 1
        row.event_type, row.category, row.severity = EventType.SYSTEM_SNAPSHOT.value, "system", "info"
        row.risk_score, row.risk_level, row.login_hour = 0, risk_level_from_score(0), None
        nd.update(record_kind=RECORD_SYSTEM_SNAPSHOT, timestamp_source=row.timestamp_source,
                  timestamp_tz_basis=TZ_COLLECTION_CLOCK)

    def apply_login_history(self, row: Event, nd: dict, source: str, server: Server, host_tz: tzinfo | None) -> None:
        if FOOTER.match(row.raw_log) or NON_RECORD_LINES["lastb"].match(row.raw_log):
            self.counts["wtmp/btmp footer artifact rows"] += 1
            occurrence = parse_occurrence(row.raw_log, collected_at=to_utc(row.collection_timestamp or row.timestamp, self.db_tz),
                                          source_hint=source, host_tz=host_tz)
            if occurrence.source == SOURCE_EVENT and occurrence.tz_basis == TZ_HOST:
                self.retime(row, occurrence.event_time, "footer")
            if row.actor_id == row.username:
                row.actor_id = None
            if row.username:
                nd["parsed_username_artifact"] = row.username
            row.event_type, row.category, row.severity = EventType.SYSTEM_EVENT.value, "system", "info"
            row.username, row.source_ip, row.login_hour = None, None, None
            row.risk_score, row.risk_level = 10, risk_level_from_score(10)
            nd.update(record_kind=RECORD_SYSTEM_EVENT, artifact="OUTPUT_FOOTER")
            return

        derived = derive(source, row.raw_log, hostname=row.hostname, host_tz=host_tz)
        if derived is None:
            self.uncorrectable["login-history line no longer parseable"] += 1
            return
        meta = derived["metadata"]
        kind = meta["record_kind"]
        self.counts[f"{source} {kind} rows"] += 1
        if kind == RECORD_SYSTEM_EVENT and row.event_type != EventType.SYSTEM_EVENT.value:
            self.counts[f"{source} reboot/shutdown reclassified from '{row.event_type}'"] += 1
        if host_tz is None:
            self.uncorrectable[f"{source} row: host timezone unknown (time left as stored)"] += 1
        elif meta["timestamp_source"] == SOURCE_EVENT:
            self.retime(row, datetime.fromisoformat(derived["timestamp"]), source)
        else:
            self.uncorrectable[f"{source} row: no parseable source time (time left as stored)"] += 1
        if row.actor_id and row.actor_id == row.username and derived["username"] is None:
            row.actor_id = None
        row.event_type, row.category, row.severity = derived["event_type"], derived["category"], derived["severity"]
        row.risk_score = derived["risk_score"]
        row.risk_level = risk_level_from_score(derived["risk_score"])
        row.username, row.source_ip = derived["username"], derived["source_ip"]
        row.timestamp_source = meta["timestamp_source"] if host_tz is not None else row.timestamp_source
        row.login_hour = (login_hour_from(to_utc(row.timestamp, self.db_tz))
                          if kind == RECORD_SECURITY_EVENT and row.timestamp_source == SOURCE_EVENT else None)
        nd.update(meta["normalized_data"])
        nd["record_kind"] = kind
        if host_tz is None:
            nd.pop("timestamp_tz_basis", None)
        self.queue_hash(row, nd)

    def apply_parser_event(self, row: Event, nd: dict, server: Server, ctx: dict[str, str], host_tz: tzinfo | None) -> None:
        self.counts["sshd/journal/audit parser rows"] += 1
        nd.setdefault("record_kind", RECORD_SECURITY_EVENT)
        occurrence = parse_occurrence(row.raw_log, collected_at=to_utc(row.collection_timestamp or row.timestamp, self.db_tz),
                                      source_hint=nd.get("source"), host_tz=host_tz)
        stored = to_utc(row.timestamp, self.db_tz)
        if occurrence.source == SOURCE_EVENT and occurrence.event_time == stored:
            nd["timestamp_tz_basis"] = occurrence.tz_basis
            self.counts[f"parser rows already correct ({occurrence.tz_basis})"] += 1
        elif occurrence.source == SOURCE_EVENT and occurrence.tz_basis == TZ_HOST:
            self.retime(row, occurrence.event_time, "parser wall-clock")
            nd["timestamp_tz_basis"] = TZ_HOST
            if row.login_hour is not None:
                row.login_hour = login_hour_from(occurrence.event_time)
            self.queue_hash(row, nd)
        else:
            self.uncorrectable[f"parser row time differs from source but semantics not host wall-clock ({occurrence.tz_basis})"] += 1
        collector_ip = ctx.get("collector_ip")
        if (collector_ip and row.event_type in LOGIN_TYPES and row.username == server.username
                and row.source_ip == collector_ip):
            nd.update(record_origin=RECORD_ORIGIN_COLLECTOR, record_origin_basis=COLLECTOR_ORIGIN_BASIS)
            self.counts["parser rows tagged COLLECTOR_GENERATED"] += 1
        elif row.event_type in LOGIN_TYPES and not collector_ip:
            self.uncorrectable["login row: collector IP unknown (origin left SOURCE_OBSERVED)"] += 1

    def retime(self, row: Event, new_utc: datetime, label: str) -> None:
        old = to_utc(row.timestamp, self.db_tz)
        if old != new_utc:
            self.counts[f"{label} timestamp corrected to host-zone UTC"] += 1
            self.sample(f"{label} retimed", row, old, new_utc)
            row.timestamp = new_utc

    def queue_hash(self, row: Event, nd: dict) -> None:
        new_hash = crud.calculate_event_hash(
            row.raw_log, crud._parse_timestamp(to_utc(row.timestamp, self.db_tz)), server_id=row.server_id,
            event_type=row.event_type, username=row.username, source_ip=row.source_ip,
        )
        if new_hash == row.hash:
            return
        holder = self.claimed.get(new_hash) or self.existing_hashes.get(new_hash)
        if holder and holder != row.id and holder not in self.hash_updates:
            self.counts["hash collision: identical occurrence already stored (row kept, old hash kept)"] += 1
            nd["duplicate_of_row"] = holder
            return
        self.claimed[new_hash] = row.id
        self.hash_updates[row.id] = new_hash

    def assign_hashes(self, changed_rows: list[Event]) -> None:
        targets = [r for r in changed_rows if r.id in self.hash_updates]
        for row in targets:
            row.hash = f"backfill-{uuid.uuid4().hex}"
        self.session.flush()
        for row in targets:
            row.hash = self.hash_updates[row.id]
        self.session.flush()
        self.counts["hashes recomputed"] = len(targets)

    def sample(self, label: str, row: Event, before, after) -> None:
        self.samples.setdefault(label, (row.raw_log[:90], str(before), str(after)))

    def report(self) -> None:
        print("\n== Counts ==")
        for key, value in sorted(self.counts.items()):
            print(f"  {key}: {value}")
        print("== Not safely correctable (left as stored) ==")
        for key, value in sorted(self.uncorrectable.items()) or [("none", 0)]:
            print(f"  {key}: {value}")
        print("== Samples (raw line | before | after) ==")
        for label, (raw, before, after) in self.samples.items():
            print(f"  [{label}] {raw!r} | {before} | {after}")


def cloud_fingerprint(session) -> tuple:
    rows = session.execute(select(Event.id, Event.hash, Event.timestamp, Event.event_type, Event.normalized_data)
                           .where(Event.source_type == "CLOUD").order_by(Event.id)).all()
    return len(rows), hash(tuple(map(tuple, rows)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="commit the changes (default: dry run)")
    args = parser.parse_args()
    session = get_session()
    try:
        cloud_before = cloud_fingerprint(session)
        Backfill(session).run(apply=args.apply)
        cloud_after = cloud_fingerprint(session)
        print(f"CLOUD rows: {cloud_before[0]} before, {cloud_after[0]} after, unchanged={cloud_before == cloud_after}")
        print("LINUX total:", session.scalar(select(func.count(Event.id)).where(Event.source_type == "LINUX")))
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
