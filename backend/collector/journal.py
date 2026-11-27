"""Incremental journald reading with a per-server cursor.

Entries are read as JSON (one object per line, each with its own __CURSOR) so a bounded
read never loses position, then rebuilt into the exact `journalctl -o short-iso` line the
parser and the event hash already use. Only auth (4) and authpriv (10) facilities are read:
sshd, sudo, su, PAM sessions and systemd-logind.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

JOURNAL_FACILITIES = ("4", "10")
JOURNAL_FIELDS = "MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_PID,_COMM,_HOSTNAME,_BOOT_ID,_SOURCE_REALTIME_TIMESTAMP"
CURSOR_PATTERN = re.compile(r"[A-Za-z0-9=;_-]{1,512}")
MARKER = "__DS_"
MODE_INITIAL = "initial"
MODE_CURSOR = "cursor"
MODE_SINCE = "since"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Read-only, no root: current boot, whether journald keeps history on disk, boots available.
JOURNAL_STATUS_COMMAND = (
    f"printf '{MARKER}BOOT_ID=%s\\n' \"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\"; "
    f"if [ -d /var/log/journal ]; then echo {MARKER}VAR_LOG_JOURNAL=yes; else echo {MARKER}VAR_LOG_JOURNAL=no; fi; "
    f"printf '{MARKER}STORAGE=%s\\n' \"$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null"
    " | sed -n 's/^[[:space:]]*Storage=[[:space:]]*//p' | tail -n 1)\"; "
    f"printf '{MARKER}BOOTS=%s\\n' \"$(journalctl --list-boots -q --no-pager 2>/dev/null | grep -cE '[0-9a-f]{{32}}')\""
)


@dataclass(frozen=True, slots=True)
class JournalPosition:
    """Last journal entry stored for one server. Empty means read from the oldest available entry."""

    cursor: str | None = None
    boot_id: str | None = None
    realtime_usec: int | None = None


@dataclass(slots=True)
class JournalBatch:
    lines: list[str]
    # Rebuilt line -> journal metadata for that entry (boot_id, occurrence realtime_usec, pid, program).
    entries: dict[str, dict[str, Any]]
    mode: str | None
    entries_read: int
    truncated: bool
    last_position: JournalPosition | None
    current_boot_id: str | None = None
    persistent: bool | None = None
    storage: str | None = None
    boots_available: int | None = None
    errors: list[str] = field(default_factory=list)


def normalize_boot_id(value: str | None) -> str | None:
    """/proc reports a dashed UUID; journal _BOOT_ID is 32 hex characters."""
    cleaned = (value or "").strip().replace("-", "").lower()
    return cleaned or None


def build_journal_command(position: JournalPosition, max_entries: int) -> str:
    """Remote command: status markers, read mode, then at most max_entries JSON entries."""
    base = (
        f"journalctl -o json --output-fields={JOURNAL_FIELDS} --no-pager -q "
        + " ".join(f"SYSLOG_FACILITY={facility}" for facility in JOURNAL_FACILITIES)
    )
    read = f"2>/dev/null | head -n {int(max_entries)}"
    if position.cursor and CURSOR_PATTERN.fullmatch(position.cursor):
        cursor = shlex.quote(position.cursor)
        since = f"--since=@{position.realtime_usec // 1_000_000}" if position.realtime_usec else ""
        return (
            f"{JOURNAL_STATUS_COMMAND}; "
            f"if journalctl -q -n 1 -o cat --no-pager --after-cursor={cursor} >/dev/null 2>&1; "
            f"then echo {MARKER}MODE={MODE_CURSOR}; {base} --after-cursor={cursor} {read}; "
            f"else echo {MARKER}MODE={MODE_SINCE}; {base} {since} {read}; fi"
        )
    return f"{JOURNAL_STATUS_COMMAND}; echo {MARKER}MODE={MODE_INITIAL}; {base} {read}"


def occurrence_usec(entry: dict[str, Any]) -> int | None:
    """When the sending process logged the entry; journald's receive time only if the sender gave none."""
    for key in ("_SOURCE_REALTIME_TIMESTAMP", "__REALTIME_TIMESTAMP"):
        value = entry.get(key)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def short_iso_line(entry: dict[str, Any], host_tz: tzinfo | None) -> str | None:
    """Rebuild `journalctl -o short-iso` output for one entry (identifier, then _PID before SYSLOG_PID)."""
    message = entry.get("MESSAGE")
    if isinstance(message, list):
        message = bytes(message).decode("utf-8", errors="replace")
    usec = occurrence_usec(entry)
    if not isinstance(message, str) or usec is None:
        return None
    moment = (_EPOCH + timedelta(microseconds=int(usec))).astimezone(host_tz or timezone.utc)
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%S%z")
    stamp = f"{stamp[:-2]}:{stamp[-2:]}"
    identifier = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "unknown"
    pid = entry.get("_PID") or entry.get("SYSLOG_PID")
    head = f"{stamp} {entry.get('_HOSTNAME') or 'localhost'} {identifier}"
    head = f"{head}[{pid}]:" if pid else f"{head}:"
    return f"{head} {message.replace(chr(10), ' ')}"


def _persistent(storage: str | None, var_log_journal: str | None) -> bool | None:
    value = (storage or "").strip().lower()
    if value == "persistent":
        return True
    if value in {"volatile", "none"}:
        return False
    if var_log_journal in {"yes", "no"}:
        return var_log_journal == "yes"
    return None


def parse_journal_output(lines: list[str], host_tz: tzinfo | None, max_entries: int) -> JournalBatch:
    markers: dict[str, str] = {}
    rebuilt: list[str] = []
    entries: dict[str, dict[str, Any]] = {}
    last: dict[str, Any] | None = None
    read = 0
    for line in lines:
        if line.startswith(MARKER):
            key, _, value = line[len(MARKER):].partition("=")
            markers[key] = value.strip()
            continue
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        read += 1
        if entry.get("__CURSOR"):
            last = entry
        text = short_iso_line(entry, host_tz)
        if text is None:
            continue
        rebuilt.append(text)
        entries[text] = {
            "boot_id": normalize_boot_id(entry.get("_BOOT_ID")),
            "realtime_usec": occurrence_usec(entry),
            "pid": entry.get("_PID") or entry.get("SYSLOG_PID"),
            "program": entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM"),
        }
    boots = markers.get("BOOTS", "")
    return JournalBatch(
        lines=rebuilt,
        entries=entries,
        mode=markers.get("MODE"),
        entries_read=read,
        truncated=read >= max_entries,
        last_position=JournalPosition(
            cursor=last["__CURSOR"],
            boot_id=normalize_boot_id(last.get("_BOOT_ID")),
            realtime_usec=int(last["__REALTIME_TIMESTAMP"]) if last.get("__REALTIME_TIMESTAMP") else None,
        ) if last else None,
        current_boot_id=normalize_boot_id(markers.get("BOOT_ID")),
        persistent=_persistent(markers.get("STORAGE"), markers.get("VAR_LOG_JOURNAL")),
        storage=markers.get("STORAGE") or "auto",
        boots_available=int(boots) if boots.isdigit() else None,
    )
