"""Parse `last -F` / `lastb -F` lines into a session with a stable identity.

The same wtmp session is printed differently over time ("still logged in", then
"- <logout> (hh:mm)", "- crash", "gone - no logout"), so the raw line cannot identify it.
The identity is source, user, terminal, remote host and login time; collection time is
never part of it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo

from backend.core.timestamps import parse_last_line

_TS = (
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}"
)
LAST_LINE = re.compile(
    rf"^(?P<user>\S+)\s+(?P<terminal>system \S+|\S+)\s+(?:(?P<host>\S+)\s+)?(?P<login>{_TS})"
    rf"(?:\s+-\s+(?P<logout>{_TS})|\s+-\s+(?P<end>crash|down|no logout)"
    r"|\s+(?P<state>still logged in|still running|gone - no logout))?"
    r"(?:\s+\((?P<duration>(?:\d+\+)?\d{2}:\d{2})\))?\s*$"
)
SESSION_ID_MAX = 120
DURATION_FROM_LOGOUT = "wtmp_logout_time"
DURATION_REPORTED = "wtmp_reported_duration"


@dataclass(frozen=True, slots=True)
class LoginHistorySession:
    session_key: str
    session_id: str
    username: str
    terminal: str
    remote_host: str | None
    login_time: datetime
    logout_time: datetime | None
    session_state: str
    duration_seconds: float | None
    duration_basis: str | None


def _reported_seconds(value: str | None) -> float | None:
    """`last` prints duration as [days+]hh:mm; it is rounded to the minute."""
    if not value:
        return None
    days, _, clock = value.rpartition("+")
    hours, minutes = clock.split(":")
    return float((int(days or 0) * 24 * 60 + int(hours) * 60 + int(minutes)) * 60)


def session_key_for(source: str, username: str, terminal: str, remote_host: str | None, login_utc: datetime) -> str:
    return f"{source}:{username}:{terminal}:{remote_host or '-'}:{login_utc.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def session_id_for(key: str) -> str:
    if len(key) <= SESSION_ID_MAX:
        return key
    return "wtmp:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_login_history_line(
    line: str,
    *,
    source: str,
    collected_at: datetime,
    host_tz: tzinfo | None,
) -> LoginHistorySession | None:
    match = LAST_LINE.match(line.strip())
    if not match:
        return None
    login = parse_last_line(match.group("login"), collected_at=collected_at, host_tz=host_tz)
    if login is None:
        return None
    logout = (
        parse_last_line(match.group("logout"), collected_at=collected_at, host_tz=host_tz)
        if match.group("logout") else None
    )
    duration: float | None = None
    basis: str | None = None
    if logout is not None:
        duration, basis, state = (logout - login).total_seconds(), DURATION_FROM_LOGOUT, "closed"
    elif match.group("end"):
        state = match.group("end").replace(" ", "_")
        reported = _reported_seconds(match.group("duration"))
        if reported is not None:
            duration, basis = reported, DURATION_REPORTED
    else:
        state = (match.group("state") or "unknown").replace(" - ", "_").replace(" ", "_")
    terminal = match.group("terminal")
    host = match.group("host")
    key = session_key_for(source, match.group("user"), terminal, host, login)
    return LoginHistorySession(
        session_key=key,
        session_id=session_id_for(key),
        username=match.group("user"),
        terminal=terminal,
        remote_host=host,
        login_time=login,
        logout_time=logout,
        session_state=state,
        duration_seconds=duration,
        duration_basis=basis,
    )
