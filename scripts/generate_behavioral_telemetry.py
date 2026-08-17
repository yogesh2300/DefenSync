"""Generate deterministic synthetic aggregate behavioral telemetry.

This script does not collect keystrokes or command contents. It creates only
privacy-preserving aggregate timing/statistical fields for prototype validation.
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 424242
DATASET_DIR = Path(__file__).resolve().parents[1] / "datasets" / "behavioral"
OUTPUT = DATASET_DIR / "generated_behavioral_telemetry.csv"
README = DATASET_DIR / "README.md"

FIELDS = [
    "timestamp",
    "user_id",
    "linux_username",
    "session_id",
    "server_id",
    "typing_speed_cpm",
    "command_rate_per_minute",
    "command_error_rate",
    "idle_time_seconds",
    "repeated_command_ratio",
    "session_duration_minutes",
    "login_hour",
    "is_anomaly",
    "behavior_class",
    "data_origin",
]

USERS = {
    "user-001": {"linux_username": "alice", "typing": 185, "cmd": 3.2, "err": 0.08, "idle": 90, "rep": 0.18, "dur": 55, "hour": 9},
    "user-002": {"linux_username": "bob", "typing": 145, "cmd": 2.4, "err": 0.12, "idle": 140, "rep": 0.12, "dur": 42, "hour": 10},
    "user-003": {"linux_username": "carol", "typing": 220, "cmd": 4.0, "err": 0.06, "idle": 70, "rep": 0.24, "dur": 65, "hour": 13},
    "user-004": {"linux_username": "dinesh", "typing": 165, "cmd": 2.9, "err": 0.10, "idle": 110, "rep": 0.16, "dur": 50, "hour": 16},
    "user-005": {"linux_username": "eve", "typing": 205, "cmd": 3.6, "err": 0.07, "idle": 80, "rep": 0.20, "dur": 60, "hour": 11},
}

COUNTS = {
    "NORMAL": 800,
    "OVER_EFFICIENCY": 80,
    "AUTOMATED_ACTIVITY": 60,
    "UNUSUAL_SESSION": 30,
    "SUSPICIOUS_BEHAVIOR": 30,
}

# Dedicated presentation identity: enough NORMAL rows on one server to reach ACTIVE.
DEMO_USER_ID = "yogesh"
DEMO_LINUX_USERNAME = "yogesh"
DEMO_SERVER_ID = "server-demo"
DEMO_NORMAL_COUNT = 25
DEMO_OVER_EFFICIENCY_COUNT = 6
DEMO_AUTOMATED_COUNT = 4
DEMO_BASE = {
    "typing": 172.0,
    "cmd": 2.8,
    "err": 0.09,
    "idle": 110.0,
    "rep": 0.15,
    "dur": 46.0,
    "hour": 10,
}


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def make_record(rng: random.Random, index: int, behavior_class: str) -> dict[str, object]:
    user_id = list(USERS.keys())[index % len(USERS)]
    base = USERS[user_id]
    server_id = f"server-{(index % 3) + 1:02d}"
    timestamp = datetime(2026, 7, 15, tzinfo=timezone.utc) + timedelta(minutes=index * 5)

    typing = rng.gauss(base["typing"], 14)
    cmd = rng.gauss(base["cmd"], 0.45)
    err = rng.gauss(base["err"], 0.025)
    idle = rng.gauss(base["idle"], 20)
    rep = rng.gauss(base["rep"], 0.04)
    dur = rng.gauss(base["dur"], 12)
    hour = int(clamp(round(rng.gauss(base["hour"], 1.2)), 0, 23))

    if behavior_class == "OVER_EFFICIENCY":
        typing = base["typing"] * rng.uniform(1.85, 2.25)
        cmd = base["cmd"] * rng.uniform(2.05, 2.7)
        err = base["err"] * rng.uniform(0.05, 0.22)
        idle = base["idle"] * rng.uniform(0.05, 0.18)
        rep = rng.uniform(0.72, 0.88)
    elif behavior_class == "AUTOMATED_ACTIVITY":
        typing = base["typing"] * rng.uniform(2.1, 2.8)
        cmd = base["cmd"] * rng.uniform(3.2, 5.0)
        err = base["err"] * rng.uniform(0.0, 0.08)
        idle = base["idle"] * rng.uniform(0.0, 0.08)
        rep = rng.uniform(0.84, 0.98)
        dur = base["dur"] * rng.uniform(0.4, 0.8)
    elif behavior_class == "UNUSUAL_SESSION":
        hour = rng.choice([0, 1, 2, 3, 22, 23])
        dur = base["dur"] * rng.choice([rng.uniform(0.18, 0.35), rng.uniform(2.4, 3.4)])
    elif behavior_class == "SUSPICIOUS_BEHAVIOR":
        typing = base["typing"] * rng.uniform(1.25, 1.65)
        cmd = base["cmd"] * rng.uniform(1.35, 1.9)
        err = base["err"] * rng.uniform(0.35, 0.65)
        idle = base["idle"] * rng.uniform(0.35, 0.65)
        rep = rng.uniform(0.48, 0.68)
        hour = int(clamp(base["hour"] + rng.choice([-4, 4, 5]), 0, 23))

    return {
        "timestamp": timestamp.isoformat(),
        "user_id": user_id,
        "linux_username": base["linux_username"],
        "session_id": f"sess-{index + 1:05d}",
        "server_id": server_id,
        "typing_speed_cpm": round(clamp(typing, 20, 900), 2),
        "command_rate_per_minute": round(clamp(cmd, 0, 80), 3),
        "command_error_rate": round(clamp(err, 0, 1), 4),
        "idle_time_seconds": round(clamp(idle, 0, 3600), 2),
        "repeated_command_ratio": round(clamp(rep, 0, 1), 4),
        "session_duration_minutes": round(clamp(dur, 1, 720), 2),
        "login_hour": hour,
        "is_anomaly": behavior_class != "NORMAL",
        "behavior_class": behavior_class,
        "data_origin": "SYNTHETIC",
    }


def make_demo_record(rng: random.Random, index: int, behavior_class: str) -> dict[str, object]:
    """Create a synthetic row for the presentation identity `yogesh` on one server."""
    timestamp = datetime(2026, 8, 1, tzinfo=timezone.utc) + timedelta(minutes=index * 7)
    typing = rng.gauss(DEMO_BASE["typing"], 8)
    cmd = rng.gauss(DEMO_BASE["cmd"], 0.22)
    err = rng.gauss(DEMO_BASE["err"], 0.012)
    idle = rng.gauss(DEMO_BASE["idle"], 12)
    rep = rng.gauss(DEMO_BASE["rep"], 0.02)
    dur = rng.gauss(DEMO_BASE["dur"], 6)
    hour = int(clamp(round(rng.gauss(DEMO_BASE["hour"], 0.8)), 8, 17))

    if behavior_class == "OVER_EFFICIENCY":
        typing = DEMO_BASE["typing"] * rng.uniform(1.9, 2.2)
        cmd = DEMO_BASE["cmd"] * rng.uniform(2.05, 2.6)
        err = DEMO_BASE["err"] * rng.uniform(0.04, 0.18)
        idle = DEMO_BASE["idle"] * rng.uniform(0.04, 0.16)
        rep = rng.uniform(0.74, 0.86)
    elif behavior_class == "AUTOMATED_ACTIVITY":
        typing = DEMO_BASE["typing"] * rng.uniform(2.2, 2.7)
        cmd = DEMO_BASE["cmd"] * rng.uniform(3.2, 4.6)
        err = DEMO_BASE["err"] * rng.uniform(0.0, 0.06)
        idle = DEMO_BASE["idle"] * rng.uniform(0.0, 0.08)
        rep = rng.uniform(0.86, 0.96)
        dur = DEMO_BASE["dur"] * rng.uniform(0.35, 0.7)

    return {
        "timestamp": timestamp.isoformat(),
        "user_id": DEMO_USER_ID,
        "linux_username": DEMO_LINUX_USERNAME,
        "session_id": f"sess-yogesh-{index + 1:04d}",
        "server_id": DEMO_SERVER_ID,
        "typing_speed_cpm": round(clamp(typing, 20, 900), 2),
        "command_rate_per_minute": round(clamp(cmd, 0, 80), 3),
        "command_error_rate": round(clamp(err, 0, 1), 4),
        "idle_time_seconds": round(clamp(idle, 0, 3600), 2),
        "repeated_command_ratio": round(clamp(rep, 0, 1), 4),
        "session_duration_minutes": round(clamp(dur, 1, 720), 2),
        "login_hour": hour,
        "is_anomaly": behavior_class != "NORMAL",
        "behavior_class": behavior_class,
        "data_origin": "SYNTHETIC",
    }


def build_rows() -> list[dict[str, object]]:
    rng = random.Random(SEED)
    rows: list[dict[str, object]] = []
    idx = 0
    for behavior_class, count in COUNTS.items():
        for _ in range(count):
            rows.append(make_record(rng, idx, behavior_class))
            idx += 1
    for _ in range(DEMO_NORMAL_COUNT):
        rows.append(make_demo_record(rng, idx, "NORMAL"))
        idx += 1
    for _ in range(DEMO_OVER_EFFICIENCY_COUNT):
        rows.append(make_demo_record(rng, idx, "OVER_EFFICIENCY"))
        idx += 1
    for _ in range(DEMO_AUTOMATED_COUNT):
        rows.append(make_demo_record(rng, idx, "AUTOMATED_ACTIVITY"))
        idx += 1
    rng.shuffle(rows)
    return rows


def generate() -> Path:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    rows = build_rows()

    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    README.write_text(
        "# DefenSync Behavioral Telemetry Dataset\n\n"
        "This dataset is synthetic and generated with a deterministic random seed. "
        "It is designed only for prototype validation of aggregate behavioral baselines. "
        "These values are NOT live Linux keystroke or session telemetry.\n\n"
        "Privacy notes:\n"
        "- No keystrokes are collected or stored.\n"
        "- No passwords, command contents, clipboard data, or typed text are stored.\n"
        "- Only aggregate timing and statistical measurements are included.\n\n"
        f"Class counts: {COUNTS}\n"
        f"Demo identity: {DEMO_USER_ID} on {DEMO_SERVER_ID} "
        f"(NORMAL={DEMO_NORMAL_COUNT}, OVER_EFFICIENCY={DEMO_OVER_EFFICIENCY_COUNT}, "
        f"AUTOMATED_ACTIVITY={DEMO_AUTOMATED_COUNT})\n",
        encoding="utf-8",
    )
    return OUTPUT


if __name__ == "__main__":
    path = generate()
    print(f"Generated {path}")
