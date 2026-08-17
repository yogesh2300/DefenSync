"""Generate a small synthetic OpenStack log sample for presentation demos.

These lines follow the existing Loghub-style parser prefix:
  YYYY-MM-DD HH:MM:SS.mmm PID SEVERITY logger [req-... user tenant] message

This is NOT a real public Loghub dump. Importers must label it SYNTHETIC_CLOUD_DEMO.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "datasets" / "OpenStack" / "demo"
OUTPUT = OUTPUT_DIR / "openstack_synthetic_demo.log"
README = Path(__file__).resolve().parents[1] / "datasets" / "OpenStack" / "README.md"

DEMO_USER = "yogesh"
DEMO_TENANT = "demo-tenant"
OTHER_USER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
OTHER_TENANT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
INSTANCE = "cccccccc-cccc-cccc-cccc-cccccccccccc"
VOLUME = "dddddddd-dddd-dddd-dddd-dddddddddddd"
IMAGE = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

# Align with behavioral yogesh rows: 2026-08-01 + (1000 * 7 minutes) = 2026-08-05 20:40 UTC
YOGESH_ANCHOR = datetime(2026, 8, 5, 20, 40, tzinfo=timezone.utc)


def _req(index: int) -> str:
    return f"req-{index:08d}-1234-1234-1234-123456789abc"


def _line(
    stamp: datetime,
    severity: str,
    logger: str,
    message: str,
    *,
    user: str = OTHER_USER,
    tenant: str = OTHER_TENANT,
    pid: int = 2931,
) -> str:
    ts = stamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    req = _req(int(stamp.timestamp()) + pid)
    return f"{ts} {pid} {severity} {logger} [{req} {user} {tenant}] {message}"


def build_lines() -> list[str]:
    lines: list[str] = []
    base = datetime(2026, 8, 5, 18, 0, tzinfo=timezone.utc)

    # Normal informational API / VM / auth activity
    for index in range(70):
        stamp = base + timedelta(minutes=index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "nova.osapi_compute.wsgi.server",
                f'10.11.10.{(index % 50) + 1} "GET /v2/servers/detail HTTP/1.1" status: 200 len: 1842 time: 0.12',
            )
        )
    for index in range(25):
        stamp = base + timedelta(minutes=80 + index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "nova.compute.manager",
                f"[instance: {INSTANCE}] build_and_run_instance created server demo-vm-{index:02d}",
            )
        )
    for index in range(15):
        stamp = base + timedelta(minutes=110 + index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "keystone.auth.plugins.password",
                "Authenticated successfully; token issued for project demo",
            )
        )
    for index in range(12):
        stamp = base + timedelta(minutes=130 + index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "cinder.volume.manager",
                f"volume attached {VOLUME} to instance {INSTANCE}",
            )
        )
    for index in range(10):
        stamp = base + timedelta(minutes=145 + index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "glance.api.v2.images",
                f'"GET /v2/images/{IMAGE} HTTP/1.1" status: 200 len: 512 time: 0.08',
            )
        )
    for index in range(8):
        stamp = base + timedelta(minutes=160 + index)
        lines.append(
            _line(
                stamp,
                "INFO",
                "neutron.api.v2.resource",
                'create network demo-net completed',
            )
        )

    # Warnings
    for index in range(20):
        stamp = base + timedelta(minutes=175 + index)
        lines.append(
            _line(
                stamp,
                "WARNING",
                "nova.compute.manager",
                f"[instance: {INSTANCE}] VM paused while waiting for volume attach retry {index}",
            )
        )

    # Errors / high-severity / auth failures
    for index in range(12):
        stamp = base + timedelta(minutes=200 + index)
        lines.append(
            _line(
                stamp,
                "ERROR",
                "nova.api.openstack.wsgi",
                f'10.11.20.{index + 1} "POST /v2/servers HTTP/1.1" status: 403 len: 88 time: 0.04 Unauthorized: policy doesn\'t allow os_compute_api:servers:create',
            )
        )
    for index in range(8):
        stamp = base + timedelta(minutes=215 + index)
        lines.append(
            _line(
                stamp,
                "ERROR",
                "keystone.auth.plugins.password",
                f"authentication failed from 203.0.113.{index + 10}: invalid credentials",
            )
        )
    for index in range(6):
        stamp = base + timedelta(minutes=225 + index)
        lines.append(
            _line(
                stamp,
                "CRITICAL",
                "nova.compute.manager",
                f"[instance: {INSTANCE}] Failed to destroy instance after repeated compute errors",
            )
        )

    # Yogesh overlap: same actor_id as behavioral demo, within 15 minutes of 20:40 UTC
    yogesh_events = [
        (0, "INFO", "keystone.auth.plugins.password", "Authenticated successfully; token issued for user yogesh"),
        (2, "INFO", "nova.compute.manager", f"[instance: {INSTANCE}] build_and_run_instance created server yogesh-lab"),
        (4, "INFO", "nova.osapi_compute.wsgi.server", '10.20.30.40 "GET /v2/servers/detail HTTP/1.1" status: 200 len: 220 time: 0.09'),
        (6, "INFO", "nova.compute.manager", f"[instance: {INSTANCE}] start instance yogesh-lab powering-on"),
        (8, "WARNING", "nova.compute.manager", f"[instance: {INSTANCE}] VM paused while snapshotting yogesh-lab"),
        (10, "ERROR", "keystone.auth.plugins.password", "authentication failed for yogesh: invalid credentials"),
        (12, "ERROR", "nova.api.openstack.wsgi", '10.20.30.40 "DELETE /v2/servers/' + INSTANCE + ' HTTP/1.1" status: 403 len: 64 time: 0.05 Unauthorized: policy doesn\'t allow os_compute_api:servers:delete'),
        (14, "CRITICAL", "nova.compute.manager", f"[instance: {INSTANCE}] Failed to destroy instance yogesh-lab"),
    ]
    for offset, severity, logger, message in yogesh_events:
        lines.append(
            _line(
                YOGESH_ANCHOR + timedelta(minutes=offset),
                severity,
                logger,
                message,
                user=DEMO_USER,
                tenant=DEMO_TENANT,
                pid=4100,
            )
        )

    return lines


def generate() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = build_lines()
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    README.write_text(
        "# OpenStack demo dataset\n\n"
        "The file `demo/openstack_synthetic_demo.log` is a **synthetic** sample written "
        "to match DefenSync's existing OpenStack parser. It is not a Loghub public dump "
        "and must be stored as `data_origin=SYNTHETIC_CLOUD_DEMO`.\n\n"
        "A small subset of lines uses actor `yogesh` near 2026-08-05 20:40 UTC so the "
        "Intelligence page can correlate them with the synthetic behavioral demo identity.\n",
        encoding="utf-8",
    )
    return OUTPUT


if __name__ == "__main__":
    path = generate()
    print(f"Generated {path} ({sum(1 for _ in path.open(encoding='utf-8'))} lines)")
