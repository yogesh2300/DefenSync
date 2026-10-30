#!/usr/bin/env python3
"""QA-ONLY local OTP mailbox for DefenSync browser demos.

This process *is* the QA SMTP mailbox (in-memory). It binds to 127.0.0.1 only.
It does not share memory with other processes, does not read .env or Gmail, and
does not add any HTTP API. Start it before the backend that delivers OTP email
to 127.0.0.1:<port>.

Usage (PowerShell), from the repo root with the venv active:

  # Default: announce arrivals without showing the code
  python scripts/qa_otp_mailbox.py

  # Opt-in: print OTP values for typing into the local UI
  python scripts/qa_otp_mailbox.py --print-codes

  # Optional port (must match backend SMTP_PORT / QA_SMTP_PORT)
  $env:QA_SMTP_PORT = "2525"
  python scripts/qa_otp_mailbox.py --print-codes

Then start the backend with process SMTP pointed at this mailbox (not .env):

  $env:SMTP_HOST = "127.0.0.1"
  $env:SMTP_PORT = "2525"
  $env:SMTP_SECURITY = "none"
  $env:SMTP_FROM = "defensync-qa@localhost"
  $env:SMTP_USERNAME = " "
  $env:SMTP_PASSWORD = " "
  python -m backend.main

Sign in at the local frontend and, if --print-codes was used, type the OTP
shown in this terminal. Codes are never written to application logs.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.testing.otp_mailbox import QA_SMTP_HOST, OTPMailbox, QALoginError

BANNER = "QA-ONLY — local DefenSync demo mailbox; not for production."


def mask_recipient(address: str) -> str:
    value = (address or "").strip().lower()
    if "@" not in value:
        return "***"
    local, _, domain = value.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[:1]}***@{domain}"


def format_arrival(*, print_codes: bool, code: str, recipients: tuple[str, ...] = ()) -> str:
    who = ", ".join(mask_recipient(item) for item in recipients) if recipients else "(recipient unknown)"
    if print_codes:
        return f"[QA-ONLY] OTP for {who}: {code}"
    return f"[QA-ONLY] OTP received for {who} (hidden; pass --print-codes to display)."


def consume_delivery(
    mailbox: OTPMailbox,
    *,
    since: float,
    timeout: float = 1.0,
) -> tuple[str, tuple[str, ...]] | None:
    """Wait for one in-memory delivery at/after `since` (same process as the mailbox)."""
    deadline = time.monotonic() + timeout
    with mailbox._ready:
        while True:
            for delivery in reversed(list(mailbox._deliveries)):
                if delivery.received_at >= since:
                    mailbox._deliveries.remove(delivery)
                    return delivery.code, delivery.recipients
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            mailbox._ready.wait(remaining)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local QA OTP mailbox for DefenSync browser demos (127.0.0.1 only).",
    )
    parser.add_argument(
        "--print-codes",
        action="store_true",
        help="Opt-in: print OTP values so they can be typed into the local UI.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Listen port (default: QA_SMTP_PORT or 2525). Host is always 127.0.0.1.",
    )
    return parser


def run_mailbox(
    mailbox: OTPMailbox,
    *,
    print_codes: bool,
    emit: Callable[[str], None],
    should_stop: Callable[[], bool] | None = None,
    poll_timeout: float = 1.0,
) -> None:
    """Block until should_stop(), announcing each OTP delivery."""
    emit(BANNER)
    emit(f"Listening on {mailbox.host}:{mailbox.port}")
    if print_codes:
        emit("OTP display ENABLED (--print-codes). Use only on a trusted local machine.")
    else:
        emit("OTP display DISABLED (default). Re-run with --print-codes to show codes.")

    since = time.monotonic()
    while True:
        if should_stop is not None and should_stop():
            return
        delivery = consume_delivery(mailbox, since=since, timeout=poll_timeout)
        if delivery is None:
            continue
        code, recipients = delivery
        emit(format_arrival(print_codes=print_codes, code=code, recipients=recipients))
        since = time.monotonic()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    port = args.port
    if port is None:
        port = int(os.getenv("QA_SMTP_PORT", "2525"))
    if port < 0:
        print("Port must be >= 0 (0 = ephemeral).", file=sys.stderr)
        return 2

    try:
        mailbox = OTPMailbox(host=QA_SMTP_HOST, port=port).start()
    except QALoginError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if mailbox.host != "127.0.0.1":
        mailbox.stop()
        print("Refusing to listen on a non-loopback host.", file=sys.stderr)
        return 1

    try:
        run_mailbox(mailbox, print_codes=bool(args.print_codes), emit=print)
    except KeyboardInterrupt:
        print("\nStopping QA mailbox.")
    finally:
        mailbox.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
