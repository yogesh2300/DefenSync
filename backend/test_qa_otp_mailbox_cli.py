"""Focused tests for scripts/qa_otp_mailbox.py (QA-only local demo helper)."""

from __future__ import annotations

import smtplib
import threading
import time
import unittest
from email.message import EmailMessage
from pathlib import Path

from backend.testing.otp_mailbox import OTPMailbox

# Import the script module without installing it as a package.
import importlib.util

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "qa_otp_mailbox.py"
SPEC = importlib.util.spec_from_file_location("qa_otp_mailbox_script", SCRIPT)
assert SPEC and SPEC.loader
qa_cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa_cli)


def send_otp(port: int, *, to: str, code: str) -> None:
    message = EmailMessage()
    message["From"] = "defensync-qa@localhost"
    message["To"] = to
    message.set_content(f"DefenSync verification code\n\nYour verification code is: {code}\n")
    with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
        smtp.send_message(message)


class QaOtpMailboxCliTests(unittest.TestCase):
    def test_format_masks_by_default_and_prints_only_when_opted_in(self):
        hidden = qa_cli.format_arrival(
            print_codes=False,
            code="654321",
            recipients=("analyst@example.test",),
        )
        shown = qa_cli.format_arrival(
            print_codes=True,
            code="654321",
            recipients=("analyst@example.test",),
        )
        self.assertIn("a***@example.test", hidden)
        self.assertNotIn("654321", hidden)
        self.assertIn("--print-codes", hidden)
        self.assertIn("654321", shown)
        self.assertIn("[QA-ONLY]", shown)
        self.assertEqual(qa_cli.mask_recipient("Alice@Example.TEST"), "a***@example.test")

    def test_parser_requires_explicit_print_codes_flag(self):
        default = qa_cli.build_parser().parse_args([])
        opted = qa_cli.build_parser().parse_args(["--print-codes", "--port", "0"])
        self.assertFalse(default.print_codes)
        self.assertTrue(opted.print_codes)
        self.assertEqual(opted.port, 0)

    def test_synthetic_smtp_delivery_and_opt_in_printing(self):
        mailbox = OTPMailbox(host="127.0.0.1", port=0).start()
        self.addCleanup(mailbox.stop)
        self.assertEqual(mailbox.host, "127.0.0.1")

        since = time.monotonic()
        send_otp(mailbox.port, to="demo.user@example.test", code="112233")
        delivery = qa_cli.consume_delivery(mailbox, since=since, timeout=5.0)
        self.assertIsNotNone(delivery)
        code, recipients = delivery
        self.assertEqual(code, "112233")
        self.assertIn("demo.user@example.test", recipients)

        lines: list[str] = []
        stop_at = time.monotonic() + 2.0

        def should_stop() -> bool:
            return time.monotonic() >= stop_at or len(lines) >= 4

        worker = threading.Thread(
            target=qa_cli.run_mailbox,
            kwargs={
                "mailbox": mailbox,
                "print_codes": False,
                "emit": lines.append,
                "should_stop": should_stop,
                "poll_timeout": 0.1,
            },
            daemon=True,
        )
        worker.start()
        time.sleep(0.05)
        send_otp(mailbox.port, to="second@example.test", code="998877")
        worker.join(timeout=5)
        self.assertTrue(any("OTP received" in line for line in lines))
        self.assertTrue(all("998877" not in line for line in lines))

        since = time.monotonic()
        send_otp(mailbox.port, to="third@example.test", code="445566")
        code, recipients = qa_cli.consume_delivery(mailbox, since=since, timeout=5.0)
        shown = qa_cli.format_arrival(print_codes=True, code=code, recipients=recipients)
        self.assertIn("445566", shown)
        self.assertIn("t***@example.test", shown)


if __name__ == "__main__":
    unittest.main()
