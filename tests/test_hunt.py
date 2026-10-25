import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hunt import LogonEvent, hunt, parse_time  # noqa: E402

T0 = datetime(2026, 8, 14, tzinfo=timezone.utc)


def failures(ip, count, accounts=("admin",), step_seconds=10, start=0):
    return [
        LogonEvent(T0 + timedelta(seconds=start + i * step_seconds), "vm-01", "LogonFailed",
                   accounts[i % len(accounts)], ip)
        for i in range(count)
    ]


class HuntTests(unittest.TestCase):
    def test_bruteforce_detected(self):
        findings = hunt(failures("192.0.2.1", 12))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection, "Brute force")

    def test_below_threshold_ignored(self):
        self.assertEqual(hunt(failures("192.0.2.1", 5)), [])

    def test_slow_failures_outside_window_ignored(self):
        # 12 failures, 2 minutes apart -> never 10 inside a 5-minute window
        self.assertEqual(hunt(failures("192.0.2.1", 12, step_seconds=120)), [])

    def test_success_after_bruteforce_is_high(self):
        events = failures("192.0.2.1", 12)
        events.append(LogonEvent(T0 + timedelta(minutes=10), "vm-01", "LogonSuccess", "admin", "192.0.2.1"))
        findings = hunt(events)
        self.assertEqual(findings[0].severity, "High")

    def test_password_spray_detected(self):
        accounts = ("a", "b", "c", "d", "e", "f")
        findings = hunt(failures("192.0.2.9", 6, accounts=accounts, step_seconds=300))
        self.assertEqual(findings[0].detection, "Password spraying")

    def test_parse_defender_portal_time(self):
        self.assertEqual(parse_time("8/14/2026, 3:12:45.123 AM").hour, 3)


if __name__ == "__main__":
    unittest.main()
