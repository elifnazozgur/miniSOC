import unittest
from datetime import datetime, timedelta, timezone

from minisoc.models import SecurityEvent
from minisoc.detection import detect_brute_force


class TestBruteForce(unittest.TestCase):
    def create_events(
        self,
        count=10,
        interval_seconds=20,
        source_ip="192.168.1.50",
        username="admin",
        outcome="failure",
        hostname="server",
    ):
        start = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
        events = []

        for i in range(count):
            events.append(
                SecurityEvent(
                    timestamp=start + timedelta(seconds=i * interval_seconds),
                    source_ip=source_ip,
                    source_port=50000 + i,
                    username=username,
                    user_exists=None,
                    action="ssh_login",
                    outcome=outcome,
                    hostname=hostname,
                )
            )

        return events

    def test_fast_attempts_trigger_alert(self):
        events = self.create_events(count=10, interval_seconds=20)
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "R1")

    def test_slow_attempts_do_not_trigger(self):
        events = self.create_events(count=10, interval_seconds=60)
        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_below_threshold(self):
        events = self.create_events(count=9)
        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_different_ips_not_combined(self):
        events = (
            self.create_events(count=5, source_ip="192.168.1.50")
            + self.create_events(count=5, source_ip="192.168.1.51")
        )
        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_different_users_not_combined(self):
        events = (
            self.create_events(count=5, username="admin")
            + self.create_events(count=5, username="elif")
        )
        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_successful_logins_not_counted(self):
        events = (
            self.create_events(count=9)
            + self.create_events(count=1, outcome="success")
        )
        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_different_hosts_not_combined(self):
        events = (
            self.create_events(count=5, hostname="server1")
            + self.create_events(count=5, hostname="server2")
        )
        self.assertEqual(len(detect_brute_force(events)), 0)


if __name__ == "__main__":
    unittest.main()
