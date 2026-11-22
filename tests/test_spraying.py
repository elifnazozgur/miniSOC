
import unittest
from datetime import datetime, timedelta, timezone

from minisoc.models import SecurityEvent
from minisoc.detection import detect_password_spraying


class TestPasswordSpraying(unittest.TestCase):

    def test_five_distinct_users_trigger_alert(self):
        start = datetime(
            2026, 11, 22, 10, 0,
            tzinfo=timezone.utc
        )

        users = ["admin", "root", "elif", "guest", "test"]
        events = []

        for i, username in enumerate(users):
            events.append(SecurityEvent(
                timestamp=start + timedelta(minutes=i),
                source_ip="192.168.1.50",
                source_port=50000 + i,
                username=username,
                user_exists=None,
                action="ssh_login",
                outcome="failure",
                hostname="server"
            ))

        alerts = detect_password_spraying(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "R2")
        self.assertEqual(alerts[0]["distinct_users"], 5)


    def test_repeated_users_do_not_trigger_alert(self):
        start = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
        users = [
            "admin", "admin", "root", "root",
            "elif", "elif", "guest", "guest",
            "admin", "root"
        ]

        events = [
            SecurityEvent(
                timestamp=start + timedelta(seconds=i * 30),
                source_ip="192.168.1.50",
                source_port=50000 + i,
                username=username,
                user_exists=None,
                action="ssh_login",
                outcome="failure",
                hostname="server"
            )
            for i, username in enumerate(users)
        ]

        self.assertEqual(len(detect_password_spraying(events)), 0)

    def test_users_outside_window_do_not_trigger(self):
        start = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
        users = ["admin", "root", "elif", "guest", "test"]

        events = [
            SecurityEvent(
                timestamp=start + timedelta(minutes=i * 3),
                source_ip="192.168.1.50",
                source_port=50000 + i,
                username=username,
                user_exists=None,
                action="ssh_login",
                outcome="failure",
                hostname="server"
            )
            for i, username in enumerate(users)
        ]

        self.assertEqual(len(detect_password_spraying(events)), 0)

    def test_different_ips_not_combined(self):
        start = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
        users = ["admin", "root", "elif", "guest", "test"]

        events = [
            SecurityEvent(
                timestamp=start + timedelta(minutes=i),
                source_ip=(
                    "192.168.1.50" if i < 3
                    else "192.168.1.51"
                ),
                source_port=50000 + i,
                username=username,
                user_exists=None,
                action="ssh_login",
                outcome="failure",
                hostname="server"
            )
            for i, username in enumerate(users)
        ]

        self.assertEqual(len(detect_password_spraying(events)), 0)


if __name__ == "__main__":
    unittest.main()
