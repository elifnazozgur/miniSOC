
import unittest

from minisoc.parser import parse_ssh_log
from minisoc.detection import (
    detect_brute_force,
    detect_password_spraying,
)


class TestIntegration(unittest.TestCase):

    def test_ssh_logs_generate_r1_and_r2_alerts(self):
        usernames = [
            "admin", "root", "elif", "guest", "test"
        ]

        logs = []

        for i in range(10):
            minute = i // 2
            second = (i % 2) * 20

            logs.append(
                f"Nov 22 10:{minute:02d}:{second:02d} "
                f"server sshd[{1000 + i}]: "
                f"Failed password for "
                f"{usernames[i % 5]} from "
                f"192.168.1.50 port {50000 + i} ssh2"
            )

        events = [
            parse_ssh_log(line, year=2026)
            for line in logs
        ]

        self.assertTrue(
            all(event is not None for event in events)
        )

        r1_alerts = detect_brute_force(events)
        r2_alerts = detect_password_spraying(events)

        self.assertEqual(len(r1_alerts), 0)
        self.assertEqual(len(r2_alerts), 1)
        self.assertEqual(r2_alerts[0]["rule"], "R2")


if __name__ == "__main__":
    unittest.main()
