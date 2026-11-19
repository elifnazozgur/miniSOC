import unittest
from datetime import timezone

from minisoc.parser import parse_ssh_log


def parse(line):
    return parse_ssh_log(line, year=2026, source_timezone=timezone.utc)


class TestSSHParser(unittest.TestCase):
    def test_invalid_user_failure(self):
        event = parse(
            "Nov 13 14:32:18 server sshd[1234]: Failed password for invalid user "
            "admin from 192.168.1.50 port 53122 ssh2"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.outcome, "failure")
        self.assertIs(event.user_exists, False)

    def test_success(self):
        event = parse(
            "Nov 13 15:10:42 server sshd[5678]: Accepted password for "
            "elif from 10.0.0.25 port 48291 ssh2"
        )
        self.assertEqual(event.outcome, "success")
        self.assertIsNone(event.user_exists)

    def test_reject_invalid_ip(self):
        self.assertIsNone(parse(
            "Nov 13 14:32:18 server sshd[1234]: Failed password for admin "
            "from 999.999.999.999 port 53122 ssh2"
        ))

    def test_reject_invalid_port(self):
        self.assertIsNone(parse(
            "Nov 13 14:32:18 server sshd[1234]: Failed password for admin "
            "from 192.168.1.50 port 99999 ssh2"
        ))

    def test_reject_oversized(self):
        self.assertIsNone(parse("X" * 10000))

    def test_reject_unrecognized(self):
        self.assertIsNone(parse("not an SSH login record"))

    def test_reject_embedded_control_character(self):
        self.assertIsNone(parse(
            "Nov 13 14:32:18 server sshd[1234]: Failed password for "
            "admin from 192.168.1.50 port 53122 ssh2\x00"
        ))


if __name__ == "__main__":
    unittest.main()
