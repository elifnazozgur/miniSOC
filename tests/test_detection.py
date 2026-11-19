import unittest
from datetime import datetime, timedelta, timezone

from minisoc.detection import detect_brute_force
from minisoc.models import SecurityEvent


def sample(n, *, ip="10.0.0.1", username="admin", outcome="failure"):
    return SecurityEvent(
        timestamp=datetime(2026, 11, 13, tzinfo=timezone.utc) + timedelta(seconds=n * 20),
        source_ip=ip,
        source_port=50000,
        username=username,
        user_exists=None,
        action="ssh_login",
        outcome=outcome,
        hostname="test-host",
    )


class DetectionTests(unittest.TestCase):
    def test_threshold_fires_once(self):
        self.assertEqual(len(detect_brute_force([sample(i) for i in range(10)])), 1)

    def test_below_threshold_does_not_fire(self):
        self.assertEqual(detect_brute_force([sample(i) for i in range(9)]), [])

    def test_separate_sources_not_combined(self):
        events = [sample(i, ip="10.0.0.1") for i in range(5)]
        events += [sample(i, ip="10.0.0.2") for i in range(5)]
        self.assertEqual(detect_brute_force(events), [])

    def test_separate_users_not_combined(self):
        events = [sample(i, username="admin") for i in range(5)]
        events += [sample(i, username="elif") for i in range(5)]
        self.assertEqual(detect_brute_force(events), [])

    def test_success_does_not_count_as_failure(self):
        events = [sample(i) for i in range(9)] + [sample(9, outcome="success")]
        self.assertEqual(detect_brute_force(events), [])

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            detect_brute_force([], threshold=0)


if __name__ == "__main__":
    unittest.main()
