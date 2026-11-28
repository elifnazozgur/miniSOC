from io import StringIO
import json
import unittest

from minisoc.ingest import read_events
from minisoc.pipeline import DEFAULT_RULES, detect_alerts, load_rules


class TestInputs(unittest.TestCase):
    def test_csv_and_json_normalize_the_same_record(self):
        csv = (
            "timestamp,source_ip,source_port,username,hostname,outcome,user_exists\n"
            "2026-12-01T12:00:00+03:00,192.0.2.1,1234,alice,server,success,true\n"
        )
        data = [{
            "timestamp": "2026-12-01T09:00:00Z",
            "source_ip": "192.0.2.1", "source_port": 1234,
            "username": "alice", "hostname": "server", "outcome": "success",
            "user_exists": True,
        }]
        expected = read_events(StringIO(csv), "csv", 2026)
        self.assertEqual(expected, read_events(StringIO(json.dumps(data)), "json", 2026))
        self.assertEqual(len(expected[0]), 1)

    def test_new_source_needs_prior_success_for_same_host_and_account(self):
        log = StringIO("\n".join(
            f"Dec  1 09:00:0{i} {host} sshd[1]: {result} password for {user} "
            f"from 192.0.2.{ip} port 1234 ssh2"
            for i, (host, result, user, ip) in enumerate([
                ("a", "Failed", "alice", 1), ("a", "Accepted", "alice", 2),
                ("b", "Accepted", "alice", 3), ("a", "Accepted", "bob", 3),
                ("a", "Accepted", "alice", 3), ("a", "Accepted", "alice", 3),
            ])
        ))
        events, ignored = read_events(log, "ssh", 2026)
        self.assertEqual(ignored, 0)
        self.assertEqual(
            [(a["rule"], a["source_ip"]) for a in detect_alerts(events, load_rules(DEFAULT_RULES))],
            [("R5", "192.0.2.3")],
        )

    def test_invalid_user_burst_counts_distinct_explicitly_invalid_names(self):
        for names, expected in [(["a", "b", "c", "d", "e"], True),
                                (["a", "a", "b", "c", "d"], False)]:
            with self.subTest(names=names):
                log = StringIO("\n".join(
                    f"Dec  1 09:00:0{i} host sshd[1]: Failed password for "
                    f"{'invalid user ' if user != 'known' else ''}{user} "
                    "from 192.0.2.1 port 1234 ssh2"
                    for i, user in enumerate([*names, "known"])
                ))
                events, ignored = read_events(log, "ssh", 2026)
                self.assertEqual(ignored, 0)
                alerts = detect_alerts(events, load_rules(DEFAULT_RULES))
                self.assertEqual(any(a["rule"] == "R3" for a in alerts), expected)
