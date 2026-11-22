from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class TestCLI(unittest.TestCase):
    def test_ssh_log_to_alerts_and_idempotent_storage(self):
        with TemporaryDirectory() as folder:
            log = Path(folder) / "auth.log"
            db = Path(folder) / "alerts.sqlite3"
            lines = [
                f"Nov 22 12:00:{second:02} server sshd[10]: Failed password "
                "for alice from 192.0.2.1 port 12345 ssh2"
                for second in range(10)
            ]
            lines.extend(
                f"Nov 22 12:00:{second:02} server sshd[10]: Accepted password "
                f"for {user} from {ip} port 12345 ssh2"
                for second, user, ip in [
                    (9, "alice", "192.0.2.1"),
                    (10, "bob", "192.0.2.1"),
                    (11, "alice", "192.0.2.2"),
                    (12, "alice", "192.0.2.1"),
                    (13, "alice", "192.0.2.1"),
                ]
            )
            lines.append("unrelated log entry")
            log.write_text("\n".join(lines), encoding="utf-8")
            command = [
                sys.executable, "-m", "minisoc", str(log),
                "--year", "2026", "--db", str(db),
            ]
            for _ in range(2):
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                output = json.loads(result.stdout)
                self.assertEqual(output["parsed"], 15)
                self.assertEqual(output["ignored"], 1)
                self.assertEqual([alert["rule"] for alert in output["alerts"]], ["R1", "R3"])
                self.assertEqual(output["alerts"][1]["timestamp"], "2026-11-22T12:00:12+00:00")

            with closing(sqlite3.connect(db)) as connection:
                rows = connection.execute("SELECT rule FROM alerts ORDER BY rule").fetchall()
            self.assertEqual(rows, [("R1",), ("R3",)])
