import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class TestIncidentDemo(unittest.TestCase):
    def test_demo_queue_and_storage(self):
        root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            report = Path(tmp) / "incidents.html"
            database = Path(tmp) / "alerts.sqlite3"
            command = [
                sys.executable, "-m", "minisoc", "demo/auth.log.sample",
                "--year", "2026", "--db", str(database), "--html", str(report),
            ]
            for _ in range(2):
                subprocess.run(command, cwd=root, env={**os.environ, "PYTHONPATH": "src"},
                               check=True, capture_output=True)
            html = report.read_text(encoding="utf-8")
            self.assertIn("25 parsed · 0 ignored · 2 incidents", html)
            self.assertIn("58.5 / 100 · medium", html)
            self.assertIn("7.5 / 100 · low", html)
            self.assertLess(html.index("192.0.2.10"), html.index("192.0.2.20"))
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 4)
            finally:
                connection.close()
