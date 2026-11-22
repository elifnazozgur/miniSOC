import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .detection import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_brute_force,
)
from .parser import parse_ssh_log


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect suspicious activity in SSH logs.")
    parser.add_argument("log", type=Path, help="OpenSSH auth.log file")
    parser.add_argument("--year", type=int, default=datetime.now(timezone.utc).year)
    parser.add_argument("--db", type=Path, help="SQLite file for persisting alerts")
    args = parser.parse_args()
    if not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999")

    events = []
    ignored = 0
    try:
        with args.log.open(encoding="utf-8", errors="replace") as lines:
            for line in lines:
                event = parse_ssh_log(line.rstrip("\r\n"), year=args.year)
                if event is None:
                    ignored += 1
                else:
                    events.append(event)

        brute_force = detect_brute_force(events)
        alerts = (
            brute_force
            + detect_password_spraying(events)
            + detect_success_after_brute_force(events, brute_force)
        )
        alerts.sort(key=lambda alert: (alert["timestamp"], alert["rule"]))

        if args.db is not None:
            if args.db.resolve() == args.log.resolve() or (
                args.db.exists() and args.db.samefile(args.log)
            ):
                parser.error("--db and the input log must be different files")
            with closing(sqlite3.connect(args.db)) as connection, connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        rule TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        username TEXT NOT NULL,
                        details TEXT NOT NULL,
                        PRIMARY KEY (rule, timestamp, hostname, source_ip, username)
                    )
                """)
                connection.executemany("""
                    INSERT INTO alerts (rule, timestamp, hostname, source_ip, username, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (rule, timestamp, hostname, source_ip, username)
                    DO UPDATE SET details = excluded.details
                """, (
                    (
                        alert["rule"], alert["timestamp"], alert["hostname"],
                        alert["source_ip"], alert.get("username", ""),
                        json.dumps(alert, sort_keys=True),
                    )
                    for alert in alerts
                ))
    except (OSError, sqlite3.Error) as error:
        parser.exit(1, f"miniSOC: {error}\n")

    print(json.dumps({"parsed": len(events), "ignored": ignored, "alerts": alerts}, indent=2))


if __name__ == "__main__":
    main()
