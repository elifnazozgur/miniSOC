import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .incidents import build_incidents, render_incidents
from .ingest import read_events
from .pipeline import DEFAULT_RULES, detect_alerts, load_rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect suspicious activity in SSH logs.")
    parser.add_argument("log", type=Path, help="OpenSSH, CSV or JSON input")
    parser.add_argument("--year", type=int, default=datetime.now(timezone.utc).year)
    parser.add_argument("--db", type=Path, help="SQLite file for persisting alerts")
    parser.add_argument("--html", type=Path, help="Write a ranked incident queue as HTML")
    parser.add_argument("--format", choices=("ssh", "csv", "json"),
                        help="Input format, inferred from the extension by default")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Rule settings YAML")
    args = parser.parse_args()
    if not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999")

    if args.html is not None:
        for other in (args.log, args.db, args.rules):
            if other is not None and (
                args.html.resolve() == other.resolve()
                or (args.html.exists() and other.exists() and args.html.samefile(other))
            ):
                parser.error("--html must differ from the input log, database and rules file")

    input_format = args.format or {".csv": "csv", ".json": "json"}.get(
        args.log.suffix.lower(), "ssh"
    )
    try:
        rules = load_rules(args.rules)
        with args.log.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
            events, ignored = read_events(stream, input_format, args.year)
        alerts = detect_alerts(events, rules)

        if args.db is not None:
            for other in (args.log, args.rules):
                if args.db.resolve() == other.resolve() or (
                    args.db.exists() and args.db.samefile(other)
                ):
                    parser.error("--db must differ from the input and rules files")
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
        if args.html is not None:
            incidents = build_incidents(events, alerts, evidence_minutes=max(
                rules[rule]["window_minutes"] for rule in ("R1", "R2", "R3")
            ))
            args.html.write_text(render_incidents(incidents, len(events), ignored), encoding="utf-8")
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"miniSOC: {error}\n")

    print(json.dumps({"parsed": len(events), "ignored": ignored, "alerts": alerts}, indent=2))


if __name__ == "__main__":
    main()
