# miniSOC
Lightweight SSH security monitoring, threat detection, incident correlation, and risk scoring platform.

## Run the SSH log detector

From the repository root with Python 3.10 or newer:

```sh
PYTHONPATH=src python -m minisoc path/to/auth.log --year 2026 --db alerts.sqlite3
PYTHONPATH=src python -m unittest discover -s tests -v
```

In PowerShell, first run `$env:PYTHONPATH = "src"`, then run the Python
commands without the `PYTHONPATH=src` prefix.

The command outputs JSON with parsed and ignored line counts and ordered
alerts. Omit `--db` for JSON output alone. The SQLite `alerts` table
keeps one row per rule, timestamp, host, source IP and username (where
applicable). Running the same file again updates matching rows.

R1 flags repeated failures for one account. R2 flags failures across
multiple accounts. R3 flags the first successful password login for the
same host, IP and account strictly after an R1 alert and within ten
minutes of it. An R3 alert indicates a login worth reviewing.

The parser expects classic OpenSSH password log lines and interprets
timestamps as UTC. Use one input year per file and pass it explicitly
for historical logs. Analyses use the records in the input file.
