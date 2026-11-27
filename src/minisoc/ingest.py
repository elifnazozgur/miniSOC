import csv
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from typing import TextIO

from .models import SecurityEvent
from .parser import parse_ssh_log


def parse_record(record: dict) -> SecurityEvent:
    if not isinstance(record, dict):
        raise ValueError("Expected an event object")

    timestamp = datetime.fromisoformat(
        record["timestamp"].replace("Z", "+00:00")
    )
    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    source_ip = str(ip_address(record["source_ip"]))
    port = record["source_port"]
    if type(port) is not int and not (isinstance(port, str) and port.isdecimal()):
        raise ValueError("Invalid source port")
    source_port = int(port)
    if not 1 <= source_port <= 65535:
        raise ValueError("Invalid source port")

    username = record["username"]
    hostname = record["hostname"]
    if not all(isinstance(value, str) and value.strip() for value in (username, hostname)):
        raise ValueError("Expected a username and hostname")

    outcome = record["outcome"]
    if outcome not in ("success", "failure") or record.get("action", "ssh_login") != "ssh_login":
        raise ValueError("Expected an SSH login outcome")

    user_exists = record.get("user_exists")
    if isinstance(user_exists, str):
        user_exists = {"true": True, "false": False, "": None}[user_exists.lower()]
    elif user_exists is not None and type(user_exists) is not bool:
        raise ValueError("Expected a boolean user_exists")

    return SecurityEvent(
        timestamp.astimezone(timezone.utc), source_ip, source_port, username,
        user_exists, "ssh_login", outcome, hostname,
    )


def read_events(
    stream: TextIO, input_format: str, year: int
) -> tuple[list[SecurityEvent], int]:
    events = []
    ignored = 0

    if input_format == "csv":
        records = csv.DictReader(stream)
    elif input_format == "json":
        records = json.load(stream)
        if not isinstance(records, list):
            raise ValueError("JSON must contain an array of events")
    else:
        for line in stream:
            event = parse_ssh_log(line.rstrip("\r\n"), year=year)
            if event is None:
                ignored += 1
            else:
                events.append(event)
        return events, ignored

    for record in records:
        try:
            events.append(parse_record(record))
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
            ignored += 1

    return events, ignored