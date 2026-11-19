"""Strict parser for a documented subset of OpenSSH syslog messages.

This parser intentionally accepts only password-authentication events.
Unsupported or malformed lines return None rather than fabricating events.
"""

import ipaddress
import re
from datetime import datetime, tzinfo

from .models import SecurityEvent

MAX_LOG_LENGTH = 2048

LOG_PATTERN = re.compile(
    r"^(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<host>[A-Za-z0-9_.-]{1,255}) "
    r"sshd\[\d+\]: "
    r"(?P<outcome>Failed|Accepted) password for "
    r"(?P<invalid>invalid user )?"
    r"(?P<username>\S{1,64}) "
    r"from (?P<ip>\S{1,45}) "
    r"port (?P<port>\d{1,5}) ssh2$"
)


def parse_ssh_log(
    line: str, *, year: int, source_timezone: tzinfo
) -> SecurityEvent | None:
    """Parse one supported log line; return None for unsupported/invalid records.

    Syslog timestamps omit year and timezone, so both are explicit inputs.
    """
    if not isinstance(line, str):
        raise TypeError("line must be str")
    if source_timezone is None or source_timezone.utcoffset(None) is None:
        raise ValueError("source_timezone must be a fixed-offset tzinfo")
    if not 1 <= year <= 9999:
        raise ValueError("year is outside supported range")
    if len(line) > MAX_LOG_LENGTH:
        return None

    line = line.rstrip("\r\n")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in line):
        return None

    match = LOG_PATTERN.fullmatch(line)
    if match is None:
        return None

    fields = match.groupdict()
    try:
        timestamp = datetime.strptime(
            f"{year} {fields['date']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=source_timezone)
        address = str(ipaddress.ip_address(fields["ip"]))
        port = int(fields["port"])
        if not 1 <= port <= 65535:
            return None
    except (ValueError, OverflowError):
        return None

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=address,
        source_port=port,
        username=fields["username"],
        user_exists=False if fields["invalid"] else None,
        action="ssh_login",
        outcome="success" if fields["outcome"] == "Accepted" else "failure",
        hostname=fields["host"],
    )
