
import ipaddress
import re
from datetime import datetime, timezone

from .models import SecurityEvent


def parse_ssh_log(line: str, year: int = 2026):
    pattern = (
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(\S+) sshd\[\d+\]: "
        r"(Failed|Accepted) password for "
        r"(invalid user )?"
        r"(\S+) from "
        r"(\S+) port (\d+) ssh2$"
    )

    match = re.fullmatch(pattern, line)

    if match is None:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year} {match.group(1)}",
            "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)

        hostname = match.group(2)
        outcome = (
            "failure"
            if match.group(3) == "Failed"
            else "success"
        )
        user_exists = (
            False if match.group(4) else None
        )
        username = match.group(5)
        source_ip = str(
            ipaddress.ip_address(match.group(6))
        )
        source_port = int(match.group(7))

        if not 1 <= source_port <= 65535:
            return None

        return SecurityEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            user_exists=user_exists,
            action="ssh_login",
            outcome=outcome,
            hostname=hostname
        )

    except ValueError:
        return None
