from collections import defaultdict, deque
from datetime import timedelta

from .models import SecurityEvent


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect R1: repeated failed SSH logins for one host, IP and account.

    A new alert is raised when a group first reaches the threshold within
    the sliding time window. Events must have comparable timestamps.
    """
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")

    failed_attempts = defaultdict(deque)
    alerts = []
    duration = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.action != "ssh_login" or event.outcome != "failure":
            continue

        key = (event.hostname, event.source_ip, event.username)
        window = failed_attempts[key]
        cutoff = event.timestamp - duration

        while window and window[0] < cutoff:
            window.popleft()

        window.append(event.timestamp)

        if len(window) == threshold:
            alerts.append({
                "rule": "R1",
                "source_ip": event.source_ip,
                "username": event.username,
                "hostname": event.hostname,
                "timestamp": event.timestamp.isoformat(),
                "failed_attempts": len(window),
            })

    return alerts
