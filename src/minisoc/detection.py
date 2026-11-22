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

def detect_password_spraying(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 10
):

    if threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be positive")

    attempts = defaultdict(deque)
    alerts = []

    events = sorted(events, key=lambda event: event.timestamp)

    for event in events:
        if event.action != "ssh_login":
            continue

        if event.outcome != "failure":
            continue

        key = (event.hostname, event.source_ip)
        window = attempts[key]

        cutoff = event.timestamp - timedelta(minutes=window_minutes)

        while window and window[0][0] < cutoff:
            window.popleft()

        previous_users = {
            username for _, username in window
        }

        window.append((event.timestamp, event.username))

        unique_users = {
            username for _, username in window
        }

        if (
            len(previous_users) < threshold
            and len(unique_users) >= threshold
        ):
            alerts.append({
                "rule": "R2",
                "source_ip": event.source_ip,
                "hostname": event.hostname,
                "timestamp": event.timestamp.isoformat(),
                "distinct_users": len(unique_users),
            })

    return alerts



    return alerts
