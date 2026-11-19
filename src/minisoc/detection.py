"""Initial transparent, deterministic brute-force detection rule (R1)."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import SecurityEvent


@dataclass(frozen=True)
class Alert:
    rule_id: str
    timestamp: str
    source_ip: str
    username: str
    failed_count: int


def detect_brute_force(
    events: Iterable[SecurityEvent], *, threshold: int = 10, window_minutes: int = 5
) -> list[Alert]:
    """R1: alert once per IP/account burst of >=threshold failures within window.

    Events are ordered by event time. This is an offline batch detector, not a
    real-time streaming engine. Keying by IP AND account prevents unrelated
    accounts from being merged into a single brute-force series.
    """
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")
    windows: dict[tuple[str, str], deque] = defaultdict(deque)
    alerted: set[tuple[str, str]] = set()
    result: list[Alert] = []
    delta = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.source_ip, event.username)
        queue = windows[key]
        while queue and event.timestamp - queue[0] > delta:
            queue.popleft()
        if event.action != "ssh_login" or event.outcome != "failure":
            continue
        queue.append(event.timestamp)
        if len(queue) >= threshold and key not in alerted:
            result.append(
                Alert(
                    rule_id="R1",
                    timestamp=event.timestamp.isoformat(),
                    source_ip=event.source_ip,
                    username=event.username,
                    failed_count=len(queue),
                )
            )
            alerted.add(key)
        if len(queue) < threshold:
            alerted.discard(key)
    return result
