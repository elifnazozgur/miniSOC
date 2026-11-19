"""Normalized authentication events used by MiniSOC."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

Outcome = Literal["success", "failure"]


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    source_port: int
    username: str
    user_exists: bool | None
    action: str
    outcome: Outcome
    hostname: str
