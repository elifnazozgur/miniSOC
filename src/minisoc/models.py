
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    source_port: int
    username: str
    user_exists: bool | None
    action: str
    outcome: str
    hostname: str
