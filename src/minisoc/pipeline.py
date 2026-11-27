from pathlib import Path

import yaml

from .detection import (
    detect_brute_force,
    detect_invalid_user_burst,
    detect_new_source,
    detect_password_spraying,
    detect_success_after_brute_force,
)
from .models import SecurityEvent

DEFAULT_RULES = Path(__file__).with_name("rules.yaml")
RULE_FIELDS = {
    "R1": {"threshold", "window_minutes"},
    "R2": {"threshold", "window_minutes"},
    "R3": {"threshold", "window_minutes"},
    "R4": {"window_minutes"},
    "R5": {"minimum_known_sources"},
}


def load_rules(path: Path) -> dict:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid rule YAML: {error}") from error

    if not isinstance(document, dict) or document.keys() != RULE_FIELDS.keys():
        raise ValueError("Rule YAML must define R1, R2, R3, R4 and R5")

    settings = {}
    for rule, fields in RULE_FIELDS.items():
        entry = document[rule]
        options = entry.get("detection") if isinstance(entry, dict) else None
        if not isinstance(options, dict) or options.keys() != fields:
            raise ValueError(
                f"{rule} detection must define {', '.join(sorted(fields))}"
            )
        if any(type(value) is not int or not 1 <= value <= 10000
               for value in options.values()):
            raise ValueError(
                f"{rule} detection settings must be integers from 1 to 10000"
            )
        settings[rule] = options

    return settings


def detect_alerts(events: list[SecurityEvent], rules: dict) -> list[dict]:
    brute_force = detect_brute_force(events, **rules["R1"])
    alerts = (
        brute_force
        + detect_password_spraying(events, **rules["R2"])
        + detect_invalid_user_burst(events, **rules["R3"])
        + detect_success_after_brute_force(events, brute_force, **rules["R4"])
        + detect_new_source(events, **rules["R5"])
    )
    return sorted(alerts, key=lambda alert: (alert["timestamp"], alert["rule"]))