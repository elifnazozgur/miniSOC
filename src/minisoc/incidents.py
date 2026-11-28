from collections import defaultdict
from datetime import datetime, timedelta
from html import escape

from .models import SecurityEvent


def build_incidents(
    events: list[SecurityEvent], alerts: list[dict], evidence_minutes: int = 10
) -> list[dict]:
    """Group alerts on one host/source within 60 minutes of the first alert."""
    alerts_by_source = defaultdict(list)
    for alert in alerts:
        alerts_by_source[alert["hostname"], alert["source_ip"]].append(alert)

    failures_by_source = defaultdict(list)
    for event in events:
        if event.action == "ssh_login" and event.outcome == "failure":
            failures_by_source[event.hostname, event.source_ip].append(event)

    incidents = []
    for (hostname, source_ip), source_alerts in alerts_by_source.items():
        groups = []
        for alert in sorted(source_alerts, key=lambda item: item["timestamp"]):
            timestamp = datetime.fromisoformat(alert["timestamp"])
            if not groups or timestamp - groups[-1][0] > timedelta(hours=1):
                groups.append((timestamp, []))
            groups[-1][1].append(alert)

        for start, timeline in groups:
            end = datetime.fromisoformat(timeline[-1]["timestamp"])
            # Recover threshold evidence preceding the first alert.
            evidence_start = start - timedelta(minutes=evidence_minutes)
            failures = [
                event for event in failures_by_source[hostname, source_ip]
                if evidence_start <= event.timestamp <= end
            ]
            failed_accounts = {event.username for event in failures}
            accounts = sorted(failed_accounts | {
                alert["username"] for alert in timeline if "username" in alert
            })
            factors = {
                "Failure volume": round(25 * min(1, len(failures) / 50), 2),
                "Account breadth": round(20 * min(1, len(failed_accounts) / 20), 2),
                "Success after brute force": 30 if any(
                    alert["rule"] == "R4" for alert in timeline
                ) else 0,
                "Sensitive account name": 15 if {"admin", "root"}.intersection(accounts) else 0,
                "New source for account": 10 if any(
                    alert["rule"] == "R5" for alert in timeline
                ) else 0,
            }
            score = round(sum(factors.values()), 2)
            severity = "high" if score >= 70 else "medium" if score >= 40 else "low"
            incidents.append({
                "hostname": hostname, "source_ip": source_ip,
                "start": start.isoformat(), "end": end.isoformat(),
                "failed_attempts": len(failures), "accounts": accounts,
                "score": score, "severity": severity, "factors": factors,
                "timeline": timeline,
            })
    return sorted(incidents, key=lambda item: (-item["score"], item["start"]))


def render_incidents(incidents: list[dict], parsed: int, ignored: int) -> str:
    cards = []
    for incident in incidents:
        factors = "".join(
            f"<li>{escape(label)} +{points:g}</li>"
            for label, points in incident["factors"].items()
        )
        timeline = "".join(
            f'<li><time>{escape(alert["timestamp"])}</time> '
            f'{escape(alert["rule"])} {escape(alert.get("username", "Multiple accounts"))}</li>'
            for alert in incident["timeline"]
        )
        cards.append(f"""
        <article data-severity="{incident["severity"]}">
          <h2>{escape(incident["hostname"])} · {escape(incident["source_ip"])}</h2>
          <p><strong>{incident["score"]:g} / 100 · {incident["severity"]}</strong></p>
          <p>{incident["failed_attempts"]} failures · {len(incident["accounts"])} accounts</p>
          <p>{escape(", ".join(incident["accounts"]))}</p>
          <div class="details">
            <section><h3>Score breakdown</h3><ul>{factors}</ul></section>
            <section><h3>Alert timeline</h3><ol>{timeline}</ol></section>
          </div>
        </article>""")
    body = "".join(cards) or "<p>No incidents in this log.</p>"
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MiniSOC Incident Queue</title>
<style>
body {{ font: 16px/1.55 system-ui,sans-serif; background:#edf2f6; color:#102637; margin:0; }}
main {{ max-width: 920px; padding: 2rem 1rem; margin:auto; }}
article {{ background:white; border-left:5px solid #137773; margin:1rem 0; padding:1rem 1.4rem; }}
h1,h2,h3 {{ line-height:1.2; }}
strong {{ color:#08615e; }}
.details {{ display:flex; flex-wrap:wrap; gap:1rem 2rem; }}
time {{ font-family:monospace; }}
label {{ display:inline-block; margin:0 1rem 0.5rem 0; }}
input,select {{ font:inherit; padding:0.3rem; }}
[hidden] {{ display:none; }}
</style>
<main><h1>MiniSOC Incident Queue</h1>
<p>{parsed} parsed · {ignored} ignored · {len(incidents)} incidents</p>
<label>Search incidents <input type="search" id="query" placeholder="IP, account or rule"></label>
<label>Severity <select id="severity">
<option value="">All</option><option>high</option><option>medium</option><option>low</option>
</select></label>
<p id="no-match" hidden>No incidents match these filters.</p>
{body}</main>
<script>
const query = document.getElementById("query");
const severity = document.getElementById("severity");
const cards = Array.from(document.querySelectorAll("article"));
function filterQueue() {{
  const term = query.value.trim().toLowerCase();
  for (const card of cards) {{
    const match = card.textContent.toLowerCase().includes(term);
    card.hidden = !match || Boolean(severity.value && card.dataset.severity !== severity.value);
  }}
  document.getElementById("no-match").hidden = cards.length === 0 || cards.some(card => !card.hidden);
}}
query.addEventListener("input", filterQueue);
severity.addEventListener("change", filterQueue);
</script></html>
"""
