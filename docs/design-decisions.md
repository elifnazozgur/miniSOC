# MiniSOC — Design Decisions

## ADR-001: Normalize authentication logs before detection
**Status:** Accepted

Raw logs are untrusted text with inconsistent fields. A parser converts a narrowly
defined OpenSSH password-authentication subset into immutable SecurityEvent objects.
Other log sources will need their own parser but can reuse the same detection logic.

**Security reasoning:** Strict input size and syntax checks, IP/port validation,
and no execution of log contents. Unsupported events return None. In production
we must also count rejected lines rather than silently ignoring them.

**Known limitations:** OpenSSH logs do not reveal passwords. Syslog may not carry
year or timezone; ingestion must supply them. This parser handles only one
documented OpenSSH message family, not every SSH authentication method.

## ADR-002: Deterministic, auditable initial detection
**Status:** Accepted

R1 groups failed logins by (source IP, username) and applies a five-minute
window with ten failures as an initial threshold. Rules operate on normalized
events, not raw strings.

**Security reasoning:** Explainable alerts and deterministic behavior make
false positives measurable. Thresholds require tuning using a development
dataset, never the held-out test split.

**Known limitations:** R1 can miss distributed or low-and-slow attacks. The
current detector processes events in batch; correlation and risk scoring are
separate future stages. Alert output is a threshold signal, not proof of compromise.
