from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import NormalizedEvent


IP_TO_HOST = {
    "10.10.20.10": "guest1",
    "10.10.30.10": "admin1",
    "10.10.40.10": "server1",
}

FAILED_PASSWORD = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<src>[0-9.]+) port (?P<src_port>\d+)"
)
PENALTY_DROP = re.compile(
    r"drop connection #\d+ from \[(?P<src>[0-9.]+)\]:(?P<src_port>\d+) "
    r"on \[(?P<dst>[0-9.]+)\]:(?P<dst_port>\d+) penalty: failed authentication"
)
FIREWALL_COUNTER = re.compile(
    r"Firewall counter: (?P<before>\d+) -> (?P<after>\d+) \(delta: (?P<delta>\d+)\)"
)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _event_id(source_type: str, raw_line: str) -> str:
    return f"evt_{_sha256(f'{source_type}:{raw_line}')[:20]}"


def _utc_from_epoch(value: Any) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _utc_from_iso(value: Any) -> str | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value))
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json_lines(path: Path, warnings: list[str]) -> Iterator[tuple[int, str, dict[str, Any]]]:
    if not path.exists():
        warnings.append(f"Missing input file: {path}")
        return

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\n")
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                warnings.append(f"{path}:{line_number}: invalid JSON: {exc.msg}")
                continue
            yield line_number, raw_line, record


def normalize_zeek(path: Path, warnings: list[str]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line_number, raw_line, record in _read_json_lines(path, warnings):
        source_ip = record.get("id.orig_h")
        destination_ip = record.get("id.resp_h")
        events.append(
            NormalizedEvent(
                event_id=_event_id("zeek_conn", raw_line),
                observed_at=_utc_from_epoch(record.get("ts")),
                source_type="zeek_conn",
                event_type="network_connection",
                source_host=IP_TO_HOST.get(source_ip),
                source_ip=source_ip,
                source_port=record.get("id.orig_p"),
                destination_host=IP_TO_HOST.get(destination_ip),
                destination_ip=destination_ip,
                destination_port=record.get("id.resp_p"),
                protocol=str(record.get("proto", "")).lower() or None,
                action="observed",
                outcome=str(record.get("conn_state", "unknown")),
                message="Zeek network connection",
                raw_reference=f"{path.name}:{line_number}",
                raw_sha256=_sha256(raw_line),
                attributes={
                    "zeek_uid": record.get("uid"),
                    "service": record.get("service"),
                    "conn_state": record.get("conn_state"),
                    "orig_pkts": record.get("orig_pkts"),
                    "resp_pkts": record.get("resp_pkts"),
                    "orig_ip_bytes": record.get("orig_ip_bytes"),
                    "resp_ip_bytes": record.get("resp_ip_bytes"),
                },
            )
        )
    return events


def normalize_suricata(path: Path, warnings: list[str]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line_number, raw_line, record in _read_json_lines(path, warnings):
        if record.get("event_type") != "alert" or not record.get("alert"):
            continue
        alert = record["alert"]
        source_ip = record.get("src_ip")
        destination_ip = record.get("dest_ip")
        events.append(
            NormalizedEvent(
                event_id=_event_id("suricata_alert", raw_line),
                observed_at=_utc_from_iso(record.get("timestamp")),
                source_type="suricata_alert",
                event_type="ids_alert",
                source_host=IP_TO_HOST.get(source_ip),
                source_ip=source_ip,
                source_port=record.get("src_port"),
                destination_host=IP_TO_HOST.get(destination_ip),
                destination_ip=destination_ip,
                destination_port=record.get("dest_port"),
                protocol=str(record.get("proto", "")).lower() or None,
                action="alerted",
                outcome="observed",
                message=str(alert.get("signature", "Suricata alert")),
                signature_id=alert.get("signature_id"),
                raw_reference=f"{path.name}:{line_number}",
                raw_sha256=_sha256(raw_line),
                attributes={
                    "suricata_action": alert.get("action"),
                    "severity": alert.get("severity"),
                    "category": alert.get("category"),
                    "interface": record.get("in_iface"),
                    "vlan": record.get("vlan"),
                },
            )
        )
    return events


def normalize_sshd(path: Path, warnings: list[str]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    if not path.exists():
        warnings.append(f"Missing input file: {path}")
        return events

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\n")
            failure = FAILED_PASSWORD.search(raw_line)
            penalty = PENALTY_DROP.search(raw_line)

            if failure:
                source_ip = failure.group("src")
                events.append(
                    NormalizedEvent(
                        event_id=_event_id("sshd", raw_line),
                        source_type="sshd",
                        event_type="authentication_failure",
                        source_host=IP_TO_HOST.get(source_ip),
                        source_ip=source_ip,
                        source_port=int(failure.group("src_port")),
                        destination_host="server1",
                        destination_ip="10.10.40.10",
                        destination_port=22,
                        protocol="tcp",
                        action="denied",
                        outcome="failed_password",
                        message="sshd rejected a password",
                        raw_reference=f"{path.name}:{line_number}",
                        raw_sha256=_sha256(raw_line),
                        attributes={
                            "account": failure.group("user"),
                            "timestamp_note": "sshd -E output has no per-line timestamp",
                        },
                    )
                )
            elif penalty:
                source_ip = penalty.group("src")
                destination_ip = penalty.group("dst")
                events.append(
                    NormalizedEvent(
                        event_id=_event_id("sshd", raw_line),
                        source_type="sshd",
                        event_type="source_penalty_drop",
                        source_host=IP_TO_HOST.get(source_ip),
                        source_ip=source_ip,
                        source_port=int(penalty.group("src_port")),
                        destination_host=IP_TO_HOST.get(destination_ip),
                        destination_ip=destination_ip,
                        destination_port=int(penalty.group("dst_port")),
                        protocol="tcp",
                        action="dropped",
                        outcome="pre_authentication_drop",
                        message="sshd source penalty dropped the connection",
                        raw_reference=f"{path.name}:{line_number}",
                        raw_sha256=_sha256(raw_line),
                        attributes={
                            "reason": "failed authentication",
                            "timestamp_note": "sshd -E output has no per-line timestamp",
                        },
                    )
                )
    return events


def normalize_firewall_validation(path: Path, warnings: list[str]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    if not path.exists():
        warnings.append(f"Missing input file: {path}")
        return events

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\n")
            match = FIREWALL_COUNTER.search(raw_line)
            if not match:
                continue
            events.append(
                NormalizedEvent(
                    event_id=_event_id("firewall_validation", raw_line),
                    source_type="firewall_validation",
                    event_type="firewall_drop",
                    source_host="guest1",
                    source_ip="10.10.20.10",
                    destination_host="server1",
                    destination_ip="10.10.40.10",
                    protocol="tcp",
                    action="dropped",
                    outcome="blocked",
                    message="core1 Guest-to-local firewall counter increased",
                    raw_reference=f"{path.name}:{line_number}",
                    raw_sha256=_sha256(raw_line),
                    attributes={
                        "counter_before": int(match.group("before")),
                        "counter_after": int(match.group("after")),
                        "counter_delta": int(match.group("delta")),
                    },
                )
            )
    return events


def normalize_directory(input_dir: Path) -> tuple[list[NormalizedEvent], list[str]]:
    warnings: list[str] = []
    events = [
        *normalize_zeek(input_dir / "zeek-conn.log", warnings),
        *normalize_suricata(input_dir / "suricata-eve.json", warnings),
        *normalize_sshd(input_dir / "sshd.log", warnings),
        *normalize_firewall_validation(input_dir / "attack-validation.txt", warnings),
    ]
    unique_events = {event.event_id: event for event in events}
    ordered = sorted(
        unique_events.values(),
        key=lambda event: (event.observed_at or "9999", event.event_id),
    )
    return ordered, warnings
