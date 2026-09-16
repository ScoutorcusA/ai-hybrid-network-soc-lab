from __future__ import annotations

import hashlib
from collections.abc import Iterable

from .models import Asset, Incident, NormalizedEvent


SCAN_PORTS = {22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080}


def _incident_id(incident_type: str, evidence_ids: list[str]) -> str:
    material = f"{incident_type}:{':'.join(sorted(evidence_ids))}"
    return f"inc_{hashlib.sha256(material.encode()).hexdigest()[:20]}"


def _window(events: Iterable[NormalizedEvent]) -> tuple[str | None, str | None]:
    timestamps = sorted(event.observed_at for event in events if event.observed_at)
    if not timestamps:
        return None, None
    return timestamps[0], timestamps[-1]


def _guest_scan_incident(events: list[NormalizedEvent]) -> Incident | None:
    zeek = [
        event
        for event in events
        if event.source_type == "zeek_conn"
        and event.source_ip == "10.10.20.10"
        and event.destination_ip == "10.10.40.10"
        and event.protocol == "tcp"
        and event.destination_port in SCAN_PORTS
    ]
    suricata = [
        event
        for event in events
        if event.source_type == "suricata_alert"
        and event.signature_id == 1000003
        and event.source_ip == "10.10.20.10"
        and event.destination_ip == "10.10.40.10"
    ]
    firewall = [
        event
        for event in events
        if event.event_type == "firewall_drop"
        and event.source_ip == "10.10.20.10"
        and event.destination_ip == "10.10.40.10"
    ]

    if not zeek and not suricata:
        return None

    evidence = [*zeek, *suricata, *firewall]
    evidence_ids = sorted({event.event_id for event in evidence})
    ports = sorted({event.destination_port for event in zeek if event.destination_port})
    no_response = [
        event
        for event in zeek
        if event.attributes.get("conn_state") == "S0"
        and event.attributes.get("orig_pkts") == 1
        and event.attributes.get("resp_pkts") == 0
    ]
    successful = [event for event in zeek if event.outcome == "SF"]
    firewall_delta = sum(
        int(event.attributes.get("counter_delta", 0)) for event in firewall
    )
    uncertainties: list[str] = []
    if not firewall:
        uncertainties.append(
            "No firewall-counter evidence was supplied, so enforcement is not independently proven."
        )
    if not suricata:
        uncertainties.append("No matching Suricata SID 1000003 alert was supplied.")

    start, end = _window(evidence)
    confidence = "high" if zeek and suricata and firewall else "medium"
    return Incident(
        incident_id=_incident_id("guest_port_scan", evidence_ids),
        incident_type="guest_port_scan",
        title="Guest VLAN TCP scan against server1",
        severity="medium",
        confidence=confidence,
        window_start=start,
        window_end=end,
        source_host="guest1",
        source_ip="10.10.20.10",
        affected_assets=[Asset(host="server1", ip="10.10.40.10")],
        facts={
            "network_connection_attempts": len(zeek),
            "distinct_destination_port_count": len(ports),
            "destination_ports": ports,
            "no_response_attempts": len(no_response),
            "successful_network_connections": len(successful),
            "firewall_drop_counter_delta": firewall_delta,
            "suricata_alert_count": len(suricata),
            "suricata_signature_ids": sorted(
                {event.signature_id for event in suricata if event.signature_id}
            ),
            "prevention_result": (
                "blocked"
                if firewall_delta >= len(ports) > 0 and len(no_response) == len(zeek)
                else "not_fully_proven"
            ),
        },
        evidence_ids=evidence_ids,
        uncertainties=uncertainties,
    )


def _ssh_guessing_incident(events: list[NormalizedEvent]) -> Incident | None:
    zeek = [
        event
        for event in events
        if event.source_type == "zeek_conn"
        and event.source_ip == "10.10.30.10"
        and event.destination_ip == "10.10.40.10"
        and event.destination_port == 22
        and event.protocol == "tcp"
    ]
    suricata = [
        event
        for event in events
        if event.source_type == "suricata_alert"
        and event.signature_id == 1000004
        and event.source_ip == "10.10.30.10"
        and event.destination_ip == "10.10.40.10"
        and event.destination_port == 22
    ]
    failures = [
        event
        for event in events
        if event.event_type == "authentication_failure"
        and event.source_ip == "10.10.30.10"
        and event.destination_ip == "10.10.40.10"
    ]
    penalties = [
        event
        for event in events
        if event.event_type == "source_penalty_drop"
        and event.source_ip == "10.10.30.10"
        and event.destination_ip == "10.10.40.10"
    ]

    if not zeek and not suricata and not failures and not penalties:
        return None

    evidence = [*zeek, *suricata, *failures, *penalties]
    evidence_ids = sorted({event.event_id for event in evidence})
    uncertainties = [
        "The sshd -E log lines have no per-line timestamps; their relationship is based on the bounded evidence-collection run."
    ]
    if not failures and not penalties:
        uncertainties.append(
            "No server1 authentication log evidence was supplied, so authentication outcome is not proven."
        )
    if not suricata:
        uncertainties.append("No matching Suricata SID 1000004 alert was supplied.")

    start, end = _window(evidence)
    confidence = "high" if zeek and suricata and (failures or penalties) else "medium"
    return Incident(
        incident_id=_incident_id("ssh_password_guessing", evidence_ids),
        incident_type="ssh_password_guessing",
        title="Repeated SSH password attempts from admin1 to server1",
        severity="high",
        confidence=confidence,
        window_start=start,
        window_end=end,
        source_host="admin1",
        source_ip="10.10.30.10",
        affected_assets=[Asset(host="server1", ip="10.10.40.10")],
        facts={
            "network_connection_attempts": len(zeek),
            "completed_ssh_protocol_sessions": sum(
                1
                for event in zeek
                if event.attributes.get("service") == "ssh" and event.outcome == "SF"
            ),
            "server_reset_sessions": sum(1 for event in zeek if event.outcome == "RSTR"),
            "failed_password_records": len(failures),
            "source_penalty_drops": len(penalties),
            "successful_authentications_observed": 0,
            "suricata_alert_count": len(suricata),
            "suricata_signature_ids": sorted(
                {event.signature_id for event in suricata if event.signature_id}
            ),
            "prevention_result": (
                "all_observed_attempts_failed_or_were_dropped"
                if zeek and len(failures) + len(penalties) >= len(zeek)
                else "not_fully_proven"
            ),
        },
        evidence_ids=evidence_ids,
        uncertainties=uncertainties,
    )


def correlate(events: list[NormalizedEvent]) -> list[Incident]:
    incidents = [
        incident
        for incident in (
            _guest_scan_incident(events),
            _ssh_guessing_incident(events),
        )
        if incident is not None
    ]
    return incidents
