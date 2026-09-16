from __future__ import annotations

from .models import AIReportBody, AnalystReport, Incident


def mock_report(incident: Incident) -> AnalystReport:
    assets = [asset.host for asset in incident.affected_assets]

    if incident.incident_type == "guest_port_scan":
        facts = incident.facts
        body = AIReportBody(
            title=incident.title,
            severity=incident.severity,
            confidence=incident.confidence,
            source_host=incident.source_host,
            affected_assets=assets,
            summary=(
                f"Zeek observed {facts['network_connection_attempts']} TCP connection "
                f"attempts from guest1 to {facts['distinct_destination_port_count']} "
                f"ports on server1. {facts['no_response_attempts']} attempts received "
                f"no response, Suricata raised {facts['suricata_alert_count']} matching "
                f"scan alert(s), and the firewall counter increased by "
                f"{facts['firewall_drop_counter_delta']}. The calculated prevention "
                f"result is {facts['prevention_result']}."
            ),
            evidence_ids=incident.evidence_ids,
            recommended_actions=[
                "Confirm guest1 is an authorized lab endpoint and preserve the bounded evidence set.",
                "Review the Guest-to-local firewall rule and continue monitoring for repeated scans.",
                "Investigate the endpoint if equivalent behavior occurs outside an approved simulation.",
            ],
            uncertainties=incident.uncertainties,
        )
    else:
        facts = incident.facts
        body = AIReportBody(
            title=incident.title,
            severity=incident.severity,
            confidence=incident.confidence,
            source_host=incident.source_host,
            affected_assets=assets,
            summary=(
                f"Zeek observed {facts['network_connection_attempts']} SSH connection "
                f"attempts from admin1 to server1. server1 recorded "
                f"{facts['failed_password_records']} failed-password event(s) and "
                f"{facts['source_penalty_drops']} connection(s) dropped by OpenSSH's "
                f"source-penalty mechanism. No successful authentication was observed."
            ),
            evidence_ids=incident.evidence_ids,
            recommended_actions=[
                "Confirm whether the activity was the approved lab simulation.",
                "If unexpected, isolate and investigate admin1 because it is a management endpoint.",
                "Preserve Zeek, Suricata, and server1 authentication evidence for review.",
            ],
            uncertainties=incident.uncertainties,
        )

    return AnalystReport(
        **body.model_dump(),
        incident_id=incident.incident_id,
        generator="mock",
    )

