from __future__ import annotations

import ipaddress
import re

from .models import AnalystReport, Incident


IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def validate_report(report: AnalystReport, incident: Incident) -> list[str]:
    errors: list[str] = []
    if report.incident_id != incident.incident_id:
        errors.append("Report incident_id does not match the incident.")
    if report.source_host != incident.source_host:
        errors.append("Report source_host does not match calculated incident facts.")

    allowed_assets = {asset.host for asset in incident.affected_assets}
    unknown_assets = set(report.affected_assets) - allowed_assets
    if unknown_assets:
        errors.append(f"Report contains unsupported affected assets: {sorted(unknown_assets)}")

    allowed_evidence = set(incident.evidence_ids)
    cited_evidence = set(report.evidence_ids)
    unsupported_evidence = cited_evidence - allowed_evidence
    if unsupported_evidence:
        errors.append(
            f"Report contains unsupported evidence IDs: {sorted(unsupported_evidence)}"
        )
    if not cited_evidence:
        errors.append("Report must cite at least one evidence ID.")

    allowed_ips = {incident.source_ip, *(asset.ip for asset in incident.affected_assets)}
    text_fields = [
        report.title,
        report.summary,
        *report.recommended_actions,
        *report.uncertainties,
    ]
    for candidate in IPV4_PATTERN.findall("\n".join(text_fields)):
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            errors.append(f"Report contains an invalid IPv4 address: {candidate}")
            continue
        if normalized not in allowed_ips:
            errors.append(f"Report contains an unsupported IPv4 address: {normalized}")

    success_count = incident.facts.get("successful_authentications_observed")
    summary_lower = report.summary.lower()
    if success_count == 0 and any(
        phrase in summary_lower
        for phrase in ("login succeeded", "successful login", "credentials were accepted")
    ):
        errors.append("Report claims a successful login that is not supported by the incident.")

    if report.analyst_review_required is not True:
        errors.append("Human analyst review must remain required.")
    return errors

