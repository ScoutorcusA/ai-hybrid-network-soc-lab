from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NormalizedEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str
    observed_at: str | None = None
    source_type: Literal[
        "zeek_conn", "suricata_alert", "sshd", "firewall_validation"
    ]
    event_type: Literal[
        "network_connection",
        "ids_alert",
        "authentication_failure",
        "source_penalty_drop",
        "firewall_drop",
    ]
    source_host: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_host: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    action: str
    outcome: str
    message: str
    signature_id: int | None = None
    raw_reference: str
    raw_sha256: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class Asset(StrictModel):
    host: str
    ip: str


class Incident(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    incident_type: Literal["guest_port_scan", "ssh_password_guessing"]
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    window_start: str | None = None
    window_end: str | None = None
    source_host: str
    source_ip: str
    affected_assets: list[Asset]
    facts: dict[str, Any]
    evidence_ids: list[str]
    uncertainties: list[str]


class AIReportBody(StrictModel):
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    source_host: str
    affected_assets: list[str]
    summary: str
    evidence_ids: list[str]
    recommended_actions: list[str]
    uncertainties: list[str]


class AnalystReport(AIReportBody):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    generator: Literal["mock", "openai", "openrouter"]
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    analyst_review_required: Literal[True] = True
