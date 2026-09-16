import json
import sys
from types import SimpleNamespace

from soc_analyst.ai import openrouter_report
from soc_analyst.correlate import correlate
from soc_analyst.models import AnalystReport
from soc_analyst.normalize import normalize_directory
from soc_analyst.report import mock_report
from soc_analyst.validate_report import validate_report


def _write_sample(raw_dir):
    raw_dir.mkdir()
    zeek = []
    for index, port in enumerate((22, 23, 80)):
        zeek.append(
            {
                "ts": 1788898086.156 + index / 1000,
                "uid": f"scan-{index}",
                "id.orig_h": "10.10.20.10",
                "id.orig_p": 49000 + index,
                "id.resp_h": "10.10.40.10",
                "id.resp_p": port,
                "proto": "tcp",
                "conn_state": "S0",
                "orig_pkts": 1,
                "resp_pkts": 0,
            }
        )
    for index in range(6):
        zeek.append(
            {
                "ts": 1788898090.0 + index,
                "uid": f"ssh-{index}",
                "id.orig_h": "10.10.30.10",
                "id.orig_p": 44000 + index,
                "id.resp_h": "10.10.40.10",
                "id.resp_p": 22,
                "proto": "tcp",
                "service": "ssh" if index < 4 else None,
                "conn_state": "SF" if index < 4 else "RSTR",
                "orig_pkts": 5,
                "resp_pkts": 4,
            }
        )
    (raw_dir / "zeek-conn.log").write_text(
        "".join(json.dumps(item) + "\n" for item in zeek), encoding="utf-8"
    )

    alerts = [
        {
            "timestamp": "2026-09-08T20:08:06.156118+0000",
            "event_type": "alert",
            "src_ip": "10.10.20.10",
            "src_port": 49000,
            "dest_ip": "10.10.40.10",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature_id": 1000003,
                "signature": "SOC LAB Guest TCP port scan attempt",
                "severity": 3,
            },
        },
        {
            "timestamp": "2026-09-08T20:08:10.156118+0000",
            "event_type": "alert",
            "src_ip": "10.10.30.10",
            "src_port": 44000,
            "dest_ip": "10.10.40.10",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature_id": 1000004,
                "signature": "SOC LAB Repeated SSH connections",
                "severity": 3,
            },
        },
    ]
    (raw_dir / "suricata-eve.json").write_text(
        "".join(json.dumps(item) + "\n" for item in alerts), encoding="utf-8"
    )

    ssh_lines = [
        f"Failed password for socops from 10.10.30.10 port {44000 + i} ssh2"
        for i in range(4)
    ] + [
        f"drop connection #0 from [10.10.30.10]:{44004 + i} on [10.10.40.10]:22 penalty: failed authentication"
        for i in range(2)
    ]
    (raw_dir / "sshd.log").write_text("\n".join(ssh_lines) + "\n", encoding="utf-8")
    (raw_dir / "attack-validation.txt").write_text(
        "Firewall counter: 2 -> 14 (delta: 12)\n", encoding="utf-8"
    )


def test_normalization_is_stable(tmp_path):
    raw_dir = tmp_path / "raw"
    _write_sample(raw_dir)
    first, first_warnings = normalize_directory(raw_dir)
    second, second_warnings = normalize_directory(raw_dir)
    assert first_warnings == []
    assert second_warnings == []
    assert [event.event_id for event in first] == [event.event_id for event in second]


def test_correlation_reconciles_ssh_evidence(tmp_path):
    raw_dir = tmp_path / "raw"
    _write_sample(raw_dir)
    events, warnings = normalize_directory(raw_dir)
    assert warnings == []
    incidents = {incident.incident_type: incident for incident in correlate(events)}
    assert set(incidents) == {"guest_port_scan", "ssh_password_guessing"}
    ssh = incidents["ssh_password_guessing"]
    assert ssh.facts["network_connection_attempts"] == 6
    assert ssh.facts["failed_password_records"] == 4
    assert ssh.facts["source_penalty_drops"] == 2


def test_mock_reports_are_evidence_grounded(tmp_path):
    raw_dir = tmp_path / "raw"
    _write_sample(raw_dir)
    events, _ = normalize_directory(raw_dir)
    for incident in correlate(events):
        report = mock_report(incident)
        assert validate_report(report, incident) == []


def test_unsupported_evidence_and_ip_are_rejected(tmp_path):
    raw_dir = tmp_path / "raw"
    _write_sample(raw_dir)
    events, _ = normalize_directory(raw_dir)
    incident = correlate(events)[0]
    valid = mock_report(incident)
    invalid = AnalystReport.model_validate(
        {
            **valid.model_dump(),
            "summary": valid.summary + " Unknown host 192.0.2.77 was involved.",
            "evidence_ids": [*valid.evidence_ids, "evt_invented"],
        }
    )
    errors = validate_report(invalid, incident)
    assert any("unsupported evidence" in error.lower() for error in errors)
    assert any("unsupported IPv4" in error for error in errors)


def test_openrouter_uses_structured_incident_only(tmp_path, monkeypatch):
    raw_dir = tmp_path / "raw"
    _write_sample(raw_dir)
    events, _ = normalize_directory(raw_dir)
    incident = correlate(events)[0]
    body = mock_report(incident)
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                model="test/free-model",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(
                                {
                                    key: value
                                    for key, value in body.model_dump().items()
                                    if key
                                    in {
                                        "title",
                                        "severity",
                                        "confidence",
                                        "source_host",
                                        "affected_assets",
                                        "summary",
                                        "evidence_ids",
                                        "recommended_actions",
                                        "uncertainties",
                                    }
                                }
                            )
                        )
                    )
                ],
                usage=SimpleNamespace(
                    prompt_tokens=100,
                    completion_tokens=50,
                    total_tokens=150,
                ),
            )

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured["client"] = kwargs
            self.chat = SimpleNamespace(
                completions=FakeCompletions()
            )

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    report = openrouter_report(incident, model="test/free-model")

    assert captured["client"]["base_url"] == "https://openrouter.ai/api/v1"
    assert captured["model"] == "test/free-model"
    assert captured["response_format"]["type"] == "json_schema"
    assert captured["response_format"]["json_schema"]["strict"] is True
    schema = captured["response_format"]["json_schema"]["schema"]
    assert schema["properties"]["source_host"]["const"] == incident.source_host
    assert schema["properties"]["affected_assets"]["items"]["enum"] == [
        asset.host for asset in incident.affected_assets
    ]
    assert schema["properties"]["evidence_ids"]["items"]["enum"] == (
        incident.evidence_ids
    )
    assert captured["extra_body"]["provider"]["require_parameters"] is True
    assert "raw_reference" not in captured["messages"][1]["content"]
    assert "never combine a host with its IP" in captured["messages"][1]["content"]
    assert report.generator == "openrouter"
    assert report.model == "test/free-model"
    assert report.total_tokens == 150
    assert validate_report(report, incident) == []
