from __future__ import annotations

import os

from .models import AIReportBody, AnalystReport, Incident


SYSTEM_PROMPT = """You are a SOC incident-report drafting assistant.
Use only the supplied structured incident. Do not invent IP addresses, hosts,
events, counts, outcomes, or evidence IDs. Cite only IDs listed in evidence_ids.
For source_host and affected_assets, copy the permitted host strings exactly;
do not append IP addresses, parentheses, labels, or other text to those values.
Keep uncertainties. Recommend human actions, but never claim to execute commands,
change firewall rules, isolate hosts, or modify infrastructure.
"""


def _openrouter_response_schema(incident: Incident) -> dict:
    """Constrain evidence-backed identifiers to the incident's exact values."""
    schema = AIReportBody.model_json_schema()
    properties = schema["properties"]
    properties["source_host"]["const"] = incident.source_host
    properties["affected_assets"]["items"] = {
        "type": "string",
        "enum": [asset.host for asset in incident.affected_assets],
    }
    properties["affected_assets"]["minItems"] = 1
    properties["evidence_ids"]["items"] = {
        "type": "string",
        "enum": incident.evidence_ids,
    }
    properties["evidence_ids"]["minItems"] = 1
    return schema


def openai_report(incident: Incident, model: str | None = None) -> AnalystReport:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "AI mode requires the optional dependency: pip install -e './python[ai]'"
        ) from exc

    selected_model = model or os.getenv("OPENAI_MODEL")
    if not selected_model:
        raise RuntimeError("Set OPENAI_MODEL or pass --model when using AI mode.")
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set.")

    response = OpenAI().responses.parse(
        model=selected_model,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Draft a structured report for this incident:\n"
                + incident.model_dump_json(indent=2),
            },
        ],
        text_format=AIReportBody,
    )
    if response.output_parsed is None:
        raise RuntimeError("The model did not return a parsed incident report.")

    usage = getattr(response, "usage", None)
    return AnalystReport(
        **response.output_parsed.model_dump(),
        incident_id=incident.incident_id,
        generator="openai",
        model=selected_model,
        input_tokens=getattr(usage, "input_tokens", None),
        output_tokens=getattr(usage, "output_tokens", None),
        total_tokens=getattr(usage, "total_tokens", None),
    )


def openrouter_report(incident: Incident, model: str | None = None) -> AnalystReport:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "OpenRouter mode requires the optional dependency: "
            "pip install -e './python[ai]'"
        ) from exc

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")

    selected_model = model or os.getenv("OPENROUTER_MODEL", "openrouter/free")
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    response = client.chat.completions.create(
        model=selected_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Draft a structured report for this incident. "
                    "In affected_assets, use only the exact host values from "
                    "incident.affected_assets; never combine a host with its IP.\n"
                    + incident.model_dump_json(indent=2)
                ),
            },
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "soc_incident_report",
                "strict": True,
                "schema": _openrouter_response_schema(incident),
            },
        },
        extra_body={"provider": {"require_parameters": True}},
    )

    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("OpenRouter returned an empty report.")

    try:
        body = AIReportBody.model_validate_json(content)
    except Exception as exc:
        raise RuntimeError(
            "OpenRouter returned a report that did not match the required schema."
        ) from exc

    usage = getattr(response, "usage", None)
    actual_model = getattr(response, "model", None) or selected_model
    return AnalystReport(
        **body.model_dump(),
        incident_id=incident.incident_id,
        generator="openrouter",
        model=actual_model,
        input_tokens=getattr(usage, "prompt_tokens", None),
        output_tokens=getattr(usage, "completion_tokens", None),
        total_tokens=getattr(usage, "total_tokens", None),
    )
