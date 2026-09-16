from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .ai import openai_report, openrouter_report
from .correlate import correlate
from .models import AnalystReport, Incident, NormalizedEvent
from .normalize import normalize_directory
from .report import mock_report
from .validate_report import validate_report


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, events: list[NormalizedEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.model_dump_json() + "\n")


def _read_jsonl(path: Path) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                events.append(NormalizedEvent.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def _read_incidents(path: Path) -> list[Incident]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Incident.model_validate(item) for item in data]


def _read_reports(path: Path) -> list[AnalystReport]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [AnalystReport.model_validate(item) for item in data]


def command_normalize(args: argparse.Namespace) -> int:
    events, warnings = normalize_directory(args.input)
    _write_jsonl(args.output, events)
    counts = Counter(event.source_type for event in events)
    print(f"Normalized events: {len(events)}")
    for source_type, count in sorted(counts.items()):
        print(f"  {source_type}: {count}")
    print(f"Parser warnings: {len(warnings)}")
    for warning in warnings:
        print(f"  WARNING: {warning}")
    print(f"Output: {args.output}")
    return 0


def command_correlate(args: argparse.Namespace) -> int:
    events = _read_jsonl(args.input)
    incidents = correlate(events)
    _write_json(args.output, [incident.model_dump() for incident in incidents])
    print(f"Correlated incidents: {len(incidents)}")
    for incident in incidents:
        print(f"  {incident.incident_id}: {incident.incident_type}")
    print(f"Output: {args.output}")
    return 0 if incidents else 1


def command_report(args: argparse.Namespace) -> int:
    incidents = _read_incidents(args.input)
    reports: list[AnalystReport] = []
    failed = False
    for incident in incidents:
        if args.mode == "mock":
            report = mock_report(incident)
        elif args.mode in {"ai", "openai"}:
            report = openai_report(incident, model=args.model)
        else:
            report = openrouter_report(incident, model=args.model)
        errors = validate_report(report, incident)
        if errors:
            failed = True
            print(f"REJECTED: {incident.incident_id}", file=sys.stderr)
            for error in errors:
                print(f"  {error}", file=sys.stderr)
            continue
        reports.append(report)
        print(f"VALID: {incident.incident_id} ({args.mode})")

    _write_json(args.output, [report.model_dump() for report in reports])
    print(f"Valid reports: {len(reports)}")
    print(f"Output: {args.output}")
    return 1 if failed else 0


def command_validate(args: argparse.Namespace) -> int:
    incidents = {item.incident_id: item for item in _read_incidents(args.incidents)}
    reports = _read_reports(args.reports)
    failures = 0
    for report in reports:
        incident = incidents.get(report.incident_id)
        if incident is None:
            failures += 1
            print(f"FAIL: no incident exists for report {report.incident_id}")
            continue
        errors = validate_report(report, incident)
        if errors:
            failures += 1
            print(f"FAIL: {report.incident_id}")
            for error in errors:
                print(f"  {error}")
        else:
            print(f"PASS: {report.incident_id}")
    print(f"Report validation failures: {failures}")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-analyst",
        description="Evidence-grounded analyst for the hybrid network SOC lab",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser("normalize", help="Normalize raw logs")
    normalize_parser.add_argument("--input", type=Path, required=True)
    normalize_parser.add_argument("--output", type=Path, required=True)
    normalize_parser.set_defaults(func=command_normalize)

    correlate_parser = subparsers.add_parser(
        "correlate", help="Group normalized events into incidents"
    )
    correlate_parser.add_argument("--input", type=Path, required=True)
    correlate_parser.add_argument("--output", type=Path, required=True)
    correlate_parser.set_defaults(func=command_correlate)

    report_parser = subparsers.add_parser("report", help="Create analyst reports")
    report_parser.add_argument("--input", type=Path, required=True)
    report_parser.add_argument("--output", type=Path, required=True)
    report_parser.add_argument(
        "--mode", choices=("mock", "ai", "openai", "openrouter"), default="mock"
    )
    report_parser.add_argument("--model")
    report_parser.set_defaults(func=command_report)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate reports against their incidents"
    )
    validate_parser.add_argument("--incidents", type=Path, required=True)
    validate_parser.add_argument("--reports", type=Path, required=True)
    validate_parser.set_defaults(func=command_validate)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(args.func(args))
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")


if __name__ == "__main__":
    main()
