"""HTML and JSON report generation for CEMÍ."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cemi.models import Finding, ScanResult, Severity
from cemi.utils.redact import redact_path, redact_string


def _finding_status(finding: Finding) -> str:
    confidence = finding.contextual_confidence.lower()

    if finding.severity == Severity.LOW and confidence != "low":
        return "Informational"
    if confidence == "low":
        return "Likely Safe"
    if confidence == "medium":
        return "Needs Review"
    if finding.severity == Severity.CRITICAL or (
        confidence == "high" and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    ):
        return "Critical Investigation"
    return "High Priority"


def generate_html_report(result: ScanResult) -> str:
    """Generate an HTML report from a ScanResult."""
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    
    # Risk level explanations
    risk_level_why = {
        "none": "No security concerns detected. Your system looks clean based on the checks performed.",
        "low": "Minor concerns detected. Review the findings when convenient — none are immediately urgent.",
        "medium": "Moderate risk detected. Some findings warrant attention. Review and address them soon.",
        "high": "High risk detected. Address these findings promptly to reduce security exposure.",
        "critical": "Critical security issues detected. Take immediate action to review and address all findings.",
    }
    
    return template.render(
        result=result,
        _RISK_LEVEL_WHY=risk_level_why,
        _finding_status=_finding_status,
    )


def save_html_report(html: str, scan_id: str, output_dir: Path) -> Path:
    """Save HTML report to a file in output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base_filename = f"cemi_report_{scan_id}.html"
    path = output_dir / base_filename
    counter = 1
    while path.exists():
        path = output_dir / f"cemi_report_{scan_id}_{counter}.html"
        counter += 1
    path.write_text(html, encoding="utf-8")
    return path


def _sanitize_json_report_value(key: str, value: Any) -> Any:
    if key == "label" and isinstance(value, str):
        if value == "exe_path":
            return "exe_path_redacted"
        if value == "command":
            return "command_redacted"
        if value == "cmdline":
            return "cmdline_redacted"
        if value == "command_line":
            return "command_line_redacted"
    if key == "value" and isinstance(value, str):
        return redact_string(redact_path(value))
    return value


def _sanitize_json_report_data(data: Any) -> Any:
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            sanitized_key = "exe_path_redacted" if key == "exe_path" else key
            sanitized_key = "command_redacted" if sanitized_key == "command" else sanitized_key
            sanitized_key = "cmdline_redacted" if sanitized_key == "cmdline" else sanitized_key
            sanitized_key = "command_line_redacted" if sanitized_key == "command_line" else sanitized_key
            sanitized[sanitized_key] = _sanitize_json_report_data(_sanitize_json_report_value(key, value))
        return sanitized
    if isinstance(data, list):
        return [_sanitize_json_report_data(item) for item in data]
    return data


def save_json_report(result: ScanResult, output_dir: Path) -> Path:
    """Save JSON report to a file in output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base_filename = f"cemi_report_{result.scan_id}.json"
    path = output_dir / base_filename
    counter = 1
    while path.exists():
        path = output_dir / f"cemi_report_{result.scan_id}_{counter}.json"
        counter += 1
    data = _sanitize_json_report_data(result.model_dump())
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path