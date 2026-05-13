"""HTML and JSON report generation for CEMÍ."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cemi.models import Finding, ScanResult, Severity


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


def save_json_report(result: ScanResult, output_dir: Path) -> Path:
    """Save JSON report to a file in output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base_filename = f"cemi_report_{result.scan_id}.json"
    path = output_dir / base_filename
    counter = 1
    while path.exists():
        path = output_dir / f"cemi_report_{result.scan_id}_{counter}.json"
        counter += 1
    data = result.model_dump()
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path