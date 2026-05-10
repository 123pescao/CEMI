"""CLI entry point for CEMÍ.

Two subcommands are available:

* ``cemi scan``     — run a local, metadata-only scan and save a report.
* ``cemi privacy``  — display privacy guarantees and exit immediately.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from cemi.collectors.browser_extensions import BrowserExtensionsCollector
from cemi.collectors.installed_apps import InstalledAppsCollector
from cemi.collectors.native_messaging import NativeMessagingHostsCollector
from cemi.collectors.scheduled_tasks import ScheduledTasksCollector
from cemi.collectors.services import ServicesCollector
from cemi.collectors.signatures import SignaturesCollector
from cemi.collectors.startup import StartupCollector
from cemi.config import PRIVACY_NOTICE, TOOL_NAME, TOOL_TAGLINE
from cemi.models import CollectorHealth, Finding, Severity
from cemi.reports import generate_html_report, save_html_report, save_json_report
from cemi.scan_engine import ScanEngine

app = typer.Typer(
    name="cemi",
    help=f"{TOOL_NAME} — {TOOL_TAGLINE}",
    no_args_is_help=True,
    add_completion=False,
)

_console = Console()


class OutputFormat(str, Enum):
    html = "html"
    json = "json"


def _confirm_privacy(yes: bool) -> None:
    """Display the privacy notice and abort unless the user agrees.

    When ``yes`` is True the prompt is skipped entirely.
    """
    if yes:
        return

    _console.print(PRIVACY_NOTICE)
    answer = typer.prompt("Do you want to continue? (y/N)", default="N", show_default=False)
    if answer.strip().lower() != "y":
        _console.print("Aborted.")
        raise typer.Exit(code=1)


_SEVERITY_STYLES: dict[str, str] = {
    "INFO": "blue",
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_RISK_LEVEL_STYLES: dict[str, str] = {
    "none": "green",
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_RISK_LEVEL_WHY: dict[str, str] = {
    "none": "No security concerns detected. Your system looks clean based on the checks performed.",
    "low": "Minor concerns detected. Review the findings when convenient — none are immediately urgent.",
    "medium": "Moderate risk detected. Some findings warrant attention. Review and address them soon.",
    "high": "High risk detected. Address these findings promptly to reduce security exposure.",
    "critical": "Critical security issues detected. Take immediate action to review and address all findings.",
}

_SEVERITY_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _finding_status(finding: Finding) -> str:
    confidence = finding.contextual_confidence.lower()

    if finding.severity == Severity.CRITICAL or (
        confidence == "high" and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    ):
        return "Critical Investigation"
    if confidence == "low":
        return "Likely Safe"
    if confidence == "medium":
        return "Needs Review"
    return "High Priority"


def _print_findings(findings: list[Finding]) -> None:
    """Print findings grouped by severity, or a clean no-findings message."""
    _console.print("\n[bold]Findings[/bold]")
    if not findings:
        _console.print("  No findings detected.")
        return

    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity.value, []).append(f)

    for sev in _SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue
        style = _SEVERITY_STYLES.get(sev, "white")
        _console.print(f"\n  [{style}][bold]{sev}[/bold][/{style}]")
        for f in group:
            _console.print(f"\n  [bold]{escape(f.title)}[/bold]")
            _console.print(f"    Severity: [{style}]{f.severity.value}[/{style}]")
            _console.print(f"    Original Confidence: {f.confidence.value}")
            _console.print(f"    Contextual Confidence: {f.contextual_confidence}")
            _console.print(f"    Status: {_finding_status(f)}")
            if f.app:
                _console.print(f"    App: {escape(f.app)}")
            _console.print(f"\n    [bold]Official Explanation[/bold]")
            _console.print(f"    {escape(f.official_explanation)}")
            _console.print(f"\n    [bold]In Other Words[/bold]")
            _console.print(f"    {escape(f.in_other_words)}")
            _console.print(f"\n    [bold]Why This Matters[/bold]")
            _console.print(f"    {escape(f.why_this_matters)}")
            _console.print(f"\n    [bold]Recommended Action[/bold]")
            _console.print(f"    {escape(f.recommended_action)}")
            reasoning = " ".join(f.reasoning_notes) if f.reasoning_notes else "Matched deterministic local rule evidence."
            _console.print(f"\n    [bold]Why CEMÍ Thinks This[/bold]")
            _console.print(f"    {escape(reasoning)}")
            n = len(f.evidence)
            _console.print(f"\n    Evidence: {n} supporting item{'s' if n != 1 else ''}")


def _print_collector_summary(health: CollectorHealth) -> None:
    """Print a one-line status for a collector, followed by any errors."""
    if health.skipped_reason:
        _console.print(
            f"  {health.collector_name}: SKIPPED — {health.skipped_reason}"
        )
    elif health.ran_successfully:
        _console.print(
            f"  {health.collector_name}: OK ({health.duration_seconds:.2f}s)"
        )
    else:
        _console.print(
            f"  {health.collector_name}: FAILED ({health.duration_seconds:.2f}s)"
        )
    if health.errors:
        _console.print("  Errors:")
        for err in health.errors:
            _console.print(f"    {err}")


_PRIVACY_GUARANTEES: list[str] = [
    "No telemetry",
    "No network upload",
    "No browser history reading",
    "No cookie reading",
    "No personal document scanning",
    "Reports are local",
]


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    output: OutputFormat = typer.Option(
        OutputFormat.html,
        "--output",
        help="Report format: html (default) or json. The report is saved locally — never uploaded.",
    ),
    app_filter: Optional[str] = typer.Option(
        None,
        "--app",
        help="Restrict the scan to a specific application name.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive privacy confirmation prompt.",
    ),
) -> None:
    if ctx.invoked_subcommand is None:
        scan(output=output, app_filter=app_filter, yes=yes)


@app.command()
def scan(
    output: OutputFormat = typer.Option(
        OutputFormat.html,
        "--output",
        help="Report format: html (default) or json. The report is saved locally — never uploaded.",
    ),
    app_filter: Optional[str] = typer.Option(
        None,
        "--app",
        help="Restrict the scan to a specific application name.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive privacy confirmation prompt.",
    ),
) -> None:
    """Run a local, metadata-only scan. All analysis and reports stay on this machine."""
    _confirm_privacy(yes)

    result = ScanEngine([
        InstalledAppsCollector(),
        ServicesCollector(),
        NativeMessagingHostsCollector(),
        BrowserExtensionsCollector(),
        StartupCollector(),
        ScheduledTasksCollector(),
        SignaturesCollector(),
    ]).run_scan()

    svcs_count = next(
        (h.items_collected for h in result.collector_health if h.collector_name == "services"),
        0,
    )
    bext_count = next(
        (h.items_collected for h in result.collector_health if h.collector_name == "browser_extensions"),
        0,
    )
    startup_count = next(
        (h.items_collected for h in result.collector_health if h.collector_name == "startup"),
        0,
    )
    sig_count = next(
        (h.items_collected for h in result.collector_health if h.collector_name == "signatures"),
        0,
    )

    _console.print("\n[bold]CEMÍ SCAN RESULTS[/bold]")
    _console.print("Scan complete.")
    _console.print("\n[bold]Risk Summary[/bold]")
    level = result.risk_summary.level
    level_style = _RISK_LEVEL_STYLES.get(level, "white")
    _console.print(f"  Risk score: {result.risk_summary.score}/100")
    _console.print(f"  Risk level: [{level_style}]{level}[/{level_style}]")
    _console.print(f"  Why this matters: {_RISK_LEVEL_WHY.get(level, '')}")

    _console.print("\n[bold]Possible Malware/Spyware Signals[/bold]")
    malware_findings = [f for f in result.findings if f.category in ("Persistence",)]
    if malware_findings:
        _console.print(f"  {len(malware_findings)} persistence or malware-style findings detected")
    else:
        _console.print("  No malware/spyware signals detected")

    _console.print("\n[bold]Privacy Signals[/bold]")
    privacy_findings = [f for f in result.findings if f.category in ("Browser", "Service")]
    if privacy_findings:
        _console.print(f"  {len(privacy_findings)} privacy-related findings detected")
    else:
        _console.print("  No privacy signals detected")

    _console.print("\n[bold]Collectors[/bold]")
    for health in result.collector_health:
        _print_collector_summary(health)

    _print_findings(result.findings)

    _console.print("\n[bold]Summary[/bold]")
    _console.print(f"  Installed apps found: {result.total_apps_scanned}")
    _console.print(f"  Services found: {svcs_count}")
    _console.print(f"  Browser extensions found: {bext_count}")
    _console.print(f"  Startup entries found: {startup_count}")
    _console.print(f"  Signatures inspected: {sig_count}")

    counts = result.risk_summary.finding_counts
    for sev in _SEVERITY_ORDER:
        if sev == "INFO":
            continue
        count = counts.get(sev, 0)
        if count > 0:
            sev_style = _SEVERITY_STYLES.get(sev, "white")
            plural = "s" if count != 1 else ""
            _console.print(f"  [{sev_style}]{count} {sev.lower()} finding{plural}[/{sev_style}]")

    _console.print("\n[bold]Recommended Next Steps[/bold]")
    _console.print("  - Review any HIGH or CRITICAL findings above")
    _console.print("  - CEMÍ is not antivirus; use trusted security tools for verification")
    _console.print("  - Findings are behavioral signals, not definitive malware detection")

    if output == OutputFormat.html:
        html = generate_html_report(result)
        report_path = save_html_report(html, result.scan_id, Path("reports"))
        _console.print(f"HTML report saved to: {report_path}")
    elif output == OutputFormat.json:
        report_path = save_json_report(result, Path("reports"))
        _console.print(f"JSON report saved to: {report_path}")


@app.command()
def privacy() -> None:
    """Show CEMÍ privacy guarantees and exit. No scan is performed."""
    _console.print("[bold]CEMÍ Privacy Guarantees[/bold]")
    for guarantee in _PRIVACY_GUARANTEES:
        _console.print(f"  {guarantee}")


@app.command()
def version() -> None:
    """Print the installed CEMÍ version."""
    import cemi as _cemi
    _console.print(f"CEMÍ {_cemi.__version__}")


def main() -> None:
    """Setuptools / `pyproject.toml` console-script entry point."""
    app()


if __name__ == "__main__":
    main()
