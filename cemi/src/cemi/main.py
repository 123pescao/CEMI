"""CLI entry point for CEMÍ.

The CLI is intentionally minimal in this phase:

* It defines a single ``scan`` command.
* Before doing anything it prints an explicit privacy notice and waits
  for confirmation (unless ``--yes`` is passed).
* It delegates collection to :class:`~cemi.scan_engine.ScanEngine` and
  prints a plain-text summary of the resulting :class:`~cemi.models.ScanResult`.
  Report generation (html/json) is a stub — the ``--output`` flag is
  accepted and validated but does not yet produce a file.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from cemi.collectors.installed_apps import InstalledAppsCollector
from cemi.collectors.native_messaging import NativeMessagingHostsCollector
from cemi.collectors.services import ServicesCollector
from cemi.config import PRIVACY_NOTICE, TOOL_NAME, TOOL_TAGLINE
from cemi.models import CollectorHealth, Finding
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


def _print_findings(findings: list[Finding]) -> None:
    """Print all findings to the console, or a clean no-findings message."""
    if not findings:
        _console.print("No findings detected.")
        return

    _console.print("\n[bold]Findings[/bold]")
    for f in findings:
        style = _SEVERITY_STYLES.get(f.severity.value, "white")
        _console.print(f"\n[bold]{escape(f.title)}[/bold]")
        _console.print(f"  Severity: [{style}]{f.severity.value}[/{style}]")
        if f.app:
            _console.print(f"  App: {escape(f.app)}")
        _console.print(f"\n  [bold]Official Explanation[/bold]")
        _console.print(f"  {escape(f.official_explanation)}")
        _console.print(f"\n  [bold]In Other Words[/bold]")
        _console.print(f"  {escape(f.in_other_words)}")
        _console.print(f"\n  [bold]Why This Matters[/bold]")
        _console.print(f"  {escape(f.why_this_matters)}")
        _console.print(f"\n  [bold]Recommended Action[/bold]")
        _console.print(f"  {escape(f.recommended_action)}")
        n = len(f.evidence)
        _console.print(f"\n  Evidence: {n} supporting item{'s' if n != 1 else ''}")


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


@app.command()
def scan(
    output: OutputFormat = typer.Option(
        OutputFormat.html,
        "--output",
        help="Output format for the (eventual) report. Choices: html, json.",
    ),
    app_filter: Optional[str] = typer.Option(
        None,
        "--app",
        help="Restrict the scan to a specific application name.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive privacy confirmation.",
    ),
    privacy: bool = typer.Option(
        False,
        "--privacy",
        help="Show privacy guarantees and exit without running a scan.",
    ),
) -> None:
    """Run a local, metadata-only scan of this machine."""
    if privacy:
        _console.print("[bold]CEMÍ Privacy Guarantees[/bold]")
        for guarantee in _PRIVACY_GUARANTEES:
            _console.print(f"  {guarantee}")
        return

    _confirm_privacy(yes)

    result = ScanEngine([
        InstalledAppsCollector(),
        ServicesCollector(),
        NativeMessagingHostsCollector(),
    ]).run_scan()

    svcs_count = next(
        (h.items_collected for h in result.collector_health if h.collector_name == "services"),
        0,
    )

    _console.print("Scan complete.")
    _console.print(f"  Installed apps found: {result.total_apps_scanned}")
    _console.print(f"  Services found: {svcs_count}")
    for health in result.collector_health:
        _print_collector_summary(health)

    _print_findings(result.findings)

    if output == OutputFormat.html:
        html = generate_html_report(result)
        report_path = save_html_report(html, result.scan_id, Path("reports"))
        _console.print(f"HTML report saved to: {report_path}")
    elif output == OutputFormat.json:
        report_path = save_json_report(result, Path("reports"))
        _console.print(f"JSON report saved to: {report_path}")


def main() -> None:
    """Setuptools / `pyproject.toml` console-script entry point."""
    app()


if __name__ == "__main__":
    main()
