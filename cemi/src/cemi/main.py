"""CLI entry point for CEMÍ.

Three subcommands are available:

* ``cemi scan``     — run a local, metadata-only scan and save a report.
* ``cemi monitor``  — repeatedly run scans and track changes over time.
* ``cemi privacy``  — display privacy guarantees and exit immediately.
"""
from __future__ import annotations

import time
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
from cemi.correlation_engine import CorrelatedSignal
from cemi.models import CollectorHealth, Finding, Severity
from cemi.monitor import compute_diff, create_snapshot, get_latest_snapshot, save_snapshot
from cemi.reports import generate_html_report, save_html_report, save_json_report
from cemi.scan_engine import ScanEngine
from cemi.timeline import get_timeline_summary, load_history

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


def _print_correlated_signals(signals: list[CorrelatedSignal]) -> None:
    """Print correlated threat signals before the standard findings."""
    if not signals:
        return

    _console.print("\n[bold]Correlated Threat Signals[/bold]")
    for signal in signals:
        _console.print(f"\n  [bold]{signal.title}[/bold]")
        _console.print(f"    Status: {signal.status}")
        _console.print(f"    Confidence: {signal.contextual_confidence}")
        _console.print(f"    Severity: {signal.severity.value}")
        _console.print(f"    Risk multiplier: {signal.risk_multiplier}")
        if signal.contributing_findings:
            _console.print("    Why CEMÍ correlated this:")
            for item in signal.contributing_findings:
                _console.print(f"      - {item}")
        if signal.reasoning_notes:
            _console.print(f"    Notes: {' '.join(signal.reasoning_notes)}")


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

    _print_correlated_signals(result.correlated_signals)
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
def monitor(
    interval: int = typer.Option(
        60,
        "--interval",
        help="Seconds between scans (default 60).",
    ),
    iterations: Optional[int] = typer.Option(
        None,
        "--iterations",
        help="Number of scans to run (default: infinite until interrupted).",
    ),
    output: Optional[OutputFormat] = typer.Option(
        None,
        "--output",
        help="Optional: save final scan as html or json report.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive privacy confirmation prompt.",
    ),
) -> None:
    """Repeatedly run scans and track changes over time.

    This is local monitoring mode that detects new and resolved findings,
    tracks risk score changes, and stores summaries in .cemi/history/.
    All data stays on this machine — no uploads or telemetry.
    """
    _confirm_privacy(yes)

    _console.print("\n[bold]CEMÍ MONITOR[/bold]")
    _console.print("Starting local monitoring mode. Press Ctrl+C to stop.\n")

    scanner = ScanEngine([
        InstalledAppsCollector(),
        ServicesCollector(),
        NativeMessagingHostsCollector(),
        BrowserExtensionsCollector(),
        StartupCollector(),
        ScheduledTasksCollector(),
        SignaturesCollector(),
    ])

    previous_snapshot = get_latest_snapshot()
    iteration = 0

    try:
        while True:
            iteration += 1
            if iterations is not None and iteration > iterations:
                break

            _console.print(
                f"[bold]Iteration {iteration}{f'/{iterations}' if iterations else ''}[/bold]"
            )

            # Run scan and create snapshot
            scan_result = scanner.run_scan()
            snapshot = create_snapshot(scan_result)
            filepath = save_snapshot(snapshot)

            # Display results
            risk_style = _RISK_LEVEL_STYLES.get(snapshot.risk_level, "white")
            _console.print(f"Risk: {snapshot.risk_score}/100 [{risk_style}]{snapshot.risk_level}[/{risk_style}]")
            _console.print(f"Snapshot saved: {filepath}")

            # Show diff if we have a previous snapshot
            if previous_snapshot:
                diff = compute_diff(previous_snapshot, snapshot)

                if diff.new_findings:
                    _console.print(f"[yellow]New findings: {len(diff.new_findings)}[/yellow]")
                    for finding in diff.new_findings:
                        _console.print(f"  + {finding['title']}")
                else:
                    _console.print("New findings: 0")

                if diff.resolved_findings:
                    _console.print(f"[green]Resolved findings: {len(diff.resolved_findings)}[/green]")
                    for finding in diff.resolved_findings:
                        _console.print(f"  - {finding['title']}")
                else:
                    _console.print("Resolved findings: 0")

                if diff.risk_score_delta != 0:
                    delta_sign = "+" if diff.risk_score_delta > 0 else ""
                    delta_style = "red" if diff.risk_score_delta > 0 else "green"
                    _console.print(
                        f"Risk score delta: [{delta_style}]{delta_sign}{diff.risk_score_delta}[/{delta_style}]"
                    )

                if diff.collector_changes:
                    _console.print(f"Collector changes: {len(diff.collector_changes)}")
                    for collector, changes in diff.collector_changes.items():
                        old_str = "OK" if changes["old"] else "FAILED"
                        new_str = "OK" if changes["new"] else "FAILED"
                        _console.print(f"  {collector}: {old_str} → {new_str}")
            else:
                _console.print("New findings: 0 (baseline scan)")
                _console.print("Resolved findings: 0 (baseline scan)")

            previous_snapshot = snapshot

            # Wait before next iteration
            if iterations is None or iteration < iterations:
                _console.print(f"Next scan in {interval}s...\n")
                time.sleep(interval)

        _console.print("\nMonitoring complete.")

        # Optional final report
        if output and iterations is not None:
            scan_result = scanner.run_scan()
            if output == OutputFormat.html:
                html = generate_html_report(scan_result)
                report_path = save_html_report(html, scan_result.scan_id, Path("reports"))
                _console.print(f"Final HTML report saved to: {report_path}")
            elif output == OutputFormat.json:
                report_path = save_json_report(scan_result, Path("reports"))
                _console.print(f"Final JSON report saved to: {report_path}")

    except KeyboardInterrupt:
        _console.print("\n\nMonitoring interrupted by user.")


@app.command()
def history(
    history_dir: Optional[Path] = typer.Option(
        None,
        "--history-dir",
        help="Path to monitor history directory. Defaults to .cemi/history relative to the current working directory.",
    ),
) -> None:
    """Show a local timeline summary for previously saved monitor snapshots."""
    snapshots = load_history(history_dir)
    if not snapshots:
        _console.print("[bold]CEMÍ HISTORY SUMMARY[/bold]")
        _console.print("No monitor history found.")
        _console.print("Run: cemi monitor --yes --interval 60 --iterations 5")
        return

    summary = get_timeline_summary(snapshots)
    _console.print("[bold]CEMÍ HISTORY SUMMARY[/bold]")
    _console.print(f"Snapshots: {summary.total_snapshots}")
    _console.print(f"First seen: {summary.first_seen_at.isoformat(sep=' ')}")
    _console.print(f"Latest snapshot: {summary.last_seen_at.isoformat(sep=' ')}")
    _console.print(f"Latest risk score: {summary.latest_risk_score}/100")
    _console.print(f"Latest risk level: {summary.latest_risk_level}")
    _console.print(f"Highest observed risk score: {summary.highest_risk_score}/100")
    _console.print(f"Risk score change: {summary.risk_score_delta:+d}")
    _console.print(f"Active findings: {len(summary.active_findings)}")
    _console.print(f"New findings since first scan: {len(summary.new_findings_since_first)}")
    _console.print(f"Resolved findings since first scan: {len(summary.resolved_findings_since_first)}")


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
