# CEMÍ — Computer Evidence Monitoring Inspector

CEMÍ is a **local-first, privacy-first** desktop security audit tool that inspects system metadata and configuration to help users understand the security posture of their machine. 

**What it does**: Identifies local behaviors and configurations commonly associated with malware, spyware, trojans, and intrusion activity.

**What it is not**: Antivirus, EDR, forensics tool, or malware removal—see [docs/limitations.md](../docs/limitations.md).

**Platform**: Designed for Windows. Limited support on Linux/WSL.

CEMÍ is **read-only, non-destructive, and local-only**. It never accesses personal files, never collects telemetry, never uploads data. All analysis, reports, and logs remain on your device under your control.

See [docs/USER_MANUAL.md](../docs/USER_MANUAL.md) for complete usage instructions, CLI reference, report handling, and privacy guidance.

See [docs/threat_model/README.md](../docs/threat_model/README.md) for detailed threat model and scope.

## Quick Start

### Installation (Python 3.11+)

Linux/macOS/WSL:

```bash
# Clone or cd to the cemi directory
cd cemi

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install editable with dev dependencies
pip install -e .[dev]
```

Windows PowerShell:

```powershell
# Clone or cd to the cemi directory
cd cemi

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install editable with dev dependencies
pip install -e .[dev]
```

### Run a Scan

```bash
# See privacy guarantees and exit
cemi privacy

# Run a scan (interactive, prompts for privacy confirmation)
cemi scan

# Run without prompt (skip privacy confirmation)
cemi scan --yes

# Save report as HTML (default)
cemi scan --yes --output html

# Save report as JSON
cemi scan --yes --output json
```

### Monitor Mode (Repeated Scans)

Track changes over time with local history:

```bash
# Run 5 scans every 60 seconds
cemi monitor --yes --interval 60 --iterations 5

# View scan history summary
cemi history

# View history from custom directory
cemi history --history-dir /path/to/.cemi/history
```

### Run Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py
```

## What CEMÍ Detects

- **Suspicious startup entries** (Run, RunOnce, startup folders)
- **Unusual scheduled tasks** (especially PowerShell, cmd, LOLBins)
- **Services running from user-writable paths**
- **Browser extensions with excessive permissions** (cookies, all URLs, scripting)
- **Browser-to-native messaging bridges** (extension-native IPC)
- **Suspicious process command-lines** (system tools used for persistence)
- **Network listening ports** and established connections
- **Risk scoring** based on finding severity and correlation

See [docs/threat_model/threat_coverage_matrix.md](../docs/threat_model/threat_coverage_matrix.md) for detailed coverage.

## What CEMÍ Does NOT Do

- **Not antivirus**: Does not confirm malware, does not remove threats
- **Not EDR**: Not for enterprise management or centralized monitoring
- **Not a forensic tool**: Does not preserve evidence chains or timeline analysis
- **No file scanning**: Metadata only (software names, versions, permissions)
- **No browser history/cookies**: Never accesses or reads browser data
- **No cloud lookups**: No VirusTotal, no reputation services (stays offline)
- **No automatic remediation**: All changes are manual and user-initiated

For full limitations, see [docs/limitations.md](../docs/limitations.md).

## Reports

Reports are saved locally to `reports/` and never uploaded:

- **HTML Report** (default): Rich visual summary with findings
- **JSON Report**: Machine-readable structured data

Reports describe system configuration and should be treated as **sensitive**. Do not commit to version control; review before sharing. See [docs/safe_report_sharing.md](../docs/safe_report_sharing.md).

## Documentation

- [docs/USER_MANUAL.md](../docs/USER_MANUAL.md) — Complete user manual with install, CLI reference, report handling, and privacy guidance
- [docs/threat_model/README.md](../docs/threat_model/README.md) — Threat model, scope, and design philosophy
- [docs/threat_model/threat_coverage_matrix.md](../docs/threat_model/threat_coverage_matrix.md) — Detailed coverage: what's detected, deferred, and forbidden
- [docs/architecture.md](../docs/architecture.md) — System design, collector architecture, redaction pipeline
- [docs/limitations.md](../docs/limitations.md) — Honest limitations: what CEMÍ does not do
- [docs/safe_report_sharing.md](../docs/safe_report_sharing.md) — How to safely share reports
- [docs/portfolio_review_notes.md](../docs/portfolio_review_notes.md) — For security engineers/hiring managers

For validation and demo:

- [docs/validation/clean_install_checklist.md](../docs/validation/clean_install_checklist.md) — Installation verification
- [docs/validation/windows_validation_checklist.md](../docs/validation/windows_validation_checklist.md) — Windows testing guide
- [docs/demo/demo_script.md](../docs/demo/demo_script.md) — Demo walkthrough
- [docs/demo/demo_commands.md](../docs/demo/demo_commands.md) — Safe commands to demonstrate
- [docs/demo/sample_report_guidance.md](../docs/demo/sample_report_guidance.md) — Creating synthetic samples

## Privacy & Security

**Core guarantees**:
- ✅ No telemetry, no analytics, no "phone home"
- ✅ Local-only: all data stays on your machine
- ✅ No personal data: never reads documents, browser history, cookies, passwords
- ✅ User-controlled: you decide what happens with reports
- ✅ Redacted output: usernames, paths, tokens redacted in all reports

**What CEMÍ never collects**:
- Personal documents, photos, videos, media
- Browser history, bookmarks, cookies, saved passwords, autofill data
- Email content or mailboxes
- Chat histories or message content
- Clipboard contents or keystrokes
- Screenshots or screen captures
- Memory dumps or process memory
- Unredacted usernames or home paths
- Unredacted hostnames

See [../privacy.md](../privacy.md) for full privacy policy.

## Status

**Version**: 0.1.0 (pre-alpha)

CEMÍ is in active development. V1 focuses on **metadata-only local audit** with privacy-first design. It is not production-ready but demonstrates production-quality engineering practices: comprehensive testing, honest documentation, and secure design principles.

## Contributing

This is a personal project for portfolio demonstration. For feedback or questions, see the main project repository.

## License

MIT

