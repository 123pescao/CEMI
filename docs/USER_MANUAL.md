# CEMÍ User Manual

## What CEMÍ Is

CEMÍ is a local-first security audit tool for desktop systems. It inspects system metadata and configuration to surface suspicious activity and privacy risks without reading documents, browser history, cookies, or other personal content.

CEMÍ is:
- read-only and non-destructive
- local-only: no uploads, telemetry, or cloud lookups
- privacy-first: sensitive strings, usernames, and paths are redacted in reports
- metadata-only: it analyzes configuration, process metadata, startup entries, browser extensions, and network state

CEMÍ is not:
- antivirus, EDR, or malware removal
- a forensic chain-of-custody tool
- a browser data or file content scanner

## Supported Platforms

CEMÍ is designed for Windows. On Linux and WSL, it can still run, but several Windows-specific collectors will be skipped or produce limited results.

If you run CEMÍ on a non-Windows host, it will warn you and continue gracefully.

## Installation

### Prerequisites

- Python 3.11 or newer
- `pip`

### Install locally

From the `cemi/` directory:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev]
```

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .[dev]
```

### Run without installing the console script

If `cemi` is not on your `PATH`, you can run the package directly:

```bash
python -m cemi.main scan --yes
```

## CLI Overview

CEMÍ exposes these primary commands:

- `cemi scan` — run a single local scan and save a report
- `cemi monitor` — run repeated scans over time and store timeline snapshots
- `cemi history` — display a summary of monitor snapshots
- `cemi privacy` — print CEMÍ privacy guarantees and exit
- `cemi version` — print the installed CEMÍ version

> Run `cemi --help` to see the current available options and commands.

## Privacy Confirmation

By default, `scan` and `monitor` prompt for consent before any scan begins. This prompt can be skipped with `--yes`.

Example:

```bash
cemi scan --yes
```

## Scan Command

Use `scan` to inspect the local system and write a report to `reports/`.

```bash
cemi scan
```

### Output formats

- `--output html` (default)
- `--output json`

### Examples

```bash
cemi scan --yes
cemi scan --yes --output html
cemi scan --yes --output json
```

### Report files

Reports are saved under the local `reports/` directory.

- HTML reports are named `cemi_report_<scan_id>.html`
- JSON reports are named `cemi_report_<scan_id>.json`

If a file with the same name already exists, CEMÍ will append a numeric suffix.

## Monitor Command

`monitor` runs scans repeatedly and records a local history of snapshots.

```bash
cemi monitor --yes --interval 60 --iterations 5
```

Options:

- `--interval <seconds>` — seconds between scans (default: 60)
- `--iterations <N>` — number of scans to run
- `--output <html|json>` — save a final report after monitoring completes
- `--yes` — skip the privacy confirmation prompt

### Notes

- Monitor mode stores snapshot data in `.cemi/history/` relative to the current working directory.
- The `--output` option only affects a final scan report after monitoring completes.
- Press `Ctrl+C` to stop monitoring early.

## History Command

`history` summarizes previously saved monitor snapshots.

```bash
cemi history
```

Options:

- `--history-dir <path>` — use a custom history directory instead of `.cemi/history`

## Privacy Command

`privacy` prints CEMÍ's privacy guarantees and exits. It performs no scan.

```bash
cemi privacy
```

## What CEMÍ Collects and Analyzes

CEMÍ inspects local system metadata and runtime state using the following collectors:

- Installed applications
- Running services
- Native messaging hosts
- Browser extensions
- Startup entries
- Scheduled tasks
- Running processes
- Network connections
- Code signature and trust metadata

## What CEMÍ Detects

CEMÍ looks for signals commonly associated with malware, spyware, persistence, and privacy risk, including:

- suspicious startup and persistence entries
- services running from user-writable or unusual paths
- browser extensions with broad permissions or active native messaging bridges
- suspicious process command lines and located binaries
- active network connections and external listening ports
- correlations between persistence and network activity

## Report Safety and Redaction

CEMÍ is designed to keep sensitive details private:

- report files are saved only on the local machine
- no report data is uploaded automatically
- JSON output is sanitized before writing
- path values and command strings are redacted where appropriate
- labels such as `exe_path`, `command`, `cmdline`, and `command_line` are rewritten in JSON output to indicate redaction

### Safe report handling

Treat generated reports as sensitive data. Do not commit them to version control. Review report content before sharing with anyone.

## Windows and Non-Windows Behavior

CEMÍ is optimized for Windows. On non-Windows platforms:

- some collectors may be skipped
- scan results may be incomplete
- CEMÍ still runs, but the tool is not guaranteed to detect Windows-specific threats

## Troubleshooting

### No output or prompt

If the tool stops after showing the privacy notice, answer `y` to continue or rerun with `--yes`.

### Report not generated

Check that the current working directory is writable and that a `reports/` directory can be created.

### Monitoring history missing

If `.cemi/history/` is empty, run `cemi monitor --yes --interval 60 --iterations 1` first.

## Development and Testing

From the `cemi/` package root, run:

```bash
pytest
```

The project uses `pytest` for unit and integration tests.

## Related Documentation

- `docs/limitations.md` — What CEMÍ does not do
- `docs/threat_model/README.md` — Threat model and scope
- `docs/safe_report_sharing.md` — Guidance for sharing reports safely
- `docs/architecture.md` — System architecture and collector design
