# CEMÍ Demo Commands

Copy-paste friendly commands for demonstrating CEMÍ.

## Setup

```bash
# Navigate to CEMÍ directory
cd cemi

# Activate virtual environment
source venv/bin/activate

# Or on Windows:
# .\venv\Scripts\Activate.ps1
```

## Core Demo Commands

### 1. Show Help

```bash
cemi --help
cemi scan --help
cemi privacy --help
cemi monitor --help
cemi history --help
cemi version --help
```

### 2. Privacy Guarantees

```bash
cemi privacy
```

### 3. Run a Scan

```bash
# Interactive (prompts for confirmation)
cemi scan

# Skip prompt
cemi scan --yes

# Generate HTML report
cemi scan --yes --output html

# Generate JSON report
cemi scan --yes --output json

# Both formats
cemi scan --yes --output html
cemi scan --yes --output json
```

### 4. View Reports

```bash
# List generated reports
ls -la reports/

# On Windows:
# Get-ChildItem -Path "reports"

# Open HTML report (macOS)
open reports/$(ls -t reports/cemi_report_*.html | head -1)

# Open HTML report (Linux)
xdg-open reports/$(ls -t reports/cemi_report_*.html | head -1)

# Open HTML report (Windows PowerShell)
# Start (Get-ChildItem -Path "reports\cemi_report_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

### 5. Inspect JSON Report

```bash
# View first 50 lines of JSON
head -50 reports/$(ls -t reports/cemi_report_*.json | head -1)

# Count findings
cat reports/$(ls -t reports/cemi_report_*.json | head -1) | jq '.findings | length'

# List finding titles
cat reports/$(ls -t reports/cemi_report_*.json | head -1) | jq '.findings[].title'

# Show risk summary
cat reports/$(ls -t reports/cemi_report_*.json | head -1) | jq '.risk_summary'

# On Windows PowerShell:
# $report = Get-ChildItem -Path "reports\cemi_report_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
# $data = Get-Content $report.FullName | ConvertFrom-Json
# $data.findings | Select-Object -First 5
```

### 6. Check for Redaction

```bash
# Should find no unredacted username
grep "$(whoami)" reports/* 2>/dev/null || echo "✓ Username redacted"

# Should find no unredacted tokens (example)
grep -E "sk-|ghp_" reports/* 2>/dev/null || echo "✓ Tokens redacted"

# Check HTML report for redaction markers
grep "\[REDACTED\]" reports/$(ls -t reports/cemi_report_*.html | head -1)

# On Windows PowerShell:
# $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
# Select-String -Path "reports\*" -Pattern $username | Measure-Object
```

### 7. Run Monitor Mode

```bash
# Quick demo: 3 scans with 10-second intervals
cemi monitor --yes --interval 10 --iterations 3

# Longer demo: 5 scans with 60-second intervals
cemi monitor --yes --interval 60 --iterations 5

# Check generated history
ls -la .cemi/history/

# View history summary
cemi history

# On Windows:
# Get-ChildItem -Path ".cemi\history"
# cemi history
```

### 8. Run Tests

```bash
# All tests
pytest -q

# Verbose
pytest -v

# Specific test file
pytest tests/test_cli.py -v

# Specific test
pytest tests/test_cli.py::TestOutputFormat::test_output_html_accepted -v

# With coverage (if coverage installed)
pytest --cov=cemi/src/cemi tests/
```

## Quick Demo (10 minutes)

```bash
# 1. Show help
cemi --help

# 2. Show privacy
cemi privacy

# 3. Run scan
cemi scan --yes

# 4. Generate reports
cemi scan --yes --output html
cemi scan --yes --output json

# 5. Open HTML report
open reports/$(ls -t reports/cemi_report_*.html | head -1)

# 6. Check redaction
grep "\[REDACTED\]" reports/$(ls -t reports/cemi_report_*.html | head -1) | head -3

# 7. Show version
cemi version
```

## Technical Deep Dive (30 minutes)

```bash
# 1. Architecture review
cat docs/architecture.md

# 2. Threat model
cat docs/threat_model/README.md

# 3. Run tests with output
pytest -v --tb=short

# 4. Run scan with monitoring
cemi monitor --yes --interval 20 --iterations 2

# 5. View history
cemi history

# 6. Inspect redaction
head -200 reports/$(ls -t reports/cemi_report_*.json | head -1) | jq '.' | less

# 7. Show privacy guarantees
cemi privacy

# 8. Check clean slate
git status
git status --ignored
```

## Troubleshooting Demo Commands

### "Command not found: cemi"

```bash
# Verify venv is activated
which python
python -c "import sys; print(sys.prefix)"

# Reinstall
pip install -e .
```

### "No reports found"

```bash
# Check current directory
pwd

# List reports
ls -la reports/

# Run scan
cemi scan --yes
```

### "No history found"

```bash
# Run monitor mode
cemi monitor --yes --interval 5 --iterations 2

# Check history directory
ls -la .cemi/history/

# View history
cemi history
```

### JSON parsing errors

```bash
# Validate JSON
python3 -m json.tool reports/$(ls -t reports/cemi_report_*.json | head -1) > /dev/null && echo "Valid JSON" || echo "Invalid JSON"

# Pretty-print
python3 -m json.tool reports/$(ls -t reports/cemi_report_*.json | head -1) | less
```

## Environment Verification

```bash
# Check Python version
python --version

# Check CEMÍ version
cemi version

# Check installed packages
pip list | grep cemi

# Check package location
pip show cemi

# Check entry point
which cemi
```

## Cleanup

```bash
# Remove generated reports
rm -rf reports/*

# Remove monitor history
rm -rf .cemi/

# Verify git status
git status
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `cemi --help` | Show all commands |
| `cemi privacy` | Show privacy guarantees |
| `cemi scan --yes` | Run scan, skip prompt |
| `cemi scan --yes --output html` | Generate HTML report |
| `cemi scan --yes --output json` | Generate JSON report |
| `cemi monitor --yes --interval 60 --iterations 5` | Run 5 scans at 60-sec intervals |
| `cemi history` | Show history summary |
| `cemi version` | Show version |
| `pytest -q` | Run all tests |
| `pytest -v tests/test_cli.py` | Run CLI tests verbosely |

## Notes

- Commands are bash-compatible; adjust for Windows PowerShell as needed
- Replace `$(ls -t reports/cemi_report_*.html | head -1)` with your report path
- All commands are read-only (no system modifications)
- Reports are generated in `reports/` (git-ignored)
- History is saved in `.cemi/history/` (git-ignored)
