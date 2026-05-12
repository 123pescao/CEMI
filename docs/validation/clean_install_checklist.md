# Clean Install Checklist

This checklist verifies that CEMÍ installs and runs correctly from a clean checkout. Use this before each release.

## Prerequisites

- [ ] Fresh checkout or clean directory
- [ ] Python 3.11 or 3.12 installed
- [ ] No existing CEMÍ venv or installation

## Installation (Linux/macOS/WSL)

```bash
# Navigate to cemi directory
cd cemi

# Create fresh virtual environment
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install editable with dev dependencies
pip install -e .[dev]
```

- [ ] Command completes without errors
- [ ] `pip list` shows `cemi 0.1.0` with status "editable"
- [ ] `which cemi` or `command -v cemi` shows path in venv

## Installation (Windows PowerShell)

```powershell
# Navigate to cemi directory
cd cemi

# Create fresh virtual environment
python -m venv venv

# Activate venv
.\venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install editable with dev dependencies
pip install -e .[dev]
```

- [ ] Command completes without errors
- [ ] `pip list` shows `cemi 0.1.0` with status "editable"
- [ ] `cemi` command is available in PowerShell

## CLI Commands

```bash
# Help
cemi --help

# Privacy
cemi privacy

# Scan help
cemi scan --help

# Monitor help
cemi monitor --help

# History help
cemi history --help

# Version
cemi version
```

- [ ] `cemi --help` shows all commands
- [ ] `cemi privacy` prints privacy guarantees
- [ ] `cemi scan --help` shows output options
- [ ] `cemi monitor --help` shows interval/iterations
- [ ] `cemi history --help` shows history directory option
- [ ] `cemi version` prints version

## Test Suite

```bash
# Run tests with summary
pytest -q

# Run tests with verbose output (optional)
pytest -v

# Run specific test file (optional)
pytest tests/test_cli.py -v
```

- [ ] All tests pass (should see "796 passed, 2 skipped")
- [ ] No test errors or warnings
- [ ] Test output is deterministic (same result on rerun)

## Scan Execution

### Basic Scan

```bash
# Run scan with privacy confirmation skipped
cemi scan --yes --output html
```

- [ ] Command completes without error
- [ ] Output includes "Scan complete"
- [ ] Output includes "Risk Summary"
- [ ] Output includes "Collectors" summary
- [ ] Report is created in `reports/` directory
- [ ] Report filename matches pattern `cemi_report_*.html`

### JSON Scan

```bash
cemi scan --yes --output json
```

- [ ] Command completes without error
- [ ] Report is created in `reports/` directory
- [ ] Report filename matches pattern `cemi_report_*.json`
- [ ] `file reports/cemi_report_*.json` shows JSON type

### Report Content Validation

```bash
# For HTML report
grep -i "risk score" reports/cemi_report_*.html | head -1

# For JSON report
python3 -c "import json; data = json.load(open($(ls -t reports/cemi_report_*.json | head -1))); print(f\"Risk score: {data['risk_summary']['score']}\")"
```

- [ ] HTML report contains "Risk score"
- [ ] HTML report contains "Risk level"
- [ ] JSON report is valid JSON
- [ ] JSON report contains `risk_summary` with `score` and `level`
- [ ] JSON report contains `findings` array
- [ ] JSON report contains `collector_health` array

### Privacy Validation (CRITICAL)

```bash
# Check for unredacted usernames (should find nothing)
grep -r $(whoami) reports/ || echo "No unredacted username found"

# Check for unredacted home paths (should find nothing)
grep -r $(pwd | sed 's|.*/||') reports/ || echo "No home path found"

# Check for common tokens (should only see redacted markers)
grep -E "sk-|ghp_|Bearer " reports/ || echo "No unredacted tokens found"
```

- [ ] No unredacted usernames in reports
- [ ] No unredacted home directory paths in reports
- [ ] No unredacted API keys or tokens
- [ ] Only `[REDACTED]` and `[REDACTED_TOKEN]` markers appear for sensitive data

## Monitor Mode (Optional)

```bash
# Run 2 quick scans
cemi monitor --yes --interval 5 --iterations 2
```

- [ ] First iteration completes
- [ ] Second iteration completes
- [ ] Output shows "Monitoring complete"
- [ ] History snapshots created in `.cemi/history/`

## Generated Files Tracking

```bash
# Check git status
git status

# Check ignored files
git status --ignored --short | grep -E "reports|\.cemi|\.venv" | head -10
```

- [ ] `reports/` directory is ignored (shown in `git status --ignored`)
- [ ] `.cemi/` directory is ignored
- [ ] `.venv/` directory is ignored
- [ ] Generated files are not staged for commit

## Clean Slate Verification

```bash
# Ensure no artifacts remain outside ignored paths
find . -name "*.pyc" -o -name "__pycache__" | wc -l
```

- [ ] Compiled Python files are not tracked
- [ ] Cache directories are not tracked
- [ ] Only source files and documentation are committed

## Cleanup

```bash
# Deactivate venv
deactivate

# Optional: Remove venv for fresh install next time
rm -rf venv
```

- [ ] venv can be cleanly removed
- [ ] Fresh install is possible without conflicts

## Notes for Future Releases

- If any step fails, document the error and update the checklist
- If new commands are added, add them to the CLI Commands section
- If test count changes, update the expected test count
- If new collectors are added, verify they skip/run appropriately on this platform

## Sign-Off

- [ ] All items checked
- [ ] All tests pass
- [ ] No errors or warnings
- [ ] Ready for release

**Date**: _______________
**Platform**: Linux [ ] | macOS [ ] | Windows [ ] | WSL [ ]
**Python Version**: _______________
**Tester Name**: _______________
