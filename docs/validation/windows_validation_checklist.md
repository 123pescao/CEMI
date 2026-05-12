# Windows Validation Checklist

This checklist is for **native Windows testing only**. It verifies that CEMÍ runs correctly on Windows and detects expected findings.

**Important**: Complete [clean_install_checklist.md](clean_install_checklist.md) first. This checklist assumes a clean install on native Windows.

## Prerequisites

- [ ] Native Windows OS (not WSL/Linux)
- [ ] Windows 10 21H2 or later, or Windows 11
- [ ] Python 3.11 or 3.12 (native, not WSL)
- [ ] PowerShell 5.1 or later (or use cmd.exe)
- [ ] Admin access (optional, needed to inspect some system areas)
- [ ] CEMÍ clean install completed

## Environment Verification

```powershell
# Verify Windows
[System.Environment]::OSVersion

# Verify Python version
python --version

# Verify CEMÍ installation
cemi version
```

- [ ] Windows version is 10 or 11
- [ ] Python version is 3.11 or later
- [ ] CEMÍ version shows 0.1.0

## Scan Execution

### Run Scan with All Collectors

```powershell
# Navigate to CEMÍ directory
cd cemi

# Run scan
cemi scan --yes --output html
```

- [ ] Scan completes without error
- [ ] Output shows "Scan complete"
- [ ] No collector exceptions in output

### Check Collector Health

```powershell
# Generate JSON report for inspection
cemi scan --yes --output json

# View report in PowerShell (inspect collector_health section)
$report = Get-ChildItem -Path "reports\cemi_report_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$data = Get-Content $report.FullName | ConvertFrom-Json
$data.collector_health | Format-Table -AutoSize
```

- [ ] `installed_apps` collector status: `ran_successfully=true` (Windows-native)
- [ ] `services` collector status: `ran_successfully=true` (Windows-native)
- [ ] `startup` collector status: `ran_successfully=true` (Windows-native)
- [ ] `scheduled_tasks` collector status: `ran_successfully=true` (Windows-native)
- [ ] `browser_extensions` collector: `ran_successfully=true` or `skipped_reason` if no browser
- [ ] `native_messaging_hosts` collector: `ran_successfully=true` or `skipped_reason`
- [ ] `processes` collector status: `ran_successfully=true`
- [ ] `network_connections` collector status: `ran_successfully=true`
- [ ] `signatures` collector: `skipped_reason="Signature verification deferred..."`

### Verify Expected Findings

At least one of the following should be detected on a typical Windows system:

```powershell
# View JSON report findings
$data = Get-Content $report.FullName | ConvertFrom-Json
$data.findings | Select-Object -First 5 | Format-Table -AutoSize title, severity, category
```

- [ ] Findings array is not empty (expect 5-50+ findings on typical system)
- [ ] At least one `Persistence` category finding
- [ ] At least one `Service` or `Browser` category finding
- [ ] Risk score is > 0

## Windows-Specific Validation

### Startup Entries

CEMÍ should detect startup entries from:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

```powershell
# Check known startup entries exist
$startupRun = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($startupRun) {
    Write-Output "Found $(($startupRun | Measure-Object).Count) startup entries"
}

# Run scan and check if any are reported
cemi scan --yes --output json
```

- [ ] At least one startup entry finding detected
- [ ] Findings include commonly-present software (e.g., antivirus, cloud sync, etc.)

### Services

CEMÍ should detect Windows services:

```powershell
# Count total services
$services = Get-Service | Measure-Object
Write-Output "Total services: $($services.Count)"

# Run scan and check
cemi scan --yes --output json
```

- [ ] Services collector reports >50 items_collected
- [ ] No services collector errors

### Scheduled Tasks

CEMÍ should detect scheduled tasks:

```powershell
# Check if tasks exist
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Measure-Object
Write-Output "Total tasks: $($tasks.Count)"

# Run scan and check
cemi scan --yes --output json
```

- [ ] Scheduled tasks collector reports items_collected
- [ ] No scheduled tasks collector errors

### Processes

```powershell
# Check running processes
Get-Process | Measure-Object
```

- [ ] Processes collector reports items_collected > 20
- [ ] No process collector errors

### Network Connections

```powershell
# Check listening ports
netstat -ano -p TCP | Measure-Object
```

- [ ] Network connections collector reports some listening ports
- [ ] No network collector errors

## Browser Extension Detection (if applicable)

If Chrome, Edge, or Firefox is installed:

```powershell
# Check if extensions are detected
cemi scan --yes --output json
$data = Get-Content (Get-ChildItem -Path "reports\cemi_report_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName | ConvertFrom-Json
$data.findings | Where-Object { $_.category -eq "Browser" } | Format-Table title, severity
```

- [ ] At least one browser extension finding detected
- [ ] Browser extensions collector ran without error

## Privacy Redaction Validation (CRITICAL)

### Check for Unredacted Data

```powershell
# Get current username
$username = $env:USERNAME
$computername = $env:COMPUTERNAME

# Get latest report
$report = Get-ChildItem -Path "reports\cemi_report_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$data = Get-Content $report.FullName | ConvertFrom-Json
$reportJson = $report.FullName | Get-Content

# Check for unredacted username
if ($reportJson -match [regex]::Escape($username)) {
    Write-Warning "FOUND UNREDACTED USERNAME: $username"
} else {
    Write-Output "✓ Username redacted"
}

# Check for unredacted computer name
if ($reportJson -match [regex]::Escape($computername)) {
    Write-Warning "FOUND UNREDACTED COMPUTER NAME: $computername"
} else {
    Write-Output "✓ Computer name redacted"
}

# Check for unredacted paths
$userPath = $env:USERPROFILE
if ($reportJson -match [regex]::Escape($userPath)) {
    Write-Warning "FOUND UNREDACTED USER PATH"
} else {
    Write-Output "✓ User paths redacted"
}
```

- [ ] No unredacted username in report
- [ ] No unredacted computer name in report
- [ ] No unredacted user profile paths in report
- [ ] All paths show `[REDACTED]` markers

### Check for Redacted Secrets

```powershell
# Check for common token patterns (should find none, only [REDACTED_TOKEN])
$report | Get-Content | Select-String -Pattern "sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|Bearer [A-Za-z0-9]" -ErrorAction SilentlyContinue
if ($?) {
    Write-Warning "FOUND POTENTIAL UNREDACTED TOKEN"
} else {
    Write-Output "✓ Tokens redacted"
}
```

- [ ] No unredacted API keys or tokens in report

## Report Handling

```powershell
# Verify reports are in reports directory
Get-ChildItem -Path "reports\cemi_report_*" -File | Format-Table Name, Length, CreationTime
```

- [ ] HTML and JSON reports exist in `reports/` directory
- [ ] Reports are not tracked by git

```powershell
# Verify git ignores reports
git status --ignored --short | findstr /I "reports" | head -5
```

- [ ] `reports/` directory is ignored by git

## Monitor Mode (Optional Windows Test)

```powershell
# Run 3 quick scans to populate history
cemi monitor --yes --interval 10 --iterations 3

# View history
cemi history
```

- [ ] All iterations complete
- [ ] History snapshots created in `.cemi\history\`
- [ ] History summary shows multiple snapshots
- [ ] No errors during monitoring

## Performance Baseline

```powershell
# Time the scan
Measure-Command { cemi scan --yes --output html }
```

- [ ] Scan completes in < 30 seconds (typical)
- [ ] No timeouts or hangs

## Stability

Run the scan multiple times to verify deterministic behavior:

```powershell
for ($i = 1; $i -le 3; $i++) {
    Write-Output "Run $i"
    cemi scan --yes --output json | Out-Null
}

# Verify reports are similar
Get-ChildItem -Path "reports\cemi_report_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object {
    Write-Output $_.Name
}
```

- [ ] All runs complete successfully
- [ ] No random crashes or hangs
- [ ] Risk scores are stable across runs (within 5 points)

## Known Findings to Expect

On a typical Windows 10/11 system, CEMÍ might detect:

- **Browser extensions**: Common extensions (ad blockers, password managers, etc.)
- **Startup entries**: Antivirus, cloud sync, system utilities
- **Services**: Windows services in normal locations (low-risk)
- **Scheduled tasks**: Windows Update, antivirus scans, backup tasks
- **Process patterns**: Common system processes (if PowerShell/LOLBins detected)

**None of these are red flags by themselves** — CEMÍ reports patterns for user review.

## Admin vs. Non-Admin

CEMÍ should work as non-admin user:

```powershell
# Run as regular user (non-admin)
cemi scan --yes --output html
```

- [ ] Scan completes without permission errors
- [ ] Collectors gracefully skip protected areas
- [ ] Report generates normally

Optional: Run as admin to see if additional data is available:

```powershell
# Note: Run this in admin PowerShell
cemi scan --yes --output html
```

- [ ] Admin scan completes
- [ ] More service/process details may be available
- [ ] No privilege escalation attempts

## Cleanup

```powershell
# Remove test reports if desired
Remove-Item -Path "reports\cemi_report_*" -Force

# Remove monitor history if desired
Remove-Item -Path ".cemi" -Recurse -Force

# Verify gitignore works
git status
```

- [ ] Generated files are cleaned up
- [ ] git status shows no uncommitted changes

## Known Limitations on Windows

- [ ] Signature verification is deferred (expected `skipped_reason`)
- [ ] WMI persistence detection not implemented in V1
- [ ] No IFEO/AppInit_DLLs detection in V1
- [ ] Process/network data is point-in-time only

## Sign-Off

- [ ] All tests passed
- [ ] All collectors ran or skipped appropriately
- [ ] All privacy redactions verified
- [ ] Reports generated correctly
- [ ] No errors or crashes
- [ ] Ready for Windows deployment

**Date**: _______________
**Windows Version**: _______________
**Python Version**: _______________
**Admin Access**: Yes [ ] | No [ ]
**Browser Installed**: Chrome [ ] | Edge [ ] | Firefox [ ] | None [ ]
**Tester Name**: _______________
**Notes**: _______________
