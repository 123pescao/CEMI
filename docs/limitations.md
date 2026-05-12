# CEMÍ Limitations

This document describes what CEMÍ does **not** do, **cannot** do by design, and what it should **never** be used for.

## What CEMÍ Is Not

### Not an Antivirus

CEMÍ is **not** antivirus software. It does not:

- Scan files for known malware signatures
- Quarantine or delete files
- Clean infected systems
- Provide active protection
- Make definitive malware/benign classification

**Use case**: Use Windows Defender, ESET, Kaspersky, or trusted antivirus for active protection.

### Not an EDR (Endpoint Detection and Response)

CEMÍ is **not** an enterprise security tool. It does not:

- Provide centralized management
- Integrate with SIEM systems
- Offer incident response automation
- Correlate with network-wide threats
- Provide forensic investigation tools

**Use case**: Use enterprise EDR (CrowdStrike, Microsoft Defender for Endpoint, SentinelOne) for managed security.

### Not a Forensic Analysis Tool

CEMÍ is **not** designed for forensic investigation. It does not:

- Preserve evidence chains
- Record timing or state changes over time (beyond monitor snapshots)
- Provide audit logs or legal-grade reporting
- Analyze disk images or memory dumps
- Perform timeline reconstruction

**Use case**: Use professional forensics tools (EnCase, FTK, Volatility) for investigations.

### Not a Malware Removal Tool

CEMÍ is **not** designed to fix infections. It does not:

- Remove malware automatically
- Disable compromised services
- Delete suspicious files
- Restore system files
- Reverse malware changes

**Use case**: If infection is suspected, use dedicated removal tools or professional help.

## What CEMÍ Cannot Detect

CEMÍ **cannot confirm** and **will not attempt** to detect:

- **Active malware execution**: CEMÍ does not scan memory or monitor process behavior at runtime
- **Rootkits or kernel-level compromises**: CEMÍ does not access kernel mode or protected system areas
- **Encrypted or obfuscated payloads**: CEMÍ does not analyze file contents or attempt decryption
- **Zero-day exploits**: CEMÍ uses pattern-based detection only (no vulnerability scanning)
- **Network-based attacks**: CEMÍ does not capture packets or analyze network traffic payloads
- **Browser history theft**: CEMÍ does not access browser history, saved passwords, or cookies
- **Keylogging or input monitoring**: CEMÍ does not monitor keyboard/mouse events
- **Credential extraction**: CEMÍ does not inspect credential storage
- **File-level encryption (ransomware)**: CEMÍ does not scan file contents or detect encryption patterns

## What CEMÍ Never Collects

By design, CEMÍ **never** accesses:

- **Personal documents**: No scanning of Documents, Pictures, Videos, Desktop, Downloads
- **Browser data**: No history, bookmarks, cookies, autofill, session data, saved passwords
- **Email content**: No mailbox scanning, no message reading
- **Chat or messaging data**: No Slack, Teams, Discord, WhatsApp, Signal inspection
- **Clipboard contents**: CEMÍ does not inspect clipboard
- **Keystroke data**: CEMÍ does not log input
- **Screenshots or screen captures**: CEMÍ does not capture display
- **Memory dumps**: CEMÍ does not inspect process memory
- **Arbitrary file contents**: CEMÍ does not read file data (metadata only)
- **Unredacted paths**: Usernames and home directories are redacted before storage
- **Unredacted hostnames**: Hostnames are stored only as SHA-256 digest

## Platform Limitations

### Windows-Only Features

The following collectors are **Windows-only** and will be skipped on Linux/macOS:

- `StartupCollector` (Run/RunOnce/startup folders)
- `ScheduledTasksCollector` (Task Scheduler)
- `ServicesCollector` (Windows Services)

On Linux/macOS, these collectors will report:
```
"skipped_reason": "Not applicable on non-Windows platform"
```

### Limited Cross-Platform Support

On Linux/macOS:
- `ProcessesCollector` and `NetworkConnectionsCollector` provide basic functionality but may miss Windows-specific context
- Registry-based detections are skipped
- File permission analysis is limited

**Recommendation**: For comprehensive security analysis, use CEMÍ on native Windows. WSL/Linux usage is supported for testing and light audits only.

## Data Collection Limitations

### Point-in-Time Snapshots

- **Processes**: CEMÍ captures the state of running processes at scan time. Processes started/stopped after the scan are not visible.
- **Network connections**: Connection state is captured at scan time. Connections that existed before or after are not visible.
- **Services/tasks/startup**: Configuration is current; historical changes are not recorded.

**Implication**: CEMÍ does not provide **behavior monitoring**. It provides **configuration snapshots**.

### No Persistence Across Reboots

- Monitor history is stored in `.cemi/history/` locally
- No cloud sync or backup
- History is lost if the directory is deleted
- No backup or recovery mechanism

**Recommendation**: Backup `.cemi/` directory if history is important.

### No Real-Time Alerting

CEMÍ does not:
- Monitor for changes and alert in real-time
- Provide immediate notification of new findings
- Watch for system changes and report them continuously

Run `cemi monitor` for repeated scans over time; do not rely on CEMÍ for real-time threat detection.

## Report Limitations

### Metadata-Based Assessment Only

Reports describe **system configuration**, not **actual threats**:

- A finding indicates a **pattern** or **configuration concern**, not definitive malware
- Absence of findings does not prove the system is clean
- Many findings may be legitimate (user choice, development tools, organizational software)

### No Context-Aware Analysis

CEMÍ does not:
- Know your threat model or risk tolerance
- Understand your organization's policies
- Distinguish between user-intentional and malicious changes
- Provide personalized recommendations

### Redaction Means Limited Detail

To preserve privacy, reports redact:
- Usernames (necessary for privacy)
- Certain paths (necessary for privacy)
- Long opaque strings that might be credentials (necessary for privacy)

**Tradeoff**: Reports are privacy-safe but may lack implementation details needed for manual analysis.

## Accuracy and False Positives

### Rule-Based Detection

CEMÍ uses rules to detect patterns. Like all pattern-based systems:
- **False positives**: Legitimate software may match suspicious patterns
- **False negatives**: Sophisticated malware may evade pattern detection
- **No confidence guarantee**: CEMÍ cannot rate its own accuracy

**Recommendation**: Review CEMÍ findings in context using trusted tools (Autoruns, Task Scheduler, Services, Defender) before acting.

### No Machine Learning or Adaptive Detection

CEMÍ uses **deterministic rules only**. It does not:
- Learn from past scans
- Adapt to your system
- Use machine learning models
- Improve accuracy over time

Rules are maintained manually and updated through releases.

## Offline and No Reputation Lookups

CEMÍ does **not** query:
- VirusTotal
- Windows Defender cloud service
- Hash reputation databases
- Domain reputation services
- Executable signature databases

**Implication**: CEMÍ cannot verify the reputation of installed software. Use external tools for reputation checks.

## No Active Remediation

CEMÍ does **not**:
- Disable services automatically
- Remove startup entries automatically
- Uninstall software automatically
- Modify registry automatically
- Delete files automatically
- Kill processes automatically

**All remediation is manual and user-initiated.**

## Integration Model Limitations

CEMÍ is a **standalone tool**. It does not:
- Integrate with Windows Defender, antivirus, or EDR
- Export data to SIEM systems
- Sync with mobile device management
- Provide API for third-party tools
- Offer plugins or extensions

## What You Should Do Instead

If you need:

- **Active malware protection**: Use Windows Defender, ESET, Kaspersky, Bitdefender
- **Enterprise security**: Use EDR like CrowdStrike or Microsoft Defender for Endpoint
- **Incident response**: Use incident response services or professional security team
- **Forensic analysis**: Use forensics software or professional forensics team
- **Penetration testing**: Use professional penetration testers
- **Vulnerability scanning**: Use vulnerability scanners (Nessus, Qualys, OpenVAS)
- **Network security**: Use network IDS/IPS, firewalls, network monitoring
- **Endpoint hardening**: Use configuration management and policy enforcement tools

## Honest Limitations Statement

**CEMÍ is not a "security solution".**

CEMÍ is a **local audit and awareness tool** that helps users understand their system configuration. It is designed to:

1. **Raise awareness** about installed software and system settings
2. **Surface patterns** that warrant manual review
3. **Encourage verification** using trusted tools
4. **Support informed decision-making** by the user

CEMÍ works best **alongside**:

- Operating system security (Windows Update, Windows Defender, Windows Firewall)
- User security practices (strong passwords, two-factor authentication, careful download practices)
- Trusted antivirus or EDR
- Regular backups
- Network security measures

## See Also

- [threat_model/README.md](threat_model/README.md) — Threat model and scope
- [safe_report_sharing.md](safe_report_sharing.md) — How to safely share reports
- [../README.md](../README.md) — Main documentation
