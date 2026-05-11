# Threat Coverage Matrix — CEMÍ

## Purpose

This document defines what CEMÍ can safely detect now, what it could safely detect in V2, what it should only explain through manual guidance, and what it should never collect or attempt. It serves as a planning guide for future development and a boundary document for security reviewers.

## CEMÍ Positioning Statement

CEMÍ does not confirm malware, spyware, trojans, or intrusions. It detects local behaviors and configurations commonly associated with those threats and explains what the user should review.

CEMÍ core remains read-only. Automatic removal is out of scope for V1 and V2.

## What CEMÍ Detects

CEMÍ detects suspicious local behaviors and configurations commonly associated with malware-like, spyware-like, trojan-like, intruder-like, data-exfiltration, defense-evasion, ransomware-like, and persistence activity. All detection is based on metadata collection only — no file content inspection, no execution, no network calls.

Current V1 coverage includes:
- Installed apps metadata (names, versions, publishers)
- Windows services metadata (status, configuration, user paths)
- Startup entries (Run, RunOnce, StartupApproved, startup folders)
- Scheduled task metadata (commands, triggers)
- Browser extension manifest permissions (cookies, all URLs, scripting, webRequest)
- Native messaging hosts (bridge capabilities)
- Browser-to-native bridge correlations
- Process metadata (command lines, redacted)
- Network connection metadata (local/remote addresses, ports, process names)
- Suspicious PowerShell startup/task commands
- LOLBin startup/task commands
- Signature/file trust checks are intentionally skipped in V1 until a safe raw-path isolation architecture is designed
- Service binaries in user paths
- Correlation engine for signal quality scoring
- Risk scoring and HTML/JSON reports

## What CEMÍ Does Not Detect

CEMÍ does not detect:
- Active malware execution or memory-resident threats
- Rootkits or kernel-level compromises
- Encrypted or obfuscated payloads
- Zero-day exploits
- Network-based attacks or intrusions
- Browser history or cookie theft
- Credential extraction or keylogging
- File content analysis or hashing
- Cloud reputation lookups
- Packet capture or traffic analysis

## What CEMÍ Must Never Collect

CEMÍ must never collect:
- Packet payloads or network traffic content
- Browser history, bookmarks, or cookies
- Saved passwords or autofill data
- Personal documents or user-authored content
- Clipboard contents or keystrokes
- Screenshots or desktop captures
- Memory dumps or process memory
- File contents or arbitrary file hashing
- Raw executable paths (unredacted)
- Usernames or home directory paths (unredacted)
- Hostnames (unredacted)
- Telemetry or usage data
- Any data that could identify the user

## Threat Coverage Matrix

| Threat Family | Common Patterns | Current CEMÍ Coverage | Safe V2 Additions | Do Not Collect | Safe Guidance | False Positive Risk | Privacy Risk | Tests Needed |
|---------------|-----------------|-----------------------|-------------------|---------------|---------------|---------------------|--------------|-------------|
| Persistence | Auto-start mechanisms, scheduled tasks, services, startup folders, Run/RunOnce keys, StartupApproved registry | Startup entries, scheduled tasks, services with user paths, RunOnce persistence, suspicious PowerShell/LOLBin commands | WMI persistence metadata (read-only), IFEO hijack detection, AppInit_DLLs detection, Winlogon shell/userinit checks, service binary path anomaly rules, startup .lnk target resolution | Raw executable paths, file execution, arbitrary file access | Check publisher/vendor, review in Windows Settings/Autoruns, scan with trusted antivirus, disable first then reboot | Medium (legitimate software uses persistence) | Low (metadata only, redacted paths) | Synthetic persistence entries, permission error handling, redaction validation |
| Living-off-the-land / LOLBins | System tools abused for malicious purposes (PowerShell, cmd, regsvr32, etc.) | LOLBin commands in startup/tasks | Extended LOLBin pattern matching, command-line anomaly detection | Command execution, file content analysis | Review command parameters, check if expected, monitor for unusual usage patterns | High (administrative scripts are common) | Low (command metadata only) | Known LOLBin patterns, false positive command examples |
| Spyware-like Browser Behavior | Extensions with excessive permissions, native messaging bridges, data collection capabilities | Extension permissions (cookies, all URLs, scripting, webRequest), native messaging hosts, extension-native correlations | Browser extension manifest analysis for data collection keywords, native host ↔ extension ID mapping, bridge graph visualization | Browser history, cookies, saved data, extension execution | Review extension permissions in browser settings, check publisher, disable or uninstall through browser UI if suspicious | Medium (some extensions legitimately need broad permissions) | Low (permission metadata only) | Permission combinations, correlation scenarios |
| Trojan-like Behavior | Unknown executables in suspicious locations, service anomalies, process anomalies | Services with user paths, suspicious startup/task commands, process metadata patterns | Service binary path validation, process command-line anomaly patterns | File execution, arbitrary hashing, reputation lookups | Verify publisher, scan with trusted tools, check file location legitimacy | Medium (user-installed software is common) | Low (metadata only) | Suspicious path scenarios, service/startup/process pattern matching |
| Data-exfiltration Risk | Network connections from suspicious processes, unusual outbound traffic patterns | Network connection metadata by process | Connection pattern analysis, known exfiltration port detection | Packet capture, payload inspection, traffic analysis | Monitor network activity, check process legitimacy, use firewall rules | High (legitimate software makes network connections) | Low (connection metadata only) | Process-network correlation, port/protocol patterns |
| Credential Theft Risk | Browser extensions with cookie/session access, broad host permissions, scripting permissions, or native messaging bridges | Extension cookie permission, broad host permissions, scripting/webRequest combinations, native messaging bridge metadata | Credential-risk category based on metadata-only capability signals | Saved passwords, credential access, keylogging, browser history, cookies | Review extension permissions, disable or uninstall unknown extensions through browser UI, rotate passwords only if exposure is suspected, use a password manager | Medium (some legitimate extensions need powerful permissions) | Medium (permission metadata can reveal security posture) | Permission combination tests, native bridge correlation tests, no credential data collection tests |
| Intruder / Remote Access Foothold Risk | Suspicious services, open ports, remote access tools | Service configuration anomalies, network listening ports | Remote access tool detection patterns, listening-port context from safe metadata only | Active scanning, vulnerability exploitation | Check service legitimacy, close unnecessary ports, use firewall | Medium (legitimate remote access tools exist) | Low (service/port metadata) | Service pattern matching, safe listening-port metadata tests |
| Defense Evasion | Hidden files, unusual permissions, startup evasion | StartupApproved metadata, user-writable startup/process path indicators | Permission anomaly detection, hidden file metadata | File system crawling, permission modification | Check file properties, review permissions, scan with trusted tools | Medium (system hardening practices vary) | Low (permission metadata) | Permission pattern tests, file attribute checks |
| Ransomware Precursor Behavior | File encryption tools, backup deletion, unusual file access patterns | N/A (out of scope for metadata-only) | File extension change monitoring (if safe), backup tool detection | File content monitoring, encryption detection | Use ransomware protection, maintain backups, monitor for unusual file changes | N/A | N/A | N/A (deferred) |
| Suspicious Services | Auto-start services, user-path services, unsigned service binaries | Services with user paths, service configuration | Service dependency analysis, service account anomaly detection | Service execution, binary analysis | Check service properties, verify publisher, disable only after careful manual review | Medium (custom services are common) | Low (service metadata) | Service configuration tests, path validation |
| Suspicious Scheduled Tasks | Unusual task commands, hidden tasks, frequent execution | Suspicious PowerShell/LOLBin tasks, task metadata | Task trigger anomaly detection, task author validation | Task execution, command testing | Review task properties, check legitimacy, disable first if suspicious, do not delete first | Medium (automation tasks are common) | Low (task metadata) | Task pattern matching, trigger analysis |
| Suspicious Startup Entries | Unusual startup programs, hidden entries, user-writable locations | Startup entries, Run/RunOnce, startup folders | Startup entry validation, .lnk target resolution | File execution, path traversal | Check startup entries in Task Manager or Autoruns, disable first if suspicious, do not delete first | Medium (user customization is common) | Low (entry metadata) | Startup entry patterns, location validation |
| Native Messaging Bridge Abuse | Browser extensions communicating with native code, excessive bridge permissions | Native messaging hosts, extension-native correlations | Bridge capability mapping, host-extension trust validation | Bridge content, message interception | Review extension and host legitimacy, disable or uninstall through official UI if suspicious | Low (bridges are uncommon) | Low (bridge metadata) | Correlation tests, permission validation |
| Browser Extension Abuse | Malicious extensions, permission abuse, data collection | Extension permissions, manifest analysis | Extension update source validation, extension behavior correlation | Extension execution, browser data access | Disable or uninstall suspicious extensions through browser UI, then check browser security settings | Medium (extension ecosystems vary) | Low (manifest metadata) | Permission analysis, manifest parsing |
| Signature / File Trust Limitations | Unsigned files, unknown publishers, trust bypasses | Honest skip: signature verification is intentionally deferred in V1 until safe raw-path isolation exists | Local-only signature metadata from already-known executable paths, if a safe architecture is designed | Raw file paths, arbitrary file access, reputation services | Use trusted antivirus, verify publishers manually, avoid unknown executables | N/A | Medium if implemented later | Tests must prove no raw paths reach ScanResult, reports, CLI, JSON, HTML, or history |

## V1 Coverage Summary

CEMÍ V1 covers persistence, browser extension risks, service anomalies, and basic network/process metadata. It provides honest skips for capabilities requiring unsafe data collection (signatures). All detection is metadata-only with strict redaction.

## V2 Candidate Coverage

V2 could safely add:
- WMI persistence metadata (read-only)
- IFEO/AppInit_DLLs detection
- Service binary path anomalies
- Startup .lnk resolution
- Extended LOLBin patterns
- Browser extension trust validation
- Native messaging bridge mapping
- Process command anomaly detection
- Network connection pattern analysis
- Local baseline comparison
- Guided remediation instructions

Each V2 addition must:
- Collect only safe metadata
- Apply redaction before storage
- Have comprehensive tests
- Include false positive analysis
- Maintain read-only operation

## Out-of-scope Detections

The following are explicitly out of scope for CEMÍ:
- Active malware confirmation (requires execution/analysis)
- Antivirus replacement (requires signatures/reputation)
- EDR replacement (requires real-time monitoring)
- Packet capture/traffic analysis (invasive, privacy-violating)
- Memory forensics (requires dumps, complex analysis)
- Browser history/cookie scanning (privacy-violating)
- Personal document scanning (privacy-violating)
- Cloud hash lookups (requires network, external dependency)
- File quarantine/deletion (destructive, requires admin)
- Automatic threat removal (destructive, high false positive risk)
- Credential extraction (privacy-violating, security risk)
- Intrusion attribution (requires network forensics)
- Rootkit detection (requires kernel access)
- Full forensic investigation (requires destructive analysis)

These are out of scope because they either violate privacy boundaries, require destructive operations, or demand capabilities beyond local metadata inspection.

## Safe Remediation Model

CEMÍ provides guidance only. Automatic remediation is out of scope.

### Explain
- What CEMÍ found
- Why it may matter
- Why it may also be legitimate

### Verify
- Check publisher/vendor
- Check whether the app/extension is expected
- Review the item in Windows Settings, browser UI, or Autoruns
- Run a trusted antivirus scan

### Scan with trusted tools
- Windows Security full scan
- Microsoft Defender Offline for high-risk persistence
- Trusted professional support if needed

### Disable first, do not delete first
- Manual disable is safer than deletion
- Reboot and rescan
- If it returns, escalate

### Escalate
- If persistence returns
- If credentials may be exposed
- If there are multiple high-risk signals
- If the user sees active compromise symptoms

## Why CEMÍ Does Not Auto-Remove Threats

- False positives can break legitimate software
- Removal can damage startup/service configuration
- Removal often requires admin privileges
- Automatic deletion can destroy forensic evidence
- Auto-remediation changes CEMÍ from read-only auditor to destructive tool
- This weakens trust and privacy positioning

Recommended future stance:
- V1/V2: no auto-removal
- Future optional separate tool: maybe disable-only remediation assistant
- Any future remediation must require explicit consent, backups/exports, exact action preview, undo guidance, and local logs

## False Positive Risks

CEMÍ has inherent false positive risks due to its metadata-only approach:
- Legitimate software uses persistence mechanisms
- Administrative scripts use LOLBins
- Browser extensions need broad permissions for functionality
- Custom services run from user directories
- Network connections are normal for many applications

Risk mitigation:
- Clear severity levels (INFO/LOW/MEDIUM/HIGH/CRITICAL)
- Confidence indicators (low/medium/high)
- Detailed explanations of why findings matter
- Guidance to verify legitimacy before action
- Correlation engine to increase confidence for multiple signals

## Privacy Risks

CEMÍ's privacy risks are reduced by design, but not zero:
- All data collection is local-only
- Strict redaction prevents user identification
- No network transmission
- No telemetry
- User-controlled report storage
- Reports may still reveal software/security configuration and should be treated as sensitive

Remaining risks:
- Report content could identify software configuration
- Redaction bypasses (must be tested against)
- Local storage of sensitive metadata
- User error in report handling

## Testing Recommendations

CEMÍ requires comprehensive testing to validate safety and effectiveness:

- Synthetic clean profile generates no HIGH/CRITICAL findings
- Synthetic suspicious profile generates expected HIGH findings
- No raw usernames or home paths in evidence
- No raw command secrets in reports
- HTML report auto-escapes malicious names
- Monitor history contains no raw process/network details
- Skipped collectors show clear skipped_reason
- Signatures skip is visible in health output
- V2 detections have false-positive tests
- Every rule has positive and negative cases
- Every new collector has permission-error tests
- Every Windows-only collector safely skips on Linux/WSL
- Redaction utilities are tested against edge cases
- Report generation handles malicious input safely
- Correlation engine produces expected signal combinations
- Risk scoring is deterministic and explainable

## Final Product Boundaries

CEMÍ is a local, read-only, privacy-first security explainer. It detects configuration and behavior patterns commonly associated with threats, but does not confirm threats, remove threats, or replace security tools. It explains what users should review and provides safe manual guidance. It avoids personal content, applies redaction to sensitive metadata, never transmits data, and never executes suspicious code. Its scope is intentionally limited to maintain safety and trustworthiness.