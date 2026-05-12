# CEMÍ Threat Model

## Overview

CEMÍ is a **local-first, metadata-only security audit tool**. It inspects system configuration and installed software to identify behaviors and patterns commonly associated with malware, spyware, trojans, and intrusion activity. **CEMÍ does not confirm the presence of malware.** It surfaces local behavioral signals that warrant manual review.

## Core Principles

- **Metadata only**: CEMÍ analyzes installed software names/versions, service configuration, startup entries, task metadata, and extension permissions. It never reads file contents, executes files, or captures network traffic.
- **Local only**: All analysis happens on the user's machine. No data leaves the device.
- **Non-destructive**: CEMÍ is read-only. It never modifies the system, disables services, removes files, or takes remedial action.
- **Privacy first**: Usernames, hostnames, and long opaque strings are redacted before reports are written. CEMÍ redacts itself — users never see unredacted sensitive data in any report or log.
- **Honest about uncertainty**: CEMÍ surfaces behavioral signals and patterns. It explains why each finding matters and what the user should review. It does not make false-confidence claims.

## What CEMÍ Can Surface

CEMÍ's threat model focuses on **local configuration and behavior signals** that may indicate:

- **Persistence mechanisms** (startup entries, scheduled tasks, services with user paths)
- **Living-off-the-land (LOLBin) abuse** (PowerShell/cmd in startup or tasks)
- **Suspicious browser extensions** (excessive permissions, native messaging bridges, data collection capabilities)
- **Service anomalies** (services running from user-writable locations, unusual configurations)
- **Process/network metadata concerns** (listening ports, process command-line patterns)
- **Trust/signature concerns** (intentionally deferred in V1 for safe design reasons)

See [threat_coverage_matrix.md](threat_coverage_matrix.md) for the full coverage map.

## What CEMÍ Cannot Confirm

CEMÍ **does not detect**:

- Active malware execution or memory-resident threats
- Rootkits or kernel-level compromises
- Encrypted or obfuscated payloads
- Zero-day exploits
- Network-based attacks or intrusions
- Browser history or saved credential theft
- Keylogging or input interception
- File-level encryption or ransomware payloads

**Important**: A clean CEMÍ scan does not prove the machine is uncompromised. It means no *detected patterns* were found — not that no threat exists.

## Privacy Boundaries — What CEMÍ Never Collects

CEMÍ is explicitly forbidden by design from accessing:

- Personal documents, photos, videos, or media
- Browser history, bookmarks, cookies, saved passwords, autofill data, or session data
- Email content or mailboxes
- Chat logs or message histories
- Clipboard contents or keystroke data
- Screenshots or screen captures
- Memory dumps or process memory
- Arbitrary file contents or directory traversal
- Raw username or home directory paths (redacted before storage)
- Unredacted hostnames (stored as SHA-256 digest)
- Telemetry or usage analytics

## Design Philosophy

### Why Read-Only?

CEMÍ is designed as an audit and awareness tool, not a remediation tool. Users who find concerning signals should:

1. **Verify** the finding is real using trusted tools (antivirus, Windows Defender, Autoruns, Task Scheduler)
2. **Review** the software/configuration to understand its legitimate purpose
3. **Decide** whether to disable, remove, or keep the item
4. **Act** manually only after understanding the consequences

Automatic removal is out of scope for CEMÍ. The operating system and user preference should govern system changes.

### Why Metadata-Only?

Metadata (software names, versions, service paths, extension permissions) is **sufficient to identify patterns** and raise awareness. It also **reduces privacy risk** — no file contents, no browser data, no personal documents are ever touched.

### Why No Cloud Lookups?

CEMÍ does not query VirusTotal, hash repositories, or reputation services because:

1. **Privacy**: Sharing file hashes, executable names, or domain names could leak system information
2. **Offline operation**: CEMÍ should work without internet
3. **Availability**: Cloud services may be down or rate-limited
4. **Transparency**: Users deserve to know exactly what data CEMÍ sees, without external dependencies

## V1 Honest Limits

CEMÍ V1 deliberately skips several capabilities that would require unsafe data collection:

- **Signature verification** is deferred until a safe raw-path isolation architecture exists
- **File content inspection** is out of scope; metadata is sufficient for V1
- **WMI persistence detection** is deferred (would require additional data collection)
- **IFEO/AppInit_DLLs detection** is deferred

These skips are **intentional design choices**, not bugs. Each deferred capability is documented in [threat_coverage_matrix.md](threat_coverage_matrix.md) with rationale.

## User Response Model

When CEMÍ identifies a finding:

1. **Understand the signal**: Read the explanation. It describes why the configuration pattern is interesting, not that the software is definitely malicious.
2. **Verify in context**: Use Windows Settings, Task Scheduler, Services, Autoruns, or other trusted tools to inspect the actual item.
3. **Research**: Search the software name, publisher, or service to understand if it's legitimate.
4. **Decide**: Disable, remove, or keep the item based on your own judgment and threat model.
5. **Monitor**: If you remove the item, watch for unexpected system behavior or reinstallation attempts.

## False Positive Philosophy

CEMÍ prefers **precision over recall**. Some malicious software may not be detected, but CEMÍ will not aggressively flag every unusual item (false positives are acceptable in a review tool, but should be minimized).

Examples:
- Development tools with scripts are common → CEMÍ does not flag every PowerShell script in tasks
- Browser extensions for power users may need broad permissions → CEMÍ flags only high-risk combinations
- User-installed software in user paths is normal → CEMÍ flags only high-risk patterns

## Integration Model

CEMÍ is **not**:

- A replacement for antivirus (use Windows Defender or trusted third-party AV)
- An EDR (endpoint detection and response) system
- A forensic analysis tool
- A malware removal tool
- An intrusion detection system for networks

CEMÍ **is** a **complementary local audit tool** that raises awareness about system configuration. It works best alongside trusted security practices:

- Keep Windows and software updated
- Run Windows Defender (or trusted antivirus) actively
- Use Windows Firewall
- Review browser extensions and permissions
- Backup data regularly
- Monitor for unusual system behavior

## Report Safety

CEMÍ reports describe the configuration of a specific machine. They should be treated as **sensitive**:

- Store in a location protected by file permissions
- Do not commit to version control
- Review before sharing with security helpers
- Do not post to public forums without review
- Delete old reports when no longer needed

See [../safe_report_sharing.md](../safe_report_sharing.md) for detailed sharing guidance.

## Recommended Reading

- [threat_coverage_matrix.md](threat_coverage_matrix.md) — detailed coverage map, what's detected, what's deferred
- [../architecture.md](../architecture.md) — system design and collector architecture
- [../limitations.md](../limitations.md) — what CEMÍ does not do
- [../safe_report_sharing.md](../safe_report_sharing.md) — how to safely share reports

## Questions?

If you have questions about CEMÍ's design, see the main [README.md](../../README.md) or the project documentation in `docs/`.
