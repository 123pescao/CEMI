# Security Notes — CEMÍ

## Operating model

- CEMÍ runs **locally** on the user's machine.
- CEMÍ does **not** require an internet connection to function, and does not make outbound network calls.
- CEMÍ does **not** elevate privileges on its own. If a collector requires administrator rights it will report `skipped_reason` and continue.

## Platform limitations

CEMÍ is designed for Windows systems. On non-Windows platforms, some collectors will be skipped and results may be limited. The tool displays a warning when run on non-Windows systems.

## V1 scope limitations

CEMÍ V1 focuses on metadata-only inspection and behavioral signals. It does **not** include:

- Active malware scanning or removal
- Real-time monitoring or blocking
- Automated remediation or system changes
- Network traffic inspection
- File content analysis
- Integration with antivirus or EDR systems

CEMÍ V1 findings are behavioral signals based on system configuration and installed software. They indicate areas for manual review by the user, not definitive malware detection.

## Handling scan reports

Although CEMÍ redacts usernames, long tokens, and hostnames, the scan reports it produces may still contain **system metadata** — software names, versions, service names, startup entries, code-signing posture, and similar information. This is not personally identifying by itself, but in aggregate it describes the configuration of a specific machine.

Users should therefore:

- Store scan reports in a location protected by their normal file permissions.
- Not post scan reports to public forums, issue trackers, or chat channels without first reviewing the content.
- Delete old reports they no longer need.

## Threat model

CEMÍ is a defensive audit tool. It is **not** an EDR, not an anti-malware engine, not antivirus, and not a replacement for operating-system-level security.

**CEMÍ does not prove the absence of malware.** A clean scan result means no checked patterns were detected — not that the machine is uncompromised.

CEMÍ detects privacy- and security-relevant behaviors based on local evidence: installed software, running services, browser extensions, and native messaging hosts. Findings indicate *configuration* or *posture* concerns for the user to review.

## Reporting vulnerabilities

If you believe you have found a security vulnerability in CEMÍ itself (for example, a redaction bypass, a path traversal in a collector, or a case where data leaves the machine), please open a private report through the project's published disclosure channel rather than a public issue.
