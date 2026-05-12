# Sample Report Guidance

This document explains how to create safe, synthetic sample reports for documentation, blogging, or portfolio use.

## Important Rules

**NEVER include**:
- Real scan reports from your machine or anyone else's
- Real usernames, hostnames, or paths (even redacted)
- Real software names with version numbers that identify a specific machine
- Real extension IDs or service names that could leak organizational info

**ALWAYS use**:
- Fully synthetic data
- Made-up software names or descriptions
- Generic example hostnames
- Clear labeling: "Synthetic demo data. Not a real machine scan."

## Why This Matters

Real reports describe a specific machine's configuration. Even redacted, they could:

- Reveal what security software you use (or don't use)
- Show your organizational software stack
- Describe your browser extensions and preferences
- Leak that you use development tools, admin utilities, etc.

Synthetic samples avoid this by being completely fictional.

## Sample JSON Report (Synthetic)

```json
{
  "scan_id": "scan-demo-001",
  "scan_version": "0.1.0",
  "started_at": "2024-05-12T10:30:00Z",
  "completed_at": "2024-05-12T10:30:15Z",
  "hostname_redacted": "sha256:abcd1234...",
  "privilege_level": "user",
  "total_apps_scanned": 47,
  "risk_summary": {
    "score": 42,
    "level": "medium",
    "finding_counts": {
      "CRITICAL": 0,
      "HIGH": 1,
      "MEDIUM": 3,
      "LOW": 5,
      "INFO": 2
    }
  },
  "findings": [
    {
      "id": "PERSIST-001",
      "instance_id": "550e8400-e29b-41d4-a716-446655440000",
      "rule_version": "1.0.0",
      "title": "PowerShell Script in Scheduled Task",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Persistence",
      "app": null,
      "official_explanation": "Scheduled tasks can run at specific times. PowerShell scripts in tasks are common in legitimate scenarios but can also be abused for persistence.",
      "why_this_matters": "Attackers often create scheduled tasks that run malicious scripts. This pattern warrants verification.",
      "evidence": [
        {
          "type": "REGISTRY_KEY",
          "value": "HKCU\\Software\\[REDACTED]\\...",
          "label": "scheduled task entry"
        }
      ],
      "recommended_action": "Review the task in Task Scheduler. Verify the command is expected and the task is from a trusted source.",
      "false_positive_risk": "medium",
      "requires_admin_to_verify": false,
      "created_at": "2024-05-12T10:30:05Z",
      "scan_id": "scan-demo-001"
    },
    {
      "id": "BROWSER-002",
      "instance_id": "660e8400-e29b-41d4-a716-446655440001",
      "rule_version": "1.0.0",
      "title": "Browser Extension with All-Sites Access",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "category": "Browser",
      "app": "Example-Extension-Name",
      "official_explanation": "Browser extensions with access to all websites can read page contents, intercept data, and modify pages.",
      "why_this_matters": "This capability can be used for legitimate purposes (ad blockers, password managers) but could also be abused for credential theft or data exfiltration.",
      "evidence": [
        {
          "type": "MANIFEST_PERMISSION",
          "value": "<all_urls>",
          "label": "extension permission"
        }
      ],
      "recommended_action": "Check the extension publisher. Review its privacy policy. If you don't recognize the extension, consider uninstalling it.",
      "false_positive_risk": "high",
      "requires_admin_to_verify": false,
      "created_at": "2024-05-12T10:30:07Z",
      "scan_id": "scan-demo-001"
    }
  ],
  "collector_health": [
    {
      "collector_name": "installed_apps",
      "ran_successfully": true,
      "privilege_level": "user",
      "items_collected": 47,
      "duration_seconds": 1.2,
      "errors": [],
      "skipped_reason": null
    },
    {
      "collector_name": "services",
      "ran_successfully": true,
      "privilege_level": "user",
      "items_collected": 156,
      "duration_seconds": 0.8,
      "errors": [],
      "skipped_reason": null
    },
    {
      "collector_name": "startup",
      "ran_successfully": true,
      "privilege_level": "user",
      "items_collected": 12,
      "duration_seconds": 0.3,
      "errors": [],
      "skipped_reason": null
    }
  ]
}
```

**Note**: "Synthetic demo data. Not a real machine scan. For demonstration purposes only."

## Sample HTML Report Structure

If creating a sample HTML report, include:

1. **Header** with disclaimer: "Synthetic Demo Report — Not Real Data"
2. **Risk Summary** section with sample score (0-100)
3. **Sample Findings** (2-5 realistic but fictional examples)
4. **Collector Summary** table
5. **Footer** with "Created for educational purposes"

Never include:
- Real software versions
- Real hostnames or usernames
- Real process IDs or service names
- Real extension IDs or paths

## Portfolio Usage

### Blog Post Example

**DO**: "CEMÍ might detect a scheduled task running PowerShell. Here's what that looks like:"

```json
{
  "title": "PowerShell Script in Scheduled Task",
  "severity": "HIGH",
  "explanation": "Scheduled tasks can run PowerShell scripts. This is common for legitimate admin tasks but can also be used for persistence."
}
```

**DON'T**: "I got this finding on my machine: [real report with real software names]"

### GitHub Portfolio

**DO**: Include sanitized example findings in documentation:

```markdown
## Example Findings

CEMÍ might report findings like:

- **Browser Extension with All-Sites Access** (MEDIUM severity)
- **Service Running from User Path** (MEDIUM severity)  
- **Startup Entry with PowerShell Command** (HIGH severity)
```

**DON'T**: Commit real scan reports

### Interview/Presentation

**DO**: Run CEMÍ live on a test machine (VirtualBox, demo environment) and discuss findings in context

**DON'T**: Use anonymized reports from production systems—they still might reveal organizational details

## Creating Synthetic Findings

Example template:

```python
Finding(
    id="SYNTHETIC-001",
    title="Example Finding for Demo",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    category="Persistence",
    evidence=[
        EvidenceItem(
            type=EvidenceType.REGISTRY_KEY,
            value="HKCU\\Software\\Example\\[REDACTED]\\Data",
            label="example registry path"
        )
    ],
    official_explanation="This is a fictional example for demonstration.",
    in_other_words="[Synthetic data]",
    why_this_matters="[Demonstration purpose]",
    recommended_action="[Example action]",
    false_positive_risk="medium"
)
```

## Storage

If storing sample reports in the repository:

- Create `docs/demo/samples/` directory
- Name files clearly: `synthetic_report_high_risk_example.json`
- Include `README.md` in samples/ stating: "All reports in this directory are synthetic data for demonstration."
- Never commit real reports to this or any other directory

## Checklist Before Sharing

- [ ] Report contains **no real usernames** (even redacted, don't use real names)
- [ ] Report contains **no real software versions** (use generic names)
- [ ] Report contains **no real hostnames** (use examples like "example-pc")
- [ ] Report clearly labeled: "Synthetic demo data"
- [ ] Finding titles are generic (not tied to real products)
- [ ] Evidence values are fictional/redacted
- [ ] No real paths or service names
- [ ] No real extension IDs or browser names (if identifiable)

## Questions?

If uncertain whether sample data is safe to share, ask:

> "If someone read this report, could they identify my machine, organization, or role?"

If yes → Don't share. Recreate with synthetic data.
If no → Probably safe to share (still good to review first).

## See Also

- [safe_report_sharing.md](../safe_report_sharing.md) — How to share real reports safely
- [demo_commands.md](demo_commands.md) — Commands to demonstrate CEMÍ live
- [demo_script.md](demo_script.md) — Full walkthrough script
