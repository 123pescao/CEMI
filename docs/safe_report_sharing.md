# Safe Report Sharing

CEMÍ reports contain system metadata that describes your machine's configuration and security posture. This guidance explains how to handle reports safely and what information they may reveal.

## Report Contents

### What CEMÍ Reports Contain

- **Installed software** (names, versions, publishers)
- **Services** (names, status, configuration)
- **Startup entries** (Run/RunOnce registry entries, startup folder items)
- **Scheduled tasks** (names, triggers, commands)
- **Browser extensions** (names, permissions)
- **Network connections** (listening ports, established connections)
- **Process command-lines** (partially, redacted)
- **Risk scores** and findings

### What CEMÍ Reports Do NOT Contain

- **Personal documents**: CEMÍ never scans Documents, Pictures, Videos, Desktop, Downloads
- **Browser history**: Not accessed or included
- **Saved passwords or cookies**: Never accessed or included
- **Email or messages**: Not accessed or included
- **Clipboard contents**: Never accessed or included
- **Screenshots**: Never captured or included
- **File contents**: Metadata only
- **Unredacted usernames**: Redacted to `[REDACTED]`
- **Unredacted hostnames**: Stored as SHA-256 digest only
- **Unredacted secrets**: Tokens, keys, hex digests redacted to `[REDACTED_TOKEN]`

## Why Reports Are Sensitive

Even with redaction, reports may reveal:

1. **Security posture**: What security software is installed (or absent)
2. **Software deployment**: What business/development tools are in use
3. **System configuration**: What services, tasks, and startup items are configured
4. **User behavior**: Browser extensions, power user tools, development environment
5. **Organizational footprint**: If shared across multiple machines, patterns of software deployment

**In aggregate**, reports describe a specific machine and could be used for targeting if shared publicly.

## General Principles

### 1. Store Reports Securely

- Keep reports in a location protected by file permissions (not accessible to other users)
- Do not store reports on shared drives without access control
- Do not leave reports on shared computers
- Delete old reports you no longer need

### 2. Do Not Commit Reports to Version Control

Reports are generated artifacts:
- CEMÍ `.gitignore` includes `reports/` and `.cemi/`
- Never commit real scan reports to Git or any public repository
- Only commit the tool code and documentation

### 3. Review Reports Before Sharing

Before sharing a report with anyone:

1. Open the report in a text editor (HTML or JSON)
2. Search for any unredacted sensitive data:
   - Usernames (should see only `[REDACTED]`)
   - Paths (should see only `C:\Users\[REDACTED]\…`)
   - Hostnames (should see only SHA-256 digests)
   - Tokens/API keys (should see only `[REDACTED_TOKEN]`)
   - Personal information (should see none)
3. If you find unredacted data, report it as a privacy bug; do not share the report

### 4. Sanitize if Needed

If you want to share a report with a security researcher or helper:

1. Make a copy of the report
2. Remove or redact any additional sensitive information you prefer not to share (software names, extensions, services that are personal)
3. Share the sanitized copy only

### 5. Assume Reports May Leak Information

Even with redaction, a report might leak:
- That you use certain development tools
- That you run certain services
- That you have unusual network configurations
- That you use specific browser extensions

If this is sensitive information for your context, do not share the report.

## Safe Sharing Scenarios

### Scenario 1: Share with a Trusted Personal Security Helper

If sharing with a security professional you trust (not via email or chat):

1. Export the report (HTML or JSON)
2. Review the report for any additional sensitive data
3. Deliver the report via secure channel (encrypted email, secure file transfer, in-person)
4. Ask the helper to delete the report when done
5. Discuss findings privately

### Scenario 2: Share in a Support Ticket (e.g., Antivirus Support)

If sharing with antivirus or software support:

1. Review the report to remove any unrelated findings
2. Export only the relevant findings (copy-paste into ticket, do not attach full report if possible)
3. Use your support ticket's encryption/authentication (do not email raw file)
4. Ask support to confirm they will not retain the report

### Scenario 3: Post to a Forum or GitHub Issue

**Do not post full reports publicly.** Instead:

1. Export the report
2. Manually extract only the relevant finding(s)
3. Remove software names, extension IDs, and other identifying information if needed
4. Sanitize the finding to describe the pattern, not the specific software
5. Post the sanitized description, not the full report
6. Do not attach the report file

**Example - WRONG**:
```
I got this finding in my CEMÍ report:
"Microsoft Office Update Scheduler" startup entry runs "C:\Users\[REDACTED]\AppData\…\UpdateTask.exe"
[attach full report.html]
```

**Example - RIGHT**:
```
I see a startup entry for a Microsoft product pointing to a script in AppData\Local\…. 
Is this normal? [describe the pattern without full report]
```

### Scenario 4: Blog Post or Portfolio

If writing about CEMÍ or security analysis:

1. Use **synthetic data only** (do not use real reports from your machine)
2. Create example findings with made-up software names and paths
3. Do not include real scanner output from your machine
4. Make it clear: "This is a synthetic example for demonstration"

## Email Safety

If you must email a report:

1. Encrypt the email (use TLS, signed certificates, or PGP if available)
2. Use your organization's secure email if available
3. Send only to trusted recipients with known email addresses
4. Do not BCC or CC unintended recipients
5. Include a brief note explaining what you're sharing and why
6. Ask recipient to delete after review

**Better**: Use secure file transfer (VeraCrypt, Tresorit, Sync.com) instead of email.

## What NOT to Do

- ❌ Do not post full reports to public forums
- ❌ Do not attach reports to GitHub issues (unless private)
- ❌ Do not commit reports to version control
- ❌ Do not email reports to untrusted addresses
- ❌ Do not leave reports on shared computers
- ❌ Do not share reports with people you do not trust
- ❌ Do not assume a "sanitized" report is safe—review it
- ❌ Do not share old reports with sensitive findings still visible

## What to Do

- ✅ Store reports in secure locations
- ✅ Delete old reports
- ✅ Review reports before sharing
- ✅ Share only with trusted parties
- ✅ Use secure channels (encrypted, authenticated)
- ✅ Ask recipients to delete when done
- ✅ Use synthetic data for documentation/blog posts
- ✅ Sanitize for public discussion (remove identifying details)

## Privacy and CEMÍ Design

CEMÍ's redaction and local-only design were created specifically to make reports safer:

- **Local only**: Reports never leave your machine automatically
- **Redacted paths**: Usernames are masked
- **Redacted tokens**: Secrets are replaced
- **Redacted hostnames**: Only SHA-256 digests
- **Metadata only**: No personal documents, no browser history, no passwords

Even with these safeguards, assume reports are sensitive and handle them accordingly.

## If You Find a Privacy Issue

If you believe a CEMÍ report leaked unredacted sensitive data:

1. Do not share the report further
2. Open a private security report (see `../SECURITY.md`)
3. Include the specific data that was not redacted
4. Describe how it could have been prevented

## See Also

- [limitations.md](limitations.md) — What CEMÍ does not do
- [threat_model/README.md](threat_model/README.md) — CEMÍ's scope
- [../privacy.md](../privacy.md) — Privacy policy
- [../SECURITY.md](../SECURITY.md) — Security notes
