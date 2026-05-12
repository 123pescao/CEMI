# CEMÍ Demo Script

This script provides a structured walkthrough to demonstrate CEMÍ's capabilities. Use this when giving demos or presentations.

## Overview (2 minutes)

**Story to tell**:

"CEMÍ is a local security audit tool that helps you understand what's installed on your machine and identify suspicious patterns. It's not antivirus, but it acts like a second set of eyes—it looks at software, services, startup entries, and browser extensions to flag things that might warrant a closer look.

Everything CEMÍ does happens locally. No data ever leaves your machine. It just describes what it finds and explains why each pattern is worth reviewing.

Let's walk through what that looks like."

## Setup (1 minute)

```bash
# Open terminal
cd cemi

# Activate venv (if not already active)
source venv/bin/activate  # or: .\venv\Scripts\Activate.ps1 on Windows

# Verify CEMÍ is installed
cemi --help
```

**Show**: The help output. Explain: "CEMÍ has 5 commands: scan, monitor, history, privacy, and version."

## Demo Step 1: Privacy Guarantees (1 minute)

```bash
cemi privacy
```

**Explain**:

"Before we do anything, CEMÍ wants you to know what it does and doesn't do. 

See these guarantees? No telemetry, no uploads, no browser history, no personal documents. CEMÍ is read-only—it never modifies your system, disables services, or deletes files.

Users are in control. All of that happens locally on your machine, and you decide what to do with the results."

## Demo Step 2: Run a Scan (2 minutes)

```bash
cemi scan --yes --output html
```

**Narrate as it runs**:

"Now CEMÍ is running a scan. Behind the scenes, it's:

1. **Collecting metadata** — installed software, services, startup entries, browser extensions, scheduled tasks
2. **Applying rules** — checking patterns for anything suspicious
3. **Correlating signals** — grouping related findings to reduce noise
4. **Scoring risk** — calculating an overall risk score based on what it found
5. **Generating a report** — saving an HTML report locally"

**While it runs, continue**:

"The whole process is local. It's talking to your registry, checking installed software, looking at Windows services. The only thing leaving the tool is a report on your machine—never uploaded anywhere."

## Demo Step 3: Explain the Report (3 minutes)

```bash
# Open the latest HTML report
ls -ltr reports/cemi_report_*.html | tail -1
open reports/cemi_report_*.html  # or: start on Windows
```

**Show and explain**:

**Risk Summary section**:
"Here's the overall risk score (0-100) and risk level. This is a summary of all the findings. Higher doesn't mean 'you're infected'—it means there are more patterns worth reviewing."

**Possible Malware/Spyware Signals**:
"These are persistence-related findings. Things that run automatically at startup, scheduled tasks with unusual commands, that kind of thing."

**Privacy Signals**:
"Browser extensions that have broad permissions, or native messaging hosts—these can be legitimate, but they're worth knowing about."

**Collectors**:
"Here's the health of each data source. All the collectors that ran, how many items they found, whether they succeeded or were skipped."

**Findings**:
"Each finding has a title, severity, and explanation. The explanation says *why* this pattern is interesting—not that it's definitely malicious, but why you should review it."

**Key point to emphasize**: "None of these findings scream 'you're infected.' They're behavioral patterns that are common in certain attack scenarios, but they're also common in legitimate software. Your job is to review and decide."

## Demo Step 4: Understand a Specific Finding (2 minutes)

**Pick a finding and explain**:

Example: "Browser Extension with Cookies Permission"
- **What it is**: A browser extension with permission to access all cookies
- **Why it matters**: An extension could potentially read your session cookies, steal credentials, etc.
- **What to do**: Check the publisher, research the extension, decide if it's trustworthy
- **What CEMÍ does NOT do**: CEMÍ doesn't know if the extension is malicious. It just flags the capability.

## Demo Step 5: Privacy Redaction (1 minute)

**Show the JSON report**:

```bash
# View JSON report
cat reports/cemi_report_*.json | head -100
```

**Point out**:

- Usernames are redacted: `"C:\Users\[REDACTED]\..."`
- Long tokens/secrets are redacted: `[REDACTED_TOKEN]`
- Hostnames are hashed: SHA-256 digest only
- No personal data whatsoever

**Emphasize**: "Even though CEMÍ reads system data, what it *reports* is sanitized. The report describes your system configuration without leaking personal information."

## Demo Step 6: Monitor Mode (Optional, 2 minutes)

```bash
# Run 2 quick scans 10 seconds apart
cemi monitor --yes --interval 10 --iterations 2
```

**Explain**:

"Monitor mode runs repeated scans and tracks changes over time. Each scan is saved as a snapshot. If you run this daily, you can see:

- New findings since the last scan
- Findings that disappeared (resolved)
- Risk score changes
- Collector status changes

It's local history only — no cloud sync, no backup, just local snapshots in `.cemi/history/`."

## Demo Step 7: Honest Limitations (1 minute)

**Show and explain what CEMÍ is NOT**:

- "Not antivirus" — doesn't scan file contents, doesn't confirm malware
- "Not EDR" — not for enterprise management
- "Not a forensic tool" — doesn't preserve evidence chains
- "Not a malware remover" — doesn't delete or remediate
- "Not a replacement for security practices" — works alongside Windows Defender, firewalls, etc.

**Emphasis**: "CEMÍ is a *complementary* audit tool. It raises awareness about what's on your system. It works best with trusted security practices: good passwords, 2FA, Windows Defender, backups."

## Demo Step 8: Threat Model (Optional, 1 minute)

**If asked "what does CEMÍ detect?"**:

Point to: `docs/threat_model/threat_coverage_matrix.md`

"Here's the threat coverage matrix. It lists:
- What CEMÍ currently detects (persistence, browser risks, service anomalies, etc.)
- What it *doesn't* detect (rootkits, keyloggers, network attacks)
- What it *never* collects (personal docs, browser history, credentials)
- What we intentionally deferred (signatures, WMI, etc.) and why

CEMÍ is honest about its boundaries."

## Demo Step 9: Q&A Points

**If asked "Could CEMÍ have a false positive?"**

"Absolutely. Development tools, power user scripts, browser extensions for accessibility—these are all legitimate but might look suspicious. CEMÍ flags patterns, not definitive threats. You should always verify using trusted tools before acting."

**If asked "Why no cloud lookups?"**

"Privacy. We don't want to upload file hashes, executable names, or domain names to external services. That's a privacy trade-off. If you want reputation lookups, use antivirus with those features."

**If asked "Why is signatures an 'honest skip'?"**

"Signature verification requires file paths. Paths can leak username, location, organizational structure. V1 is deferring that until we design safe raw-path isolation. Better to skip than to risk leaking data."

**If asked "What should I do if CEMÍ finds something?"**

"First, don't panic. Second, verify—use Windows Defender, Task Scheduler, Services, or Autoruns to confirm. Third, research—is the software legitimate? Fourth, decide—do I trust this? Last, act—disable, remove, or keep it. CEMÍ helps with step one (finding). The rest is up to you."

## Cleanup (1 minute)

```bash
# Show what was generated
ls -la reports/
ls -la .cemi/history/ 2>/dev/null || echo "No history"

# Show that generated files are ignored
git status
git status --ignored | grep -E "reports|\.cemi"

# Explain
echo "Generated reports and history are not committed—they stay on your machine."
```

## Key Messages to Reinforce

1. **Local-only**: Everything happens on your machine. No uploads.
2. **Privacy-first**: Redacted by design. No personal data leaves the tool.
3. **Read-only**: CEMÍ doesn't modify your system. You're in control.
4. **Not antivirus**: CEMÍ complements trusted security practices.
5. **Patterns, not confirmations**: Findings are worth reviewing, not definitive.
6. **Honest about uncertainty**: CEMÍ documents what it skips and why.

## Demo Timing

- Overview: 2 min
- Setup: 1 min
- Privacy: 1 min
- Scan: 2 min
- Report: 3 min
- Specific finding: 2 min
- Redaction: 1 min
- Monitor: 2 min (optional)
- Limitations: 1 min
- Threat model: 1 min (optional)
- Q&A: 5 min
- **Total: 20-25 minutes**

## Notes for Presenters

- **Bring a real machine** or VM with typical software installed (antivirus, Chrome/Edge, development tools)
- **Pre-run a scan** so you have a report to reference
- **Don't over-claim**: Stick to "patterns" and "signals," not "malware detected"
- **Invite questions**: Security professionals love discussing trade-offs
- **Have docs ready**: Point to `docs/threat_model/README.md` and `docs/limitations.md`
- **Show code if asked**: The redaction pipeline (`redact.py`) and collector isolation are good examples

## Alternative: Short Demo (10 minutes)

If time is limited:

1. Overview (1 min)
2. Run scan (2 min)
3. Show report highlights (2 min)
4. Explain one finding (2 min)
5. Honest limitations (2 min)
6. Q&A (1 min)

Focus: "It's a local audit tool that raises awareness without uploading data."

## Alternative: Deep Dive (45 minutes)

For technical audiences (developers, security engineers):

1. Overview + motivation (3 min)
2. Architecture walkthrough (5 min) — Point to `docs/architecture.md`
3. Collector isolation design (5 min) — Show `cemi/src/cemi/collectors/`
4. Rule evaluation (3 min) — Show `cemi/src/cemi/rules/`
5. Redaction pipeline (5 min) — Show `cemi/src/cemi/utils/redact.py`
6. Live scan demo (3 min)
7. Report generation (3 min)
8. Test coverage (3 min) — Show `pytest -v`
9. Design trade-offs (5 min) — Threat model discussion
10. Q&A (2 min)

Focus: "Here's how we built a privacy-first security tool with deterministic rules and safe collector isolation."
