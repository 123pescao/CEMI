# CEMÍ Architecture

## System Overview

CEMÍ operates as a **local-only, read-only security audit tool**. It collects system metadata, applies rule-based analysis, correlates signals, scores risk, and generates reports. All data stays on the user's machine.

## Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│               CLI Entry Point (main.py)                 │
│         (scan, monitor, history, privacy commands)      │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                    ScanEngine                           │
│              (orchestrates collectors)                  │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┬─────────────┐
        │              │              │             │
┌───────▼────┐ ┌──────▼──────┐ ┌────▼────┐ ┌──────▼──────┐
│ Collectors │ │ Collectors  │ │ More... │ │  Services   │
├────────────┤ ├─────────────┤ │         │ │  (Windows   │
│ - InstalledApps         │ │         │ │  only       │
│ - Services (safe)       │ │         │ │  unless     │
│ - StartupCollector      │ │         │ │  simulated) │
│ - Browser Extensions    │ │         │ │             │
│ - NativeMessaging       │ │         │ │             │
│ - Processes (point-in-  │ │         │ │             │
│   time, Windows-heavy)  │ │         │ │             │
│ - Network Connections   │ │         │ │             │
│ - ScheduledTasks        │ │         │ │             │
│ - SignaturesCollector   │ │         │ │             │
│   (intentional skip,    │ │         │ │             │
│    deferred)            │ │         │ │             │
└───────┬────┘ └─────┬────┘ └────┬────┘ └──────┬──────┘
        │            │           │              │
        └────────────┼───────────┼──────────────┘
                     │
         ┌───────────▼────────────┐
         │   Rule Engine          │
         │  (rule set evaluation) │
         └───────────┬────────────┘
                     │
         ┌───────────▼──────────────┐
         │ Correlation Engine       │
         │ (signal quality, reduce  │
         │  noise, group findings)  │
         └───────────┬──────────────┘
                     │
         ┌───────────▼──────────────┐
         │ Scoring Engine           │
         │ (risk score, severity)   │
         └───────────┬──────────────┘
                     │
         ┌───────────▼──────────────┐
         │ ScanResult (model)       │
         │ - findings               │
         │ - risk_summary           │
         │ - collector_health       │
         │ - correlated_signals     │
         └───────────┬──────────────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
    ┌───▼──┐  ┌─────▼────┐  ┌────▼─────┐
    │ HTML │  │   JSON   │  │ Monitor   │
    │Report│  │ Report   │  │ (history) │
    └──────┘  └──────────┘  └───────────┘
```

## Component Details

### Collectors (BaseCollector)

Each collector is a **isolated, read-only** component:

```
BaseCollector
├── run() → tuple[list[item], CollectorHealth]
├── Catches exceptions internally
├── Sets skipped_reason if Windows-only but not Windows
├── Returns health even on failure
└── Never raises exceptions to caller
```

**Safety guarantees**:
- Collectors do not import each other
- No collector has side effects
- Errors in one collector do not crash the scan
- Each collector reports its own status (OK, FAILED, SKIPPED)

**Collectors currently implemented**:
- `InstalledAppsCollector` — registry enumeration (Windows)
- `ServicesCollector` — service enumeration (Windows)
- `NativeMessagingHostsCollector` — browser native messaging hosts (Windows/Linux)
- `BrowserExtensionsCollector` — installed extensions (Windows/Linux)
- `StartupCollector` — Run/RunOnce/startup folders (Windows)
- `ScheduledTasksCollector` — scheduled tasks (Windows)
- `ProcessesCollector` — running processes and command-lines (Windows priority, fallback on Linux)
- `NetworkConnectionsCollector` — listening ports and established connections (Windows priority, fallback on Linux)
- `SignaturesCollector` — **intentional honest skip** (deferred for safe raw-path isolation)

**Why SignaturesCollector is an honest skip**:
In V1, file signature verification is deferred because it would require:
1. Safe isolation of raw file paths before rule processing
2. Verification that no raw paths leak to ScanResult, reports, CLI, or history
3. Architecture design to prevent accidental raw-path exposure

The `SignaturesCollector` skips intentionally with `skipped_reason` to document this design decision.

### Rule Engine

Rules evaluate collected items against patterns:

```
Rule
├── id: str
├── title: str
├── category: str (Persistence, Browser, etc.)
├── evaluate(item) → Finding | None
└── Evidence items (redacted before storage)
```

Rules are organized by category:
- Persistence rules (startup, task, service, WMI patterns)
- Browser rules (extension permissions, native messaging bridges)
- Network rules (listening ports, suspicious processes)
- Process rules (LOLBins, suspicious commands)
- Trust rules (unsigned, user-writable paths)

Each rule is **deterministic**: same input always produces same Finding.

### Correlation Engine

Correlation reduces noise and improves signal quality:

```
CorrelationEngine
├── Input: list[Finding]
├── Group findings by correlation rules
├── Assign confidence/severity adjustments
├── Output: CorrelatedSignal list
└── Goal: reduce N×M explosion (e.g., one extension + one host = one signal)
```

**Example**: Browser extension with native messaging host:
- Without correlation: 2 findings (extension + host)
- With correlation: 1 signal (extension-host pair) with combined context

### Scoring Engine

Risk scoring aggregates findings into a single risk score:

```
RiskSummary
├── score (0–100)
├── level (none, low, medium, high, critical)
├── finding_counts (by severity)
└── Deterministic formula: sum of weighted findings
```

### Redaction Pipeline

Before any data leaves the ScanResult:

1. **Path redaction**: `C:\Users\alice\…` → `C:\Users\[REDACTED]\…`
2. **Token/secret redaction**: `sk-…`, `ghp_…`, hex digests, base64 blobs → `[REDACTED_TOKEN]`
3. **Hostname redaction**: `LAPTOP-ABC123` → SHA-256 digest
4. **Evidence item redaction**: Each evidence value is redacted

Redaction is applied in `cemi.utils.redact` and integrated into report generation.

### Reports

Reports are generated from the redacted ScanResult:

- **HTML Report** (default): Rich visual summary with finding details
- **JSON Report**: Machine-readable structured data

Reports are **never uploaded**. They are saved locally to `reports/` (ignored by git).

### Monitor & History

Monitor mode repeatedly runs scans and tracks changes:

```
MonitorSnapshot
├── timestamp
├── risk_score
├── risk_level
├── finding_titles (not full findings)
├── finding_ids
└── collector_statuses

Saved to: .cemi/history/snapshot_*.json
```

**Privacy guarantee**: Snapshots store only metadata—no raw evidence, no paths, no details.

Timeline analysis compares snapshots to surface:
- New findings since first scan
- Resolved findings
- Risk score delta
- Collector status changes

## Key Design Decisions

### Why Metadata-Only?

Metadata (software names, versions, paths, permissions) is **sufficient to identify patterns**:
- Malware often persists via startup/tasks/services (metadata visible)
- Browser spyware manifests in extension permissions (metadata visible)
- Trojans often live in user-writable paths (metadata visible)

**Benefit**: No file contents, no browser data, no personal documents are touched.

### Why Local-Only?

CEMÍ works offline and never leaks system information:
- No cloud reputation lookups
- No network calls
- No telemetry
- No third-party integrations

**Benefit**: User knows exactly what data CEMÍ sees.

### Why Read-Only?

CEMÍ is an **awareness tool**, not a **remediation tool**. Users should:
1. Verify findings using trusted tools
2. Research the software
3. Decide whether to act
4. Take manual action

**Benefit**: Transparent, user-controlled decisions; no silent system changes.

### Why Honest Skips?

CEMÍ documents capabilities it **intentionally skips** via `skipped_reason`:

```
CollectorHealth(
    collector_name="signatures",
    skipped_reason="Signature verification deferred in V1 until safe raw-path isolation exists",
    ran_successfully=False,
)
```

**Benefit**: Users understand that absence of a finding does not mean CEMÍ checked—it means CEMÍ intentionally deferred the check.

## Testing Strategy

- **Unit tests**: Rule evaluation, redaction, correlation
- **Integration tests**: Collector isolation, ScanEngine orchestration
- **CLI tests**: Command parsing, output format, privacy isolation
- **Privacy tests**: No raw paths in reports, no unredacted secrets, no leaks
- **Synthetic profiles**: Known attack scenarios (known_good, known_bad)

## Future Extensibility (V2 Candidates)

Without changing V1 core:
- WMI persistence metadata (read-only)
- IFEO/AppInit_DLLs detection
- Service dependency analysis
- Startup .lnk target resolution
- Extended LOLBin patterns
- Browser extension trust validation

All would remain metadata-only, read-only, and privacy-first.

## Security Boundaries

- **No privilege escalation**: CEMÍ respects OS permissions
- **No subprocess execution**: CEMÍ does not shell out to tools
- **No network access**: CEMÍ does not make outbound calls
- **No file modification**: CEMÍ is read-only
- **No clipboard access**: CEMÍ does not inspect clipboard
- **No screenshot capture**: CEMÍ does not capture screen
- **No memory access**: CEMÍ does not inspect process memory

These boundaries are **architectural** and verified by design.
