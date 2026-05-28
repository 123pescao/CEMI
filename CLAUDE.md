# CEMÍ — Claude Code Project Rules

## Project Identity

CEMÍ (Computer Evidence Monitoring Inspector) is a local-first, privacy-first desktop security
audit tool targeting Windows. It inspects system metadata for behavioral signals associated with
malware, spyware, and persistence mechanisms.

Non-negotiable constraints:
- Must stay non-destructive at all times.
- Must not perform network I/O anywhere in the scan pipeline.
- Must not execute subprocesses unless explicitly approved in a future task.
- Must not modify the system it inspects.

## Stack

- Python 3.11+
- Typer (CLI framework)
- Rich (terminal output)
- Pydantic v2 (immutable frozen models)
- Jinja2 (HTML report rendering, autoescape always on)
- psutil (process and network introspection)
- Hatchling (PEP 517 build backend)
- pytest (test runner)

No linter or type-checker is configured in pyproject.toml yet. Do not assume ruff, mypy, or black
are available. If adding one, update pyproject.toml first and get explicit approval.

## Key Paths

| Path | Purpose |
|---|---|
| `cemi/src/cemi/main.py` | CLI entry point (Typer app, 5 subcommands) |
| `cemi/src/cemi/scan_engine.py` | Scan orchestrator; enforces raw-item lifecycle and privacy invariants |
| `cemi/src/cemi/models.py` | All Pydantic v2 frozen models (Finding, ScanResult, etc.) |
| `cemi/src/cemi/collectors/` | 10 collectors; each must never raise and must redact before returning |
| `cemi/src/cemi/rules/` | 13 rule implementations + engine base classes |
| `cemi/src/cemi/reports/` | HTML and JSON report generation (Jinja2 + generator.py) |
| `cemi/src/cemi/utils/redact.py` | Redaction pipeline; must be applied before any output |
| `cemi/src/cemi/trust/` | Local vendor allowlist matching |
| `cemi/src/cemi/correlation_engine.py` | Derives correlated signals from raw findings |
| `cemi/src/cemi/monitor.py` | Monitor mode snapshot persistence |
| `cemi/tests/` | 32 test files; 806 tests passing as of v1 audit (2026-05-14) |
| `docs/` | Architecture, threat model, validation, limitations, user manual |

## Hard Privacy Rules

- Never expose raw usernames, home directory paths, hostnames, IP addresses, process paths,
  command lines, browser data, extension data, or native messaging host paths in any output —
  CLI, JSON report, HTML report, log, or error string — unless explicitly approved.
- Redaction must happen before output reaches any of: CLI stdout, JSON serialization, HTML
  rendering, log lines, or CollectorHealth.errors strings.
- Generated reports (`reports/`) and monitor snapshots (`.cemi/history/`) may contain private
  system metadata from real machines. Do not read these files unless Joel explicitly approves.
- Do not read: `.env`, `.env.*`, credentials, tokens, SSH keys, private keys, browser profile
  data, virtualenv internals (`venv/`, `.venv/`, `.venv-win/`), generated reports, `.cemi/history/`,
  or `.git/` internals.

## Redaction Contract

Every contributor and every Claude session working on this codebase must follow this contract:

- Apply `redact_path()` and `redact_string()` (from `cemi.utils.redact`) wherever system metadata
  can appear in output — including exception messages, error strings, and evidence values.
- Collector error strings must be sanitized before being appended to `CollectorHealth.errors`.
  Use the `_redact_err()` helper pattern already present in `services.py` and
  `browser_extensions.py`. Apply the same pattern to any collector that does not already do this.
- Do not add new evidence fields that contain raw paths, raw process names, raw usernames, or
  other private values unless a redacted counterpart is used and the raw field is removed or
  kept strictly internal and never serialized.
- All Pydantic models are frozen (`model_config = ConfigDict(frozen=True, extra="forbid")`).
  Do not change this.
- Raw collector items must never reach `ScanResult`. They are discarded after rule evaluation
  in `scan_engine.py`. Do not change this invariant.

## Known Open Findings (from Phase 3B read-only onboarding, 2026-05-27)

These are not yet fixed. Do not close them silently — get explicit approval before touching any.

| Severity | Finding |
|---|---|
| High | Collector error strings may reach JSON reports unredacted. `processes.py` and `network_connections.py` do not apply `_redact_err()` before appending to `errors`. Affects `reports/generator.py:82-94`, `collectors/processes.py:92`, `collectors/network_connections.py:81`. |
| Medium | `collectors/network_connections.py` retains raw `exe_path` alongside `exe_path_redacted` in connection dicts. Raw field should be removed. |
| Medium | `main.py:122-133` prints correlated signal fields via Rich without `markup.escape()`. Attacker-controlled extension names can inject Rich markup into terminal output. |
| Medium | `local_address` (machine's own IP) present in raw network connection dicts. Not currently surfaced in reports but latent PII exposure if raw dicts are ever serialized. |
| Low | Report output path (`Path("reports")`) and monitor history path (`Path.cwd() / ".cemi" / "history"`) are CWD-relative. Paths are not canonicalized or bounded. Review before shipping a stable release. |

## Safe Development Workflow

For any non-trivial change:

1. **Explore first** — Use Explorer agent to read relevant files. Do not guess.
2. **Plan before touching code** — Use Planner to produce a numbered plan. Stop at approval gate.
3. **Security review required** for any change involving: collectors, redaction pipeline,
   CLI output, report generation, filesystem write paths, or privacy invariants.
   Use Security Reviewer on the diff before committing.
4. **Claude does not commit or push** — Joel commits and pushes manually. Claude provides
   git instructions only.

## Testing Guidance

Suggested manual test command (do not run without Joel's approval):
```
cd cemi && pytest
```

Expected baseline: 806 passed, 2 skipped (per v1 audit, 2026-05-14, commit 23d0c10).

For verbose output: `pytest -v`
For a single file: `pytest tests/test_redact.py`

Do not run tests automatically. Do not run tests unless Joel explicitly approves for the
current task.

New privacy or security fixes must include tests. Do not submit a redaction fix without a
corresponding test that verifies the raw value does not appear in output.

## Approval Rules

- No file edits without explicit per-task approval.
- No shell commands without explicit per-task approval.
- No package installs without explicit per-install approval (one install = one approval).
- No network commands.
- No MCPs.
- No reading generated reports or `.cemi/history/` unless explicitly approved.
- No committing or pushing — Joel does this manually, always.
