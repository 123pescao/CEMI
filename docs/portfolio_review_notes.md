# Portfolio Review Notes — CEMÍ

This document is written for **security engineering hiring managers, technical reviewers, and portfolio evaluators**. It explains what CEMÍ demonstrates and what design decisions matter.

## Executive Summary

CEMÍ is a **local-only, metadata-only security audit tool** that demonstrates:

1. **Privacy-first architecture**: By design, CEMÍ touches zero personal data
2. **Secure systems design**: Isolation, least privilege, deterministic behavior
3. **Thoughtful trade-offs**: Knowing when to skip features for safety
4. **Production-quality practices**: Comprehensive testing, documentation, redaction pipeline

CEMÍ is **not** production-ready (pre-alpha), but it demonstrates the thought processes and engineering practices expected in security roles.

## What This Project Demonstrates

### 1. Privacy-First Thinking

**What reviewers should notice**:

- CEMÍ explicitly documents what it **will never collect** (personal documents, browser history, cookies, passwords)
- Privacy boundaries are **architectural**, not a feature bolt-on
- Redaction is applied **deterministically** before any report generation
- The codebase **tests that redaction works** (no raw paths/tokens in reports)

**Why it matters**: Security teams need engineers who think about privacy constraints upfront, not as an afterthought. CEMÍ shows this mindset.

**Code to review**:
- `cemi/src/cemi/utils/redact.py` — How paths, tokens, and evidence are redacted
- `cemi/tests/test_redact.py` — Comprehensive redaction edge cases
- `cemi/tests/test_monitor.py` — Tests verify snapshots contain no raw paths or evidence
- `cemi/privacy.md` — Privacy policy documents what is never collected

### 2. Secure Systems Isolation

**What reviewers should notice**:

- Each **collector is isolated**: failures in one collector do not crash others
- Collectors are **read-only**: no side effects, no system modifications
- **Error handling is defensive**: exceptions are caught, health is reported, scan continues
- **No privilege escalation**: respects OS file permissions, no shell commands

**Why it matters**: Production security systems require fault tolerance and defensive programming. CEMÍ demonstrates this at scale.

**Code to review**:
- `cemi/src/cemi/collectors/` — Each collector is independent; examine error handling
- `cemi/src/cemi/scan_engine.py` — ScanEngine orchestrates collectors safely
- `cemi/src/cemi/models.py` — Health/status reporting is first-class, not an afterthought
- `cemi/tests/test_collectors.py` — Tests verify collectors fail gracefully

### 3. Honest About Uncertainty

**What reviewers should notice**:

- Findings are **signals**, not **detections** (language matters)
- Rules document **why** a pattern matters, not that it's malicious
- CEMÍ **intentionally skips** features and documents why (signatures deferred for safety)
- Correlation engine **reduces noise** rather than flags everything
- Reports say "review this" not "you are infected"

**Why it matters**: Security professionals must communicate uncertainty clearly. Overstated claims erode trust. CEMÍ demonstrates humility.

**Docs to review**:
- [docs/threat_model/README.md](threat_model/README.md) — Threat model is explicit: "signals, not confirmations"
- [docs/threat_model/threat_coverage_matrix.md](threat_model/threat_coverage_matrix.md) — Clear delineation: what's detected, what's deferred, what's "do not collect"
- [docs/limitations.md](limitations.md) — Honest about what CEMÍ cannot do
- `cemi/src/cemi/main.py` — Finding titles say "possible signal" not "malware detected"

### 4. Rule-Based Detection Done Right

**What reviewers should notice**:

- Rules are **deterministic**: same input always produces same finding
- Rules are **testable**: synthetic profiles exercise known-good and known-bad scenarios
- Rules are **documented**: each finding includes explanation, not just a score
- Rules are **versioned**: rule_version allows tracking changes over time
- Correlation **reduces false positives** by grouping related findings

**Why it matters**: Detection systems at scale require auditable, testable rules. One bad rule can trigger false alerts organization-wide. CEMÍ shows rigor.

**Code to review**:
- `cemi/src/cemi/rules/` — Rules are modular and testable
- `cemi/tests/test_rules.py` — Comprehensive rule coverage
- `cemi/tests/test_synthetic_profiles.py` — Known attack scenarios (known_good, known_bad)
- `cemi/src/cemi/correlation_engine.py` — Correlation reduces N×M explosion

### 5. Test-Driven Development

**What reviewers should notice**:

- Tests cover **happy path, sad path, and edge cases**
- Tests include **privacy/security checks** (no raw paths, no leaks, redaction validation)
- Tests are **deterministic** (no flaky timeouts, no platform-specific failures)
- Tests run on **Linux CI** (CEMÍ skips Windows-only collectors gracefully)
- Tests document **expected behavior** (what should pass, what should fail)

**Why it matters**: Security code requires comprehensive testing. CEMÍ has 796+ passing tests for a ~3K LOC package—that's test density you want in production.

**Test files to review**:
- `cemi/tests/test_monitor.py` — History, snapshots, safe read operations
- `cemi/tests/test_redact.py` — Token/path redaction edge cases
- `cemi/tests/test_cli.py` — Command parsing, privacy confirmation, output format
- `cemi/tests/test_synthetic_profiles.py` — Known scenarios

### 6. Documentation is Part of the Code

**What reviewers should notice**:

- Threat model is **explicit and versioned** (not in someone's head)
- Architecture is **documented with text diagrams** (not just code comments)
- Design decisions are **justified** (why read-only, why metadata-only, why skips)
- Limitations are **honest and specific** (not "none known")
- Portfolio is **self-aware** about what it demonstrates

**Why it matters**: Security systems require documentation as much as code. This project shows the discipline.

**Docs to review**:
- `cemi/README.md` — Clear positioning, what it is and is not
- `cemi/privacy.md` — Privacy policy is explicit
- `cemi/SECURITY.md` — Security notes are clear
- `docs/threat_model/README.md` — Threat model is readable, not a matrix only
- `docs/architecture.md` — System design explained to a junior engineer
- `docs/limitations.md` — Honest about what doesn't work

### 7. Trade-Off Analysis

**What reviewers should notice**:

- **Signatures deferred**: Rather than risk raw-path exposure, signatures are skipped in V1 with clear rationale
- **No cloud lookups**: Local-only is not just a feature, it's a privacy stance
- **Read-only design**: Not a limitation, but an intentional choice for transparency
- **Metadata-only**: Sufficient to detect patterns without touching personal data

**Why it matters**: Real engineering is about trade-offs. CEMÍ shows clear thinking about when to do less for better security/privacy.

**Design decisions to review**:
- Why `SignaturesCollector` is an honest skip (see `cemi/src/cemi/collectors/signatures.py`)
- Why CEMÍ does not query VirusTotal (see `docs/limitations.md`)
- Why CEMÍ is read-only (see `docs/threat_model/README.md`)
- Why metadata is sufficient (see `docs/architecture.md`)

### 8. Platform Realism

**What reviewers should notice**:

- CEMÍ **acknowledges** it's Windows-focused (see startup, services, tasks collectors)
- Windows-only collectors **gracefully skip** on Linux/macOS with clear reason
- CLI **warns** users on non-Windows platforms ("CEMÍ is designed for Windows")
- Tests run on **Linux CI** and pass (collectors skip cleanly)
- Documentation is **honest** about platform limitations

**Why it matters**: Real tools work on their target platform well and degrade gracefully elsewhere. CEMÍ does this.

**Code to review**:
- `cemi/src/cemi/main.py` — `_warn_non_windows()` function
- `cemi/tests/test_cli.py` — Platform warning tests
- `cemi/src/cemi/collectors/` — Each collector checks `_IS_WINDOWS` and skips if needed
- `docs/limitations.md` — Platform limitations are explicit

### 9. Package and Distribution Readiness

**What reviewers should notice**:

- `pyproject.toml` is **minimal and correct** (Hatch-based, correct entry point)
- CLI entry point **is testable** and works end-to-end
- `.gitignore` rules **prevent accidents** (generated reports, .cemi history, venv not committed)
- **Clean install** is documented and works from scratch
- **Tests pass** with no external tool dependencies

**Why it matters**: Security tools must be easy to deploy and audit. CEMÍ shows distribution discipline.

**Files to review**:
- `cemi/pyproject.toml` — Correct structure, no bloat
- `cemi/.gitignore` — Proper ignore rules
- `docs/validation/clean_install_checklist.md` — Installation tested
- Tests pass with `pytest` (no special setup needed)

## Engineering Practices Demonstrated

### Code Quality

- ✅ Type hints throughout (Python 3.11+)
- ✅ Pydantic models for data validation
- ✅ Deterministic scoring (no randomness)
- ✅ Comprehensive error handling
- ✅ No global state (functional where possible)

### Testing

- ✅ 796+ tests for ~3K LOC (high test density)
- ✅ Unit, integration, and CLI tests
- ✅ Privacy/security tests (redaction validation)
- ✅ Synthetic profile tests (known scenarios)
- ✅ Deterministic tests (no flakiness)

### Documentation

- ✅ Clear README positioning ("what it is and is not")
- ✅ Explicit privacy policy
- ✅ Threat model with coverage matrix
- ✅ Architecture documented
- ✅ Limitations honestly stated

### Security

- ✅ Read-only design
- ✅ Privacy-first redaction
- ✅ Isolated collectors (fault tolerance)
- ✅ Deterministic behavior (auditable)
- ✅ No privilege escalation
- ✅ No arbitrary code execution

### Development Practices

- ✅ Git history with logical commits
- ✅ Tests verify each phase
- ✅ Phases are documented and incremental
- ✅ Changes are reviewed (PR practice discipline)
- ✅ Versioning (0.1.0 - pre-alpha)

## Hiring Signal Strength

**Strong signals from this project**:

1. **Knows when to skip**: Developers who defer features for safety are rare
2. **Privacy native**: Not added later, but foundational
3. **Test discipline**: 796+ tests means quality standards
4. **Honest communication**: No marketing spin, clear about limitations
5. **Systems thinking**: Isolation, fault tolerance, determinism
6. **Documentation**: Threat model is written for humans
7. **Platform realism**: Works on Windows, degrades gracefully elsewhere
8. **Trade-off analysis**: Explicit about what was sacrificed for what

## Honest Assessment

### What This Project Is Not

- ❌ Not a complete security solution
- ❌ Not production-hardened (pre-alpha)
- ❌ Not tested on all Windows versions
- ❌ Not a replacement for antivirus or EDR
- ❌ Not enterprise-scale (single-machine scope)

### What This Project Demonstrates

- ✅ Security mindset (privacy-first, deterministic, honest)
- ✅ Engineering discipline (tests, documentation, design)
- ✅ Systems thinking (isolation, fault tolerance, tradeoffs)
- ✅ Communication clarity (threat model, limitations, architecture)
- ✅ Production-ready practices (even in pre-alpha)

## Questions for Interviewers

If you're interviewing the CEMÍ author, consider:

1. **Design philosophy**: "Why did you defer signatures instead of implementing them quickly?"
2. **Privacy tradeoffs**: "What data did you consider collecting but reject? Why?"
3. **False positive strategy**: "How do you balance detection and false positive rates?"
4. **Platform support**: "Why gracefully skip Windows-only collectors rather than simulate them?"
5. **Test coverage**: "How do you decide what scenarios to test?"
6. **Honest uncertainty**: "What can CEMÍ not do, and why is it OK?"

## Recommended Review Flow

1. **Start here**: `cemi/README.md` (5 min)
2. **Threat model**: `docs/threat_model/README.md` (10 min)
3. **Limitations**: `docs/limitations.md` (10 min)
4. **Architecture**: `docs/architecture.md` (10 min)
5. **Redaction**: `cemi/src/cemi/utils/redact.py` + `cemi/tests/test_redact.py` (15 min)
6. **Collectors**: `cemi/src/cemi/collectors/` (pick 2, 15 min)
7. **Tests**: `cemi/tests/` (spot-check 3 test files, 15 min)
8. **Full test run**: `pytest -q` (verify all pass, 2 min)

**Total time**: ~1.5 hours for a complete review.

## Bottom Line

CEMÍ demonstrates what **secure, thoughtful engineering** looks like:

- **Privacy by design** (not bolted on)
- **Fault tolerance and isolation** (production practices)
- **Honest communication** (no overstated claims)
- **Test discipline** (high coverage, deterministic)
- **Clear trade-offs** (know what was sacrificed and why)
- **Documentation as spec** (threat model, architecture, limitations)

This is the kind of thinking you want in security engineering roles.

---

**Next steps**: See [../README.md](../README.md) for installation and demo.
