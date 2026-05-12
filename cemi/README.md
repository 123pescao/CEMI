# CEMÍ — Computer Evidence Monitoring Inspector

CEMÍ is a local-first, privacy-first desktop security tool that inspects system metadata and configuration to help users understand the security posture of their machine. It never accesses personal files, never collects telemetry, and never transmits any data externally. All analysis, reports, and logs remain on the user's device under the user's control.

**Note: CEMÍ is designed for Windows systems.** While it may run on other platforms, some collectors will be skipped and results may be limited. Full functionality requires Windows.

## Installation

Install from the local repository in editable mode (includes dev dependencies):

```bash
pip install -e .[dev]
```

## Usage

### Run a scan

Produces an HTML report saved locally under `reports/`:

```bash
cemi scan --output html
```

Save a JSON report instead:

```bash
cemi scan --output json
```

Skip the interactive privacy confirmation:

```bash
cemi scan --output html --yes
```

Restrict the scan to a specific application:

```bash
cemi scan --app "AppName"
```

### Show privacy guarantees

Prints the list of privacy guarantees and exits immediately. No scan is performed.

```bash
cemi privacy
```

### Show installed version

```bash
cemi version
```

## Running tests

```bash
pytest
```

## Pre-release checklist

Before tagging a release, verify the following steps in order:

1. Verify tests pass:

   ```bash
   pytest
   ```

2. Install locally:

   ```bash
   pip install -e .[dev]
   ```

3. Run the tool end-to-end:

   ```bash
   cemi privacy
   cemi scan --output html
   cemi scan --output json
   cemi version
   ```

4. Confirm reports are saved locally under `reports/` and contain no unexpected data before sharing.

## Privacy

CEMÍ makes the following guarantees:

- No telemetry
- No network upload
- No browser history reading
- No cookie reading
- No personal document scanning
- Reports are local
