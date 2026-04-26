# CEMÍ — Computer Evidence Monitoring Inspector

CEMÍ is a local-first, privacy-first desktop security tool that inspects system metadata and configuration to help users understand the security posture of their machine. It never accesses personal files, never collects telemetry, and never transmits any data externally. All analysis, reports, and logs remain on the user's device under the user's control.

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

## Running tests

```bash
pytest
```

## Privacy

CEMÍ makes the following guarantees:

- No telemetry
- No network upload
- No browser history reading
- No cookie reading
- No personal document scanning
- Reports are local
