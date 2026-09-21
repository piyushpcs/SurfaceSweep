# SurfaceSweep

A recon tool that extracts API endpoints and secrets from a target's JavaScript files, and checks discovered endpoints for CORS misconfigurations. Built while learning offensive web security.

## Status

### ✅ Phase 1: JS Endpoint Extractor (complete)
- Scans external and inline `<script>` sources
- Detects likely API endpoints and full URLs via regex
- Extracts endpoints from `fetch()`, `axios.*()`, `$.ajax()`, `$.get/post()` calls
- Flags leaked secrets/API keys (AWS, GitHub, GitLab, Stripe, Firebase, npm, Bearer tokens, env vars)
- Detects publicly exposed `.js.map` source map files
- Recursive JS chunk discovery — follows references to other JS files (webpack chunks, dynamic imports)
- Scopes results into internal paths, in-scope URLs, and out-of-scope URLs
- Rate limiting, retry with backoff, robots.txt-aware politeness
- Secret deduplication — same key across multiple files shown once with all sources
- Risk scoring summary per scan
- JSON and HTML report output

### 🚧 Phase 2: CORS Misconfiguration Scanner (in progress)
- Sends spoofed `Origin` headers to discovered endpoints
- Flags wildcard and reflected-origin misconfigurations
- Distinguishes severity based on whether credentials are also allowed

### ⏳ Phase 3: JWT Security Analyzer (planned)
### ⏳ Phase 4: Combined pipeline + reporting (planned)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py https://target.com
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output JSON file (default: `reports/surfacesweep_report.json`) |
| `-t, --threads` | Concurrent fetch threads (default: 6) |
| `-d, --depth` | Recursive JS depth: 0=HTML only, 1=JS from HTML, 2=JS from JS, ... (default: 1) |
| `--html` | Also generate an HTML report |
| `--html-only` | Generate HTML report only (skip JSON) |
| `-q, --quiet` | Suppress progress output |

### Examples

```bash
# Basic scan
python main.py https://target.com

# Deep scan (follow JS references 2 levels deep) with HTML report
python main.py https://target.com -d 2 --html

# Quiet mode, custom output
python main.py https://target.com -q -o my_report.json --html
```

## Test results (Phase 1)

Tested against OWASP Juice Shop (local Docker instance):
- Found 3 JS files + 1 inline script
- Extracted 27 unique endpoint/URL references
- 0 internal API paths detected — see limitation below

### Known limitation: static regex misses concatenated endpoints
Angular (and other SPA frameworks) frequently build API URLs via string
concatenation, e.g. `environment.hostServer + '/rest/products'`. Static
regex over raw JS text cannot see across this split, so real API paths
built this way are missed. Confirmed on Juice Shop, which has a REST API
that produced zero matches despite clearly existing.

### Fixed bug: false-positive source map detection
Initial detection relied on HTTP status code alone. Servers using SPA
fallback routing return `200 + index.html` for *any* unmatched path,
including `/whatever.js.map` — producing false positives on every scan.
Fixed by validating the response is actually JSON (checking both
`Content-Type` and the first character of the response body) before
flagging a source map as exposed.

## Roadmap
- Headless browser mode (Playwright) to capture runtime API calls and solve
  the static-regex concatenation limitation. Attempted, but currently
  blocked by the Chromium binary failing to download on this network —
  revisiting later.
- JSON/CSV export options for pipeline integration
- Diff mode to compare two scans of the same target over time

## Responsible use
Built and tested only against intentionally vulnerable/legal test targets
(OWASP Juice Shop, local Flask testbed). Do not run against systems you
don't own or don't have authorization to test.
