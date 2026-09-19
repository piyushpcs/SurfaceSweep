# SurfaceSweep

A recon tool that extracts API endpoints and secrets from a target's JavaScript files, and checks discovered endpoints for CORS misconfigurations. Built while learning offensive web security.

## Status

### ✅ Phase 1: JS Endpoint Extractor (complete)
- Scans external and inline `<script>` sources
- Detects likely API endpoints and full URLs via regex
- Flags leaked secrets/API keys in JS (AWS keys, bearer tokens, generic secrets)
- Detects publicly exposed `.js.map` source map files
- Scopes results into internal paths, in-scope URLs, and out-of-scope URLs
- Concurrent fetching, JSON output

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
