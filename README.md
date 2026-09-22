# SurfaceSweep

A recon tool that extracts API endpoints and secrets from a target's JavaScript files, validates discovered endpoints, and exports results for Burp Suite/ZAP. Built while learning offensive web security.

## Status

### ✅ Phase 1: JS Endpoint Extractor (complete)
- **Static mode** — regex-based extraction from HTML and JS files
- **AST-based extraction** — tree-sitter parses JS into an Abstract Syntax Tree for precise endpoint discovery (complements regex)
- **Browser mode** — headless Chromium captures runtime API calls, lazy-loaded chunks, and dynamic endpoints
- **Full scan** — runs both modes and merges results for best coverage
- Detects likely API endpoints and full URLs via regex
- Extracts endpoints from `fetch()`, `axios.*()`, `$.ajax()`, `$.get/post()` calls
- Flags leaked secrets/API keys (60+ patterns: AWS, OpenAI, Anthropic, Twilio, SendGrid, Discord/Slack webhooks, Postman, Shopify, Cloudinary, Mapbox, GitHub, GitLab, Stripe, PayPal, Firebase, npm, PyPI, Bearer/JWT tokens, env vars, private keys, database URLs, SMTP credentials, passwords, OAuth secrets)
- Detects dangerous JS sinks (innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html, jQuery HTML, open redirect patterns) with severity ratings
- Detects internal/private host references (localhost, private IPs 10/172/192.168, *.internal/*.corp hostnames, dev/staging subdomains)
- Detects publicly exposed `.js.map` source map files
- Recursive JS chunk discovery — follows references to other JS files (webpack chunks, dynamic imports)
- **JS Deobfuscation** — decodes Base64, hex, unicode, eval(), String.fromCharCode()
- **Endpoint Validation** — confirms endpoints are live, filters false positives (404s, soft-404s)
- **WAF Detection** — identifies Cloudflare, Akamai, AWS WAF, Imperva, etc.
- **Wayback Machine** — finds historical JS files no longer linked
- **Burp/ZAP Export** — CSV output for import into proxy tools
- **Library Version Detection** — identifies JS library versions (jQuery, Bootstrap, Lodash, etc.) from content and filenames
- **CVE Lookup** — checks detected libraries against local vulnerability database and OSV.dev API
- **SPA Route Discovery** — finds hidden routes from React/Vue/Angular routers via static analysis, DOM inspection, router introspection, and BFS crawl
- Scopes results into internal paths, in-scope URLs, and out-of-scope URLs
- Rate limiting, retry with backoff
- Secret deduplication — same key across multiple files shown once with all sources
- Risk scoring summary per scan
- JSON and HTML report output
- Custom headers/cookies for authenticated scans

### 🚧 Phase 2: CORS Misconfiguration Scanner (in progress)
- Sends spoofed `Origin` headers to discovered endpoints
- Flags wildcard and reflected-origin misconfigurations
- Distinguishes severity based on whether credentials are also allowed

### ⏳ Phase 3: JWT Security Analyzer (planned)
### ⏳ Phase 4: Combined pipeline + reporting (planned)

## Setup

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Dependencies include `tree-sitter` + `tree-sitter-javascript` for AST extraction (installs from prebuilt wheels, no compiler needed). If unavailable, the tool falls back to regex-only automatically.

## Usage

```bash
# Static mode (fast, no browser)
python main.py https://target.com

# Browser mode (captures runtime endpoints)
python main.py https://target.com --browser

# Full scan — both modes combined (best coverage)
python main.py https://target.com --full --html

# Full scan with all features
python main.py https://target.com -f --validate --burp --zap --waf --html
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output JSON file (default: `reports/surfacesweep_report.json`) |
| `-t, --threads` | Concurrent fetch threads (default: 6) |
| `-d, --depth` | Recursive JS depth: 0=HTML only, 1=JS from HTML, 2=JS from JS, ... (default: 1) |
| `-b, --browser` | Use headless browser mode (captures runtime API calls) |
| `-f, --full` | Run both static + browser and merge results (best coverage) |
| `--validate` | Validate discovered endpoints to filter false positives |
| `--vt` | Validation threads (default: 10) |
| `--vtimeout` | Validation timeout in seconds (default: 5) |
| `--burp` | Export endpoints as Burp Suite CSV |
| `--zap` | Export endpoints as OWASP ZAP CSV |
| `--wayback` | Include historical JS files from Wayback Machine |
| `--waf` | Detect WAF and adjust scan speed |
| `--cve` | Detect JS library versions and check local CVE database |
| `--osv` | Query OSV.dev for additional CVEs (requires network) |
| `--spa` | Discover SPA routes (React/Vue/Angular routers, BFS crawl) |
| `--max-routes` | Max routes to crawl in SPA mode (default: 50) |
| `--no-probe` | Skip probing common admin/debug routes in SPA mode |
| `--cookie` | Cookie header for authenticated scans |
| `--header` | Custom header (repeatable: `-H 'X-Api-Key: value'`) |
| `--timeout` | Browser page load timeout in seconds (default: 30) |
| `--scope` | Limit results to this domain (e.g. `*.target.com`) |
| `--html` | Also generate an HTML report |
| `--html-only` | Generate HTML report only (skip JSON) |
| `--no-deobf` | Skip JS deobfuscation |
| `--regex-only` | Disable AST extraction, use regex only |
| `-q, --quiet` | Suppress progress output |

### Examples

```bash
# Basic static scan
python main.py https://target.com

# Browser mode — catches runtime endpoints
python main.py https://target.com --browser --html

# Full scan with validation (filters false positives)
python main.py https://target.com -f --validate --html

# Export for Burp Suite
python main.py https://target.com -f --burp --zap

# Authenticated scan
python main.py https://target.com --cookie "session=abc123" --header "X-Api-Key: value"

# Full recon with all features
python main.py https://target.com -f --validate --burp --zap --waf --wayback --cve --spa --html

# CVE check only (fast, no browser)
python main.py https://target.com --cve --osv --html

# SPA route discovery only
python main.py https://target.com --spa --validate --html
```

## Project Structure

```
SurfaceSweep/
├── main.py                       # CLI entry point
├── modules/
│   ├── __init__.py               # Package overview
│   ├── extraction/               # Core JS content extraction (Phase 1)
│   │   ├── __init__.py           # Public API re-exports
│   │   ├── engine.py             # Main orchestration (run_extractor, merge_results)
│   │   ├── patterns.py           # Regex patterns, noise/static-asset filters
│   │   ├── secrets.py            # Secret detection + deduplication
│   │   ├── http.py               # Rate limiter, retry, fetching
│   │   ├── scope.py              # Domain/scope utilities
│   │   ├── risk.py               # Risk scoring
│   │   ├── ast.py                # AST extraction (tree-sitter)
│   │   ├── browser.py            # Browser extraction (Playwright)
│   │   └── deobfuscator.py       # JS deobfuscation
│   ├── discovery/                # Expand attack surface
│   │   ├── __init__.py
│   │   ├── spa.py                # SPA route discovery
│   │   └── wayback.py            # Wayback Machine integration
│   ├── analysis/                 # Analyze findings
│   │   ├── __init__.py
│   │   ├── validator.py          # Endpoint validation
│   │   ├── libraries.py          # Library version + CVE detection
│   │   └── sinks.py              # Dangerous JS sink detection (XSS/open-redirect patterns)
│   ├── recon/                    # Target reconnaissance
│   │   ├── __init__.py
│   │   └── waf.py                # WAF detection
│   ├── reporting/                # Output generation
│   │   ├── __init__.py
│   │   ├── html.py               # HTML/JSON report generation
│   │   └── export.py             # Burp/ZAP CSV export
│   ├── cors_scanner.py           # Phase 2: CORS scanner (planned)
│   └── jwt_analyzer.py           # Phase 3: JWT analyzer (planned)
├── testbed/
│   └── vuln_api.py               # Test Flask app
└── reports/                      # Generated reports
```

## Test Results

Tested against `https://kickbacks.ai/security-policy` (real target):

| Feature | Result |
|---------|--------|
| Static scan (AST + regex) | 62 endpoints from 8 JS files |
| Browser scan | 31 endpoints, 2 XHR/fetch intercepted |
| Combined | 74 endpoints |
| Validation | 41 live, 3 restricted, 40 dead filtered |
| Burp/ZAP CSV | 35-37 endpoints exported |
| WAF | No WAF detected |

### AST vs regex comparison (same target)
- Regex only: 53 endpoints
- AST + regex: 62 endpoints (+17%)
- AST-only finds included `/login?next=...`, `/me`, `/debug/bootstrap?id=`, `/me#partner-sharing`

### CVE detection (gtec.ac.in)
- Detected: jQuery 1.11.0, Vue.js 2.1.5, FancyBox 2.1.5
- Found 4 CVEs: CVE-2020-11022/11023 (jQuery XSS), CVE-2019-11358 (jQuery prototype pollution), CVE-2024-6783 (Vue XSS), CVE-2024-5020 (FancyBox XSS)
- Risk boosted from INFO(0) to HIGH(32)

### SPA route discovery (kickbacks.ai)
- Found 20 routes: 9 DOM, 7 BFS crawl, 2 common probe, 2 static
- New finds not in HTML: `/partners`, `/surface-pricing`, `/api/advertiser/claude.md`, `/info`, `/logout`
- All validated: `/partners` (200), `/info` (200), `/logout` (405), `/api/advertiser/v1/status` (200)

### Fixed bugs
- **False-positive source map detection** — now validates JSON content before flagging
- **Validation URL filtering** — now uses base domain instead of full target URL
- **Missing risk_summary in browser mode** — now calculates risk score
- **Protocol-relative URL leak** — `//` URLs no longer leak into internal_paths

## Roadmap
- ~~Headless browser mode (Playwright)~~ ✅ Done
- ~~JS Deobfuscation~~ ✅ Done
- ~~Endpoint Validation~~ ✅ Done
- ~~Burp/ZAP Export~~ ✅ Done
- ~~WAF Detection~~ ✅ Done
- ~~Wayback Machine Integration~~ ✅ Done
- ~~AST-based extraction~~ ✅ Done
- ~~Library version + CVE detection~~ ✅ Done
- ~~SPA route crawling~~ ✅ Done
- Diff mode to compare two scans of the same target over time
- Phase 2: CORS misconfiguration scanner (in progress)

## Responsible use
Built and tested only against intentionally vulnerable/legal test targets
(OWASP Juice Shop, local Flask testbed, kickbacks.ai with permission).
Do not run against systems you don't own or don't have authorization to test.
