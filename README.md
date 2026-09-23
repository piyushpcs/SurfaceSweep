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

### ✅ Phase 2: CORS Misconfiguration Scanner (complete — Steps 1–4)
- Sends spoofed `Origin` headers to discovered endpoints (real preflight: `Access-Control-Request-Method`/`Headers` + GET/POST fallback)
- Origin matrix: evil/null, path-bearing Origins, scheme/port flips on target host, subdomain/lookalike domains, custom origin
- Normalized origin comparison (case, default ports, trailing slash) + registrable-domain awareness
- Multi-value ACAO parsing — flags non-singleton (comma-separated) lists as MEDIUM
- Evidence on each finding: `Vary`, `Allow-Methods/Headers`, `Max-Age`
- POST fallback for API-like paths when OPTIONS/GET return no ACAO
- Severity: CRITICAL (arbitrary reflected + credentials / null + credentials) → HIGH → MEDIUM → LOW → INFO
- Legitimate target origin reflection reported as INFO (not a finding)
- Rate-limited probes (`--cors-rps`, default 5/sec)
- Follows redirects and reads ACAO on the final response (apex → www etc.)
- API-first endpoint prioritization when `--cors-max` truncates the list
- Extra probe origins from hosts seen in scanned JS (`collect_js_origins`)
- Findings aggregated **one row per URL** (worst severity; all flagged origins listed)
- CLI: `--cors-threads` (default 6), `--cors-timeout` (default 5s)
- Risk boost: CRITICAL=25, HIGH=15, MEDIUM=8 per flagged URL
- **HTML report (Step 4):** severity/coverage stat cards, **Origin × URL matrix**, findings table (origins flagged, methods, hits, redirect final URL, evidence), JSON `schema_version`
- **JSON shape:** `schema_version: 1`, top-level `findings` / `probe_hits` / `endpoints_tested` / `origins` / `severity_counts` / `summary`

### ✅ Phase 3: JWT Security Analyzer (complete — Steps 1–6)
- Extracts compact JWTs (`header.payload.sig`) from JS/HTML scan results
- **Step 3 pipeline wiring:** `extract_from_text` returns JWTs; `jwts_found` populated in static/browser/wayback/full scans and merged/deduped across modes
- Decodes header/payload offline (stdlib base64/json — no network, no PyJWT)
- Flags: `alg=none`, weak/`kid` path traversal, `jku`/`x5u` URL injection, missing/long-lived `exp`, privileged claims
- Offline HS256/384/512 crack attempt against a built-in weak wordlist + secrets found in the same scan
- **Step 4 cracking:** expanded builtin wordlist (~100), `--jwt-wordlist FILE`, target-host mutations, hashcat `-m 16500` export via `--jwt-hashcat FILE`, `crack_meta` counts in report
- **Step 5 reporting parity:** JSON `schema_version: 1` + `summary` (severity/issue/crack counts), HTML severity stat cards, HTML-escaped findings table, per-token NDJSON export via `--jwt-export FILE`
- **Step 6 network (optional, `--jwt-network`):** SSRF-guarded `jku`/`x5u` JWKS fetch → RSA PEM; **RS256→HS256 key-confusion PoC** (offline re-sign with public key material — CRITICAL when forge succeeds); works offline too when `jwk` is embedded in the token
- **Step 2 offline hardening:** embedded `jwk` object, `x5c` chain, `crit` header, empty/null signature, `alg=none` with leftover signature, placeholder/low-entropy signature, `kid` SQLi metacharacters, missing `iss`/`aud`, high-entropy payload claims (possible embedded secrets)
- Severity: CRITICAL (alg none / cracked HMAC / empty signature / key-confusion forge) → HIGH → MEDIUM → LOW → INFO
- Risk boost: CRITICAL=25, HIGH=15, MEDIUM=8 per finding — **preserved across `--validate`/wayback/SPA recalculation** (Step 1)
- Unit tests: `tests/test_jwt.py` (decode, crack, analysis, Steps 2–6, risk boost, report shape)

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
| `--cors` | Scan discovered endpoints for CORS misconfigurations |
| `--cors-origin` | Custom Origin header to test (default: built-in test set) |
| `--cors-max` | Max endpoints to CORS-test (default: 50) |
| `--cors-rps` | CORS probe rate limit req/s (default: 5, 0=unlimited) |
| `--cors-threads` | CORS probe threads (default: 6) |
| `--cors-timeout` | CORS per-request timeout seconds (default: 5) |
| `--jwt` | Analyze JWTs found in scanned content (alg/none, weak HMAC, exp, claims) |
| `--jwt-wordlist` | Extra newline-delimited secrets for offline HS* cracking |
| `--jwt-hashcat` | Export HS* JWTs to FILE in hashcat mode 16500 format |
| `--jwt-export` | Write per-token JWT findings as NDJSON to FILE |
| `--jwt-network` | Fetch jku/x5u JWKS over network for key-confusion checks (SSRF-guarded) |
| `--jwt-network-timeout` | JWKS fetch timeout seconds (default: 5) |
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

# CORS misconfiguration scan
python main.py https://target.com --cors --cors-origin https://evil.com --html

# JWT security analysis with custom wordlist + exports + optional JWKS fetch
python main.py https://target.com --jwt --jwt-wordlist secrets.txt --jwt-hashcat hs_tokens.txt --jwt-export findings.ndjson --jwt-network --html
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
│   ├── cors/                     # Phase 2: CORS misconfiguration scanner
│   │   ├── __init__.py           # Public API re-exports
│   │   ├── origins.py            # Origin build/normalize/compare
│   │   ├── classifier.py         # Severity classification
│   │   ├── probe.py              # Preflight + GET/POST probing
│   │   └── scanner.py            # Prioritize, aggregate, rate limit, risk boost
│   └── jwt_analyzer.py           # Phase 3: JWT security analyzer
├── tests/                        # Unit tests (stdlib unittest)
│   └── test_cors.py
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
- New finds not in HTML: `/partners`, `/surface-pricing`, `/api/advertiser/v1/claude.md`, `/info`, `/logout`
- All validated: `/partners` (200), `/info` (200), `/logout` (405), `/api/advertiser/v1/status` (200)

### CORS Step 2 (mintlify.com)
Target: `https://mintlify.com` (apex 307-redirects to `https://www.mintlify.com`)

| Check | Result |
|-------|--------|
| Endpoints probed | `/`, `/pricing`, `/login`, `/security-policy`, `/docs`, `/api/auth/session` |
| Origin matrix sample | `evil.com`, path-bearing `evil.com/path`, `null`, `mintlify.com.evil.com`, `evil.mintlify.com` |
| Findings | 20× **MEDIUM** — `Access-Control-Allow-Origin: *` (no credentials) |
| Flagged URLs | `/`, `/pricing` (OPTIONS); `/login`, `/security-policy` (GET fallback) |
| Not flagged | `/docs`, `/api/auth/session` (no ACAO) |
| Final responses | All on `https://www.mintlify.com/...` after redirect |
| Evidence captured | `Methods: OPTIONS, GET, HEAD` / `Vary: accept-encoding` |
| Risk boost | 160 (20 × MEDIUM weight) |
| Reportable? | **No** — wildcard without credentials on public pages; not a vuln |

Redirect handling fix verified on this target: probes without following redirects saw only `307` + empty ACAO (false negative).

### CORS Step 3 (biharbhawan.gov.in)
Target: `https://biharbhawan.gov.in/`

| Check | Result |
|-------|--------|
| Scan mode | Static `-d 0`, 53 JS files, API-first prioritization |
| Endpoints tested | 1 (only `/translate_a/l` extracted as internal path) |
| Origin matrix | 22 origins (built-in + JS-seen: `192.168.100.230`, `ceobihar`, doc hosts) |
| Findings | **0** — no `Access-Control-Allow-Origin` on probed paths |
| Manual spot-check | `/`, `/login`, `/admin`, auth JS paths, GET+OPTIONS — ACAO empty |
| Risk boost | 0 (no CORS findings) |
| Reportable? | **No CORS issue** — site does not emit ACAO headers |

Manual confirmation: `GET /` with `Origin: https://evil.com` → HTTP 200, ACAO/ACAC absent (not a redirect false negative).

Aggregation check (local testbed): 348 probe hits → **21 URL rows** (worst severity per URL).

### CORS Step 4 — reporting polish (testbed :5555)
- HTML: stat cards (Critical/High/Medium/Low, URLs flagged, endpoints, origins, probe hits) + **Origin × URL matrix** + findings table
- JSON: `schema_version: 1` + `summary` block for consumers
- Verified via unit tests (matrix, summary, schema keys, severity order sync with classifier)

### Local testbed (Flask :5555)
- CRITICAL: arbitrary origin reflected + credentials, `null` + credentials
- HIGH: related/same-site reflect + credentials; wildcard + credentials (invalid combo)
- MEDIUM: wildcard `*`, non-singleton (comma-separated) ACAO lists
- INFO: legitimate target origin (not reported as a finding)
- POST-only CORS path exercised via API-like POST fallback

### Fixed bugs
- **False-positive source map detection** — now validates JSON content before flagging
- **Validation URL filtering** — now uses base domain instead of full target URL
- **Missing risk_summary in browser mode** — now calculates risk score
- **Protocol-relative URL leak** — `//` URLs no longer leak into internal_paths
- **CORS redirect false negatives** — probes follow redirects; ACAO read from final response
- **`--validate`/wayback/SPA wiping CORS+JWT risk boosts** — `calculate_risk_summary` now re-applies analysis boosts on every recalculation (Phase 3 Step 1)

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
- ~~Phase 2: CORS misconfiguration scanner~~ ✅ Done (Steps 1–4)
- ~~Phase 3: JWT security analyzer~~ ✅ Done (Steps 1–6)
- Phase 4: Combined pipeline + reporting
- Diff mode to compare two scans of the same target over time
- Secret-pattern false-positive tuning (Twilio SID / Telegram Bot Token seen on mintlify)
- PII quick wins

## Responsible use
Built and tested only against intentionally vulnerable/legal test targets
(OWASP Juice Shop, local Flask testbed, kickbacks.ai with permission).
Do not run against systems you don't own or don't have authorization to test.
