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
- Detects publicly exposed source maps (`sourceMappingURL`, inline base64, `js.map` + `sourcesContent` rescan)
- Recursive JS chunk discovery — follows references to other JS files (webpack chunks, dynamic imports)
- **JS Deobfuscation** — decodes Base64, hex, unicode, eval(), String.fromCharCode()
- **Endpoint Validation** — confirms endpoints are live, filters false positives (404s, soft-404s, SPA shells, JSON fail-in-200)
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

### ✅ Phase 1.1: JS extraction hardening (complete — Steps 1–6)
- **Step 1 — secret FP stack:** Shannon entropy (class-aware: hex/digit/lower ceilings), placeholder/template rejection (`changeme`, `your-*`, `{{…}}`, repeated/sequential fills), **proximity gate** for high-FP bare shapes (Twilio SID, Telegram bot token, Mailgun, Discord) — keyword must sit near the match; high-confidence vendor prefixes skip weak gates
- **Step 2 — structural secrets + type-aware dedup:** `process.env.X || "…"`, object `Authorization` / `X-API-Key` headers, `?client_secret=` query, Basic-auth object form; overlapping pattern hits keep the **most specific type** (span priority + match-collapsed dedup); Stripe Live Key is `sk_live_` only (`pk_live_` = Publishable)
- **Step 3 — source maps deep:** parse last `sourceMappingURL` (`//` and `/* */`, quoted), **inline `data:` base64/URI maps**, external map fetch with size caps, re-scan every `sourcesContent[]` entry for endpoints/secrets/sinks/JWTs; conventional `app.js.map` fallback
- **Step 4 — endpoint enrichment:** method inference from path verbs (`create`/`delete`/…), tags (`graphql`, `trpc`, `websocket`, `auth`, `api`, `admin`), `state_changing` + `likely_authed` hints on intercepted/SPA endpoint dicts (HTML Tags column); bare-string pools unchanged
- **Step 5 — validation hardening:** SPA index shell on API paths → **dead** (`note: spa_shell`); JSON fail-in-200 → `json_not_found` (dead) / `json_auth` (restricted) / `json_error` (live + note); soft-404 retained
- **Step 6 — tests + docs:** `test_secrets`, `test_sourcemaps`, `test_enrich`, `test_validator`; this README section; suite count **382 tests**
- Research refs: js-surgeon, jsrip, LinkFinder/SecretFinder, mapxtractor, Invicti API FP reduction, OWASP ASTF

### ✅ PII quick wins (complete — Steps 1–4)
- **Step 1 — detectors:** `modules/analysis/pii.py` — email (SaaS/analytics denylist + local-part stopwords), phone **E.164** (`+` + 8–15 digits), payment card (**Luhn** + IIN shape + test-PAN denylist), SSN (dashed form only, SSA area/group rules + sample denylist); source-map/base64 line skip; severity INFO (email/phone) or LOW (card/SSN)
- **Step 2 — pipeline wiring:** `extract_from_text` returns a **7-tuple** with PII; `pii_found` populated in static/browser/wayback/full scans; `fetch_and_extract` key `pii`; `merge_pii` for wayback fragments
- **Step 3 — reporting:** PII block in findings feed + executive summary count; HTML **Potential PII** section + PII Items stat tile
- **Step 4 — tests + docs:** `test_pii` + merge/render/feed coverage; this README section; suite count **416 tests**
- Severity is recon signal only (PII shape alone rarely bounty on H1/BB unless bulk cross-user / authz combo)

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

### ✅ Phase 2.1: CORS hardening (complete — Steps 1–5)
- **Step 1 — origin matrix:** tldextract registrable domains (correct for `co.uk` etc.), special-char/no-dot attackers (`evil_com`, `evilcom`), local-origin probes (`localhost`, `127.0.0.1`), alternate loopback forms (`127.1`, `0.0.0.0`, `[::1]`, decimal IP), third-party free-host suffixes (github.io, netlify.app, …), matrix capped at **25** origins
- **Step 2 — probe correctness:** response header `Access-Control-Allow-Private-Network` (was reading the request-side name); OPTIONS→GET escalates only when no *finding-worthy* ACAO (legit target ACAO no longer suppresses GET); no-Origin **baseline probe** (`static_acao`); cross-domain redirect **FP filter** (CORScanner-style); missing `Vary: Origin` noted on reflected dynamic ACAO; `severity_counts["ERROR"]` + `summary.error_probes`
- **Step 3 — severity notes + WAF pacing:** exploitation caveats on null/wildcard findings; `stage_cors` applies WAF `delay_multiplier` / `max_threads` / UA
- **Step 4 — perf:** shared `requests.Session` per scan (pooling, closed in `finally`); `RateLimiter` reserves the slot under lock and **sleeps outside** (threads not serialized during sleep)
- **Step 5 — tests + docs:** HTTP-layer `probe_endpoint`/`probe_baseline` coverage, escalation/error/session unit tests, WAF pacing tests, this README section
- Reference techniques: PortSwigger CORS labs, Nuclei `cors-misconfig`, CORScanner origin matrix/redirect filter, Fetch spec `Vary: Origin`

### ✅ Phase 2.2: CORS follow-through (complete — Steps 1–4)
- **Step 1 — stage order:** CORS runs **after** `validate` (`… spa → jwt → validate → cors → export`) so probes hit live endpoints only
- **Step 2 — trusted-seed re-probe:** static/third-party ACAO seeds (not reflection, not target) expand to lookalikes (`sub.<reg>`, `<reg>.evil.com`, `evil.<reg>`, path-bearing) and re-probe URLs that already returned ACAO (max 3 seeds × 5 lookalikes)
- **Step 3 — PoC HTML:** `modules/reporting/cors_poc.py` — credentialed XHR / null-iframe / bare-reflection snippets; collapsible **Proof of concept** blocks in the HTML report (CRITICAL/HIGH); standalone export via **`--cors-poc`** → `*_cors_poc.html`
- **Step 4 — tests + docs:** stage-order, seed expansion, PoC export/embed tests; this README section

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

### ✅ Phase 4: Combined pipeline + reporting (complete — Steps 1–8)
- **Step 1 — pipeline package:** `main.py` reduced to arg parsing + header assembly; orchestration lives in `modules/pipeline/` (`context` → `stages` → `runner`)
- **Step 2 — shared merge helpers:** `modules/pipeline/merge.py` — one dialect for wayback/SPA fragment merge, endpoint collection, secret/sink/JWT dedupe
- **Step 3 — risk integration:** CVE/OSV boost applied inside `calculate_risk_summary` so later recalculations (SPA/validation/wayback) preserve it; weights CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3
- **Step 4 — result schema:** every JSON report gets `schema_version: 1` + `meta` (tool, finished_at, duration, scan_mode, stages_run, stage_timings, flags)
- **Step 5 — HTML hardening:** all dynamic values escaped; distinct CRITICAL badge; WAF / Wayback historical JS / intercepted endpoints / scan-mode sections
- **Step 6 — findings feed:** cross-module `findings` list + `executive_summary` (risk, severity counts, top findings, module coverage) in JSON and HTML
- **Step 7 — report builder:** `modules/reporting/builder.py` — single path computation for JSON/HTML/Burp/ZAP outputs
- **Step 8 — integration tests:** offline end-to-end pipeline tests (stage order, schema contract, on-disk reports) in `tests/test_integration.py`
- Stage order: `waf_detect → wayback_fetch → scan → wayback_merge → waf_inject → cve → spa → jwt → validate → cors → export → report`
- Unit + integration suite: **416 tests** (`test_cors`, `test_jwt`, `test_pipeline`, `test_integration`, `test_secrets`, `test_sourcemaps`, `test_enrich`, `test_validator`, `test_pii`)

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
| `--cors-poc` | Write standalone CORS PoC HTML next to the report |
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
│   │   ├── patterns.py           # Regex patterns, noise/static-asset filters, secret FP gates
│   │   ├── secrets.py            # Secret detection, structural patterns, type-aware dedup
│   │   ├── http.py               # Rate limiter, retry, fetching
│   │   ├── scope.py              # Domain/scope utilities
│   │   ├── risk.py               # Risk scoring
│   │   ├── ast.py                # AST extraction (tree-sitter)
│   │   ├── browser.py            # Browser extraction (Playwright)
│   │   ├── sourcemaps.py         # sourceMappingURL / sourcesContent reconstruction
│   │   ├── enrich.py             # Endpoint method/tags/auth enrichment
│   │   └── deobfuscator.py       # JS deobfuscation
│   ├── discovery/                # Expand attack surface
│   │   ├── __init__.py
│   │   ├── spa.py                # SPA route discovery
│   │   └── wayback.py            # Wayback Machine integration
│   ├── analysis/                 # Analyze findings
│   │   ├── __init__.py
│   │   ├── validator.py          # Endpoint validation
│   │   ├── libraries.py          # Library version + CVE detection
│   │   ├── sinks.py              # Dangerous JS sink detection (XSS/open-redirect patterns)
│   │   └── pii.py                # PII quick wins (email / E.164 phone / Luhn card / dashed SSN)
│   ├── recon/                    # Target reconnaissance
│   │   ├── __init__.py
│   │   └── waf.py                # WAF detection
│   ├── pipeline/                 # Phase 4: ordered scan orchestration
│   │   ├── __init__.py           # Public API (run_pipeline, merge helpers)
│   │   ├── context.py            # ScanContext (args, result, stage timings)
│   │   ├── stages.py             # One function per pipeline stage
│   │   ├── merge.py              # Shared wayback/SPA/endpoint merge helpers
│   │   └── runner.py             # Stage order + schema/meta stamping
│   ├── reporting/                # Output generation
│   │   ├── __init__.py
│   │   ├── html.py               # HTML/JSON report generation
│   │   ├── export.py             # Burp/ZAP CSV export
│   │   ├── findings.py           # Cross-module findings feed + exec summary
│   │   ├── builder.py            # Unified report path/output builder
│   │   └── cors_poc.py           # CORS PoC HTML (embed + --cors-poc export)
│   ├── cors/                     # Phase 2: CORS misconfiguration scanner
│   │   ├── __init__.py           # Public API re-exports
│   │   ├── origins.py            # Origin build/normalize/compare (Phase 2.1 matrix)
│   │   ├── classifier.py         # Severity classification + exploitation notes
│   │   ├── probe.py              # Preflight + GET/POST, baseline, redirect FP filter
│   │   └── scanner.py            # Prioritize, aggregate, rate limit, risk boost, Session
│   ├── jwt/                      # Phase 3: JWT security analyzer
│   │   ├── __init__.py           # Public API re-exports
│   │   ├── decode.py             # base64url, extract, dedupe, decode
│   │   ├── crack.py              # wordlists, HMAC verify, key-confusion forge
│   │   ├── keys.py               # SSRF guard, RSA JWK→PEM, JWKS fetch
│   │   ├── checks.py             # single-token analysis + severity
│   │   └── scanner.py            # scan orchestration, summary, risk boost
├── tests/                        # Unit + integration tests (stdlib unittest)
│   ├── test_cors.py
│   ├── test_jwt.py
│   ├── test_pipeline.py
│   ├── test_integration.py       # Offline end-to-end pipeline (Phase 4 Step 8)
│   ├── test_secrets.py           # Phase 1.1 Steps 1–2 (FP stack + structural)
│   ├── test_sourcemaps.py        # Phase 1.1 Step 3
│   ├── test_enrich.py            # Phase 1.1 Step 4
│   ├── test_validator.py         # Phase 1.1 Step 5
│   └── test_pii.py               # PII quick wins Steps 1–2
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

### Phase 1.1 — secret FP + source maps + enrichment (unit)
- Suite after Phase 1.1: **382 tests** (was 270)
- Proximity gate: bare `AC…` / Telegram-shaped blobs without nearby keyword dropped; same values kept next to `accountSid` / `bot_token`
- Source maps: last `sourceMappingURL` wins; inline base64 maps decode and `sourcesContent` rescanned for endpoints + secrets
- Validation: API path + `#root`/`#__next` HTML shell → dead; `{"error":"unauthorized"}` on 200 → restricted; `{"error":"not found"}` → dead

### PII quick wins (unit)
- Suite after PII: **416 tests** (was 382)
- Email: `alerts@sentry.io` / `noreply@…` / `…@example.com` dropped; `alice.smith@corp-target.io` kept
- Phone: bare `4155552671` rejected; only strict E.164 `+14155552671`
- Card: test PAN `4111…` denylisted; Luhn-valid `4532015112830366` reported (LOW); separators normalized
- SSN: dashed only; `219-09-9999` / `123-45-6789` / area `000`/`666`/`9xx` rejected; bare 9 digits not SSN
- `extract_from_text` now returns a 7-tuple ending in `pii`; reports get `pii_found` + HTML section

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
- **CORS PNA header name** — read response `Access-Control-Allow-Private-Network` (Phase 2.1 Step 2)
- **CORS OPTIONS-only escalation FN** — GET still runs when preflight only returns legitimate target ACAO (Phase 2.1 Step 2)
- **CORS registrable-domain FP** — naive last-two-labels → tldextract via `get_registrable_domain` (Phase 2.1 Step 1)
- **RateLimiter lock-while-sleep** — sleep outside the lock so probe threads are not serialized (Phase 2.1 Step 4)
- **Stripe pk_live double-count** — Live Key pattern was `[sp]k_live_` matching Publishable too; now `sk_live_` only + span-priority dedup (Phase 1.1 Step 2)
- **Source maps: comment/base64 ignored** — only `js_url + ".map"` probed; now full `sourceMappingURL` / `sourcesContent` path (Phase 1.1 Step 3)

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
- ~~Phase 2.1: CORS hardening~~ ✅ Done (Steps 1–5)
- ~~Phase 2.2: CORS follow-through~~ ✅ Done (Steps 1–4)
- ~~Phase 3: JWT security analyzer~~ ✅ Done (Steps 1–6)
- ~~Phase 4: Combined pipeline + reporting~~ ✅ Done (Steps 1–8)
- ~~Phase 1.1: JS extraction hardening~~ ✅ Done (Steps 1–6)
- Diff mode to compare two scans of the same target over time
- ~~Secret-pattern false-positive tuning (Twilio SID / Telegram Bot Token seen on mintlify)~~ ✅ Done (Phase 1.1 Step 1)
- ~~PII quick wins~~ ✅ Done (Steps 1–4)

## Responsible use
Built and tested only against intentionally vulnerable/legal test targets
(OWASP Juice Shop, local Flask testbed, kickbacks.ai with permission).
Do not run against systems you don't own or don't have authorization to test.
