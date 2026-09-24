<div align="center">

# SurfaceSweep

**JavaScript attack-surface recon for bug bounty and penetration testing**

Extract API endpoints and secrets from a target's JavaScript, validate what is live,
check CORS and JWT issues, and export results for Burp Suite / ZAP.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-416%20passing-brightgreen)](#testing)
[![License](https://img.shields.io/badge/license-None-lightgrey)](#responsible-use)
[![Last commit](https://img.shields.io/github/last-commit/piyushpcs/SurfaceSweep)](https://github.com/piyushpcs/SurfaceSweep/commits/main)
[![Standard Readme](https://img.shields.io/badge/readme-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

[Features](#features) ·
[Install](#install) ·
[Usage](#usage) ·
[Options](#options) ·
[Architecture](#architecture) ·
[Testing](#testing) ·
[Roadmap](#roadmap)

</div>

---

## Why SurfaceSweep?

Modern SPAs hide real API traffic in obfuscated bundles, source maps, lazy chunks, and runtime XHR.
SurfaceSweep combines **static analysis (regex + AST)**, **headless browser capture**, and **historical JS (Wayback Machine)**
to build a single inventory of endpoints, then layers on checks that matter in a bounty program:

| Capability | What you get |
|------------|--------------|
| Endpoint discovery | `fetch` / `axios` / jQuery, SPA routers, nested chunks, historical JS |
| Secret hunting | 60+ patterns with entropy, placeholder, and proximity false-positive gates |
| Validation | Live / restricted / dead / soft-404 / SPA-shell classification |
| CORS | Spoofed Origin matrix, preflight + GET/POST, redirect-aware, PoC HTML |
| JWT | Offline decode, weak-HMAC crack, `alg=none`, JWKS key-confusion (optional network) |
| Risk | Weighted score (CVE + CORS + JWT) with evidence in JSON and HTML reports |

## Features

### Extraction

- **Static mode** — regex extraction from HTML and JS (fast, no browser)
- **AST mode** — tree-sitter parses JavaScript for precise call-site endpoints (falls back to regex if unavailable)
- **Browser mode** — Playwright/Chromium captures runtime XHR/fetch, lazy-loaded chunks, and dynamic endpoints
- **Full scan** — runs static + browser and merges results
- Recursive chunk discovery (webpack chunks, dynamic imports)
- **JS deobfuscation** — Base64, hex, unicode, `eval()`, `String.fromCharCode()`
- **Source maps** — `sourceMappingURL` comments, inline base64 maps, `sourcesContent` re-scan for endpoints/secrets/sinks/JWTs
- **Wayback Machine** — historical JS no longer linked from the live site
- **SPA route discovery** — React/Vue/Angular routers via static analysis, DOM, router introspection, and BFS crawl

### Detection

- Likely API endpoints and full URLs
- Leaked secrets / API keys (AWS, OpenAI, Anthropic, Twilio, SendGrid, Stripe, GitHub, Firebase, private keys, SMTP, OAuth, Bearer/JWT, …) with type-aware dedup
- Dangerous sinks (`innerHTML`, `eval`, `dangerouslySetInnerHTML`, open-redirect patterns) with severity
- Internal / private hosts (localhost, RFC1918, `*.internal` / `*.corp`, dev & staging subdomains)
- Potential **PII** (email, E.164 phone, Luhn payment cards, dashed SSNs) — recon signal only, not scored as a finding
- Library versions (jQuery, Vue, Bootstrap, Lodash, …) and **CVEs** (local DB + optional OSV.dev)
- **WAF detection** (Cloudflare, Akamai, AWS WAF, Imperva, …) with automatic pacing

### Analysis & export

- **Endpoint validation** — filters 404s, soft-404s, SPA shells, JSON fail-in-200
- **CORS scanner** — origin matrix, non-singleton ACAO, redirect FP filter, rate limits, standalone PoC HTML
- **JWT analyzer** — offline HS* cracking, wordlist/hashcat export, SSRF-guarded JWKS fetch for RS256→HS256 checks
- Scope split: internal paths, in-scope URLs, out-of-scope URLs
- Risk scoring summary per scan
- **JSON** and **HTML** reports (`schema_version: 1`, executive summary, findings feed)
- **Burp Suite** / **OWASP ZAP** CSV export
- Authenticated scans via cookies and custom headers
- Rate limiting and retry with backoff

## Install

Requires **Python 3.10+**.

```bash
git clone https://github.com/piyushpcs/SurfaceSweep.git
cd SurfaceSweep
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

`tree-sitter` and `tree-sitter-javascript` install from prebuilt wheels (no compiler needed).
If the AST stack is unavailable, SurfaceSweep automatically falls back to regex-only extraction.

## Usage

```bash
# Static mode (fast, no browser)
python main.py https://target.com

# Browser mode — captures runtime API calls
python main.py https://target.com --browser

# Full scan with validation + reports (best coverage)
python main.py https://target.com --full --validate --html

# Everything on
python main.py https://target.com -f --validate --burp --zap --waf --wayback --cve --spa --cors --jwt --html
```

### More examples

```bash
# Authenticated scan
python main.py https://target.com --cookie "session=abc123" -H "X-Api-Key: value"

# Export for Burp Suite / ZAP
python main.py https://target.com -f --burp --zap

# CVE check only (fast, no browser)
python main.py https://target.com --cve --osv --html

# SPA route discovery only
python main.py https://target.com --spa --validate --html

# CORS misconfiguration scan with custom Origin
python main.py https://target.com --cors --cors-origin https://evil.com --html

# JWT analysis + wordlist crack + hashcat/NDJSON exports + optional JWKS fetch
python main.py https://target.com --jwt --jwt-wordlist secrets.txt \
  --jwt-hashcat hs_tokens.txt --jwt-export findings.ndjson --jwt-network --html
```

Reports default to `reports/surfacesweep_report.json` (JSON) and, with `--html`, a sibling HTML file.
`reports/` is gitignored.

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output JSON file (default: `reports/surfacesweep_report.json`) |
| `-t, --threads` | Concurrent fetch threads (default: 6) |
| `-d, --depth` | Recursive JS depth: 0=HTML only, 1=JS from HTML, 2=JS from JS, … (default: 1) |
| `-b, --browser` | Headless browser mode (captures runtime API calls) |
| `-f, --full` | Static + browser, merged (best coverage) |
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
| `--cors` | Scan discovered endpoints for CORS misconfigurations |
| `--cors-origin` | Custom Origin header to test (default: built-in test set) |
| `--cors-max` | Max endpoints to CORS-test (default: 50) |
| `--cors-rps` | CORS probe rate limit req/s (default: 5, 0=unlimited) |
| `--cors-threads` | CORS probe threads (default: 6) |
| `--cors-timeout` | CORS per-request timeout seconds (default: 5) |
| `--cors-poc` | Write standalone CORS PoC HTML next to the report |
| `--jwt` | Analyze JWTs (alg/none, weak HMAC, exp, claims) |
| `--jwt-wordlist` | Extra newline-delimited secrets for offline HS* cracking |
| `--jwt-hashcat` | Export HS* JWTs to FILE (hashcat mode 16500) |
| `--jwt-export` | Write per-token JWT findings as NDJSON to FILE |
| `--jwt-network` | Fetch jku/x5u JWKS for key-confusion checks (SSRF-guarded) |
| `--jwt-network-timeout` | JWKS fetch timeout seconds (default: 5) |
| `--cookie` | Cookie header for authenticated scans |
| `--header` | Custom header (repeatable: `-H 'X-Api-Key: value'`) |
| `--timeout` | Browser page load timeout in seconds (default: 30) |
| `--scope` | Limit results to this domain (e.g. `*.target.com`) |
| `--html` | Also generate an HTML report |
| `--html-only` | HTML report only (skip JSON) |
| `--no-deobf` | Skip JS deobfuscation |
| `--regex-only` | Disable AST extraction, use regex only |
| `-q, --quiet` | Suppress progress output |

## Architecture

Pipeline stage order:

```text
waf_detect → wayback_fetch → scan → wayback_merge → waf_inject → cve → spa → jwt → validate → cors → export → report
```

```text
SurfaceSweep/
├── main.py                 # CLI entry (args + headers only)
├── modules/
│   ├── extraction/         # Regex/AST/browser extraction, secrets, source maps, risk
│   ├── discovery/          # SPA routes, Wayback Machine
│   ├── analysis/           # Validation, CVE/library, sinks, PII
│   ├── recon/              # WAF detection
│   ├── cors/               # Origin matrix, probes, classification, scanner
│   ├── jwt/                # Decode, crack, JWKS, checks, scanner
│   ├── pipeline/           # ScanContext, stages, merge helpers, runner
│   └── reporting/          # HTML/JSON, findings feed, Burp/ZAP, CORS PoC
├── tests/                  # Unit + offline integration (unittest)
├── testbed/vuln_api.py     # Local vulnerable Flask app (:5555)
└── reports/                # Generated output (gitignored)
```

<details>
<summary>Module map (collapsed)</summary>

```text
modules/extraction/   engine · patterns · secrets · http · scope · risk · ast · browser · sourcemaps · enrich · deobfuscator
modules/discovery/    spa · wayback
modules/analysis/     validator · libraries · sinks · pii
modules/recon/        waf
modules/cors/         origins · classifier · probe · scanner
modules/jwt/          decode · crack · keys · checks · scanner
modules/pipeline/     context · stages · merge · runner
modules/reporting/    html · export · findings · builder · cors_poc
tests/                test_cors · test_jwt · test_pipeline · test_integration · test_secrets · test_sourcemaps · test_enrich · test_validator · test_pii
```

</details>

Risk weights (CORS/JWT/CVE contribute; PII is recon-only):

| Severity | Weight |
|----------|--------|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |

## Testing

```bash
source venv/bin/activate
python -m unittest discover -s tests -q
```

- **416 tests** (unit + offline end-to-end integration), stdlib `unittest`, no network required
- Coverage includes extraction FP gates, source maps, enrichment, validation, PII, CORS probes/escalation,
  JWT decode/crack/JWKS, pipeline stage order, report schema (`schema_version: 1`), and finding feeds
- Local vulnerable API for manual checks: `python testbed/vuln_api.py` (port **5555**)

### Sample results (authorized targets)

| Feature | Result |
|---------|--------|
| Static scan (AST + regex) | 62 endpoints from 8 JS files |
| Browser scan | 31 endpoints, 2 XHR/fetch intercepted |
| Combined + validation | 74 → 41 live, 3 restricted, 40 dead filtered |
| AST vs regex alone | +17% endpoints (62 vs 53) |
| CVE (example) | jQuery 1.11.0 / Vue 2.1.5 → 4 CVEs; risk INFO → HIGH |
| SPA (example) | 20 routes (9 DOM, 7 BFS, 2 probe, 2 static) |

Full phase notes, bug-fix history, and per-feature validation logs live in the
[repository history](https://github.com/piyushpcs/SurfaceSweep/commits/main).

## Roadmap

- Diff mode — compare two scans of the same target over time
- Additional secret-pattern tuning as new FP reports arrive
- Optional CI workflow for the test suite

## Responsible use

Built and tested only against intentionally vulnerable or authorized targets
(local Flask testbed, OWASP Juice Shop, and sites with explicit permission).

**Do not run SurfaceSweep against systems you do not own or are not authorized to test.**
You are responsible for complying with applicable laws, program rules, and rate limits.

## Contributing

Issues and pull requests are welcome.

1. Fork and create a feature branch
2. Keep changes focused; match existing code style
3. Add or update tests — `python -m unittest discover -s tests -q` must stay green
4. Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)
5. Open a PR describing the problem and the approach

## License

No license file has been published yet. All rights reserved by the author until one is added.
Please open an issue if you want to use this project under a specific license.
