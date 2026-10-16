<div align="center">

# SurfaceSweep

**JavaScript attack-surface recon for security assessment**

Extract API endpoints and secrets from a target's JavaScript, validate what is live,
check CORS and JWT issues, and export results for Burp Suite / ZAP.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-917%20passing-brightgreen)](#testing)
[![CI](https://github.com/piyushpcs/SurfaceSweep/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushpcs/SurfaceSweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/piyushpcs/SurfaceSweep)](https://github.com/piyushpcs/SurfaceSweep/commits/main)
[![Standard Readme](https://img.shields.io/badge/readme-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

[Features](#features) ·
[Install](#install) ·
[Usage](#usage) ·
[Options](#options) ·
[Architecture](#architecture) ·
[Testing](#testing) ·
[Roadmap](#roadmap) ·
[License](#license)

</div>

---

## Why SurfaceSweep?

Modern SPAs hide real API traffic in obfuscated bundles, source maps, lazy chunks, and runtime XHR.
SurfaceSweep combines **static analysis (regex + AST)**, **headless browser capture**, and **historical JS (Wayback Machine)**
to build a single inventory of endpoints, then layers on checks that matter in a security assessment:

| Capability | What you get |
|------------|--------------|
| Endpoint discovery | `fetch` / `axios` / jQuery, SPA routers, nested chunks, historical JS |
| Secret hunting | 120+ patterns with entropy, placeholder, and proximity false-positive gates |
| Validation | Live / restricted / dead / soft-404 / SPA-shell classification |
| CORS | Spoofed Origin matrix, preflight + GET/POST, redirect-aware, PoC HTML |
| JWT | Offline decode, weak-HMAC crack, `alg=none`, JWKS key-confusion (optional network) |
| Risk | Weighted score (CVE + CORS + JWT) with evidence in JSON and HTML reports |
| GraphQL | Opt-in introspection probe — flags publicly readable schemas |
| Secret verification | Opt-in live checks against vendor APIs (OpenAI, GitHub, Stripe, …) |

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
- **robots.txt / sitemap.xml** — crawler manifests parsed for hidden paths

### Detection

- Likely API endpoints and full URLs
- **Request parameters** — query-string keys, `URLSearchParams`, axios `params: {}`, `FormData.append`, `searchParams.get`, path templates (`:id` / `${id}` / `{id}`)
- Leaked secrets / API keys (AWS, OpenAI, Anthropic, Twilio, SendGrid, Stripe, GitHub, Firebase, private keys, SMTP, OAuth, Bearer/JWT, …) with type-aware dedup
- Dangerous sinks (`innerHTML`, `eval`, `dangerouslySetInnerHTML`, open-redirect patterns) with severity
- Internal / private hosts (localhost, RFC1918, `*.internal` / `*.corp`, dev & staging subdomains)
- Potential **PII** (email, E.164 phone, Luhn payment cards, dashed SSNs) — recon signal only, not scored as a finding
- Library versions (jQuery, Vue, Bootstrap, Lodash, …) and **CVEs** (local DB + optional OSV.dev)
- **WAF detection** (Cloudflare, Akamai, AWS WAF, Imperva, …) with automatic pacing
- Prototype-pollution gadgets (`__proto__`, `constructor.prototype`, recursive merges)

### Analysis & export

- **Endpoint validation** — filters 404s, soft-404s, SPA shells, JSON fail-in-200
- **CORS scanner** — origin matrix, non-singleton ACAO, Private Network Access (PNA) notes, redirect FP filter, rate limits, standalone PoC HTML
- **JWT analyzer** — offline HS* cracking, wordlist/hashcat export, SSRF-guarded JWKS fetch for RS256→HS256 checks
- Scope split: internal paths, in-scope URLs, out-of-scope URLs
- Risk scoring summary per scan
- **JSON**, **HTML**, and **SARIF 2.1.0** reports (`schema_version: 1`, executive summary, findings feed)
- **Scan diff** — compare two reports of the same target (`--diff` or `python -m modules.reporting.diff`); writes JSON + HTML
- **Multi-target batch** — `--targets hosts.txt` with per-host output files
- **Burp Suite** / **OWASP ZAP** CSV export
- **Path/parameter wordlist** — `--wordlist` for ffuf/content discovery (segments + param names)
- **GitHub Action + SARIF** — drop-in composite action for CI that publishes findings to GitHub code scanning
- **MCP server** — dependency-free stdio wrapper (`scan_url`, `check_scope`) for agent-driven recon
- Authenticated scans via cookies and custom headers (`--cookie` / `-H`) — applied to the initial HTML/JS
  fetch, browser context, validation, CORS, and GraphQL probes; credentials are sent **only to in-scope
  hosts** so they never leak to CDNs or vendor APIs
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

Optional editable install (exposes `surfacesweep` and `surfacesweep-mcp` console commands):

```bash
pip install -e . --no-deps
surfacesweep --version
surfacesweep-mcp    # MCP server over stdio
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
python main.py https://target.com -f --validate --burp --zap --waf --wayback --cve --spa --cors --jwt --graphql --verify-secrets --html
```

### More examples

```bash
# Authenticated scan
python main.py https://target.com --cookie "session=abc123" -H "X-Api-Key: value"

# GraphQL introspection probe
python main.py https://target.com --graphql --html

# Compare two offline reports (JSON + HTML diff)
python -m modules.reporting.diff old.json new.json -o reports/diff.json

# Live-verify secrets (read-only vendor API GETs)
python main.py https://target.com --verify-secrets --html

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

# Diff this scan against a previous baseline
python main.py https://target.com -f --validate --diff reports/baseline.json

# SARIF for GitHub code scanning
python main.py https://target.com --cve --cors --sarif

# Path/parameter wordlist for content discovery (ffuf -w …)
python main.py https://target.com -f --wordlist
python main.py https://target.com -f --wordlist reports/paths.txt

# Batch scan a list of targets (one URL per line, # comments ok)
python main.py --targets hosts.txt -o reports/batch.json --html --sarif
```

Reports default to `reports/surfacesweep_report.json` (JSON) and, with `--html`, a sibling HTML file.
Batch mode writes one JSON per host next to `-o` (e.g. `reports/batch_app.example.com.json`).
`reports/` is gitignored.

### Options

| Flag | Description |
|------|-------------|
| `target` | Target URL (omit when using `--targets`) |
| `--targets FILE` | Batch mode: newline-delimited target URLs |
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
| `--graphql` | Probe discovered GraphQL endpoints for open introspection |
| `--graphql-timeout` | GraphQL introspection probe timeout seconds (default: 5) |
| `--verify-secrets` | Live-verify extracted secrets against vendor APIs (read-only GETs) |
| `--verify-secrets-timeout` | Per-secret verification timeout seconds (default: 5) |
| `--cookie` | Cookie header for authenticated scans |
| `--header` | Custom header (repeatable: `-H 'X-Api-Key: value'`) |
| `--timeout` | Browser page load timeout in seconds (default: 30) |
| `--scope` | Limit results to this domain (e.g. `*.target.com`) |
| `--html` | Also generate an HTML report |
| `--html-only` | HTML report only (skip JSON) |
| `--diff BASELINE` | Compare this scan to a baseline JSON; writes `*_diff.json` + `*_diff.html` |
| `--sarif` | Export findings as SARIF 2.1.0 (GitHub code scanning) |
| `--wordlist [FILE]` | Export path/parameter wordlist (omit FILE → sibling of `-o`) |
| `--no-deobf` | Skip JS deobfuscation |
| `--regex-only` | Disable AST extraction, use regex only |
| `--proxy` | HTTP(S) proxy for all scan requests (e.g. `http://127.0.0.1:8080`) |
| `--insecure` | Disable TLS certificate verification |
| `--ua` | Custom User-Agent for HTTP requests |
| `--fail-on` | Exit 1 when any finding is at/above `none\|low\|medium\|high\|critical` (default: `none`) |
| `--version` | Print version and exit |
| `-q, --quiet` | Suppress progress output |

Exit codes: `0` success · `1` findings at/above `--fail-on` · `2` usage error · `3` runtime error

## Architecture

Pipeline stage order:

```text
waf_detect → wayback_fetch → scan → wayback_merge → waf_inject → cve → spa → jwt → validate → graphql → verify_secrets → cors → export → report
```

```text
SurfaceSweep/
├── main.py                 # CLI entry (args + headers only)
├── modules/
│   ├── extraction/         # Regex/AST/browser extraction, params, secrets, source maps, risk
│   ├── discovery/          # SPA routes, Wayback Machine, robots/sitemap
│   ├── analysis/           # Validation, CVE/library, sinks, PII
│   ├── recon/              # WAF detection
│   ├── cors/               # Origin matrix, probes, classification, scanner
│   ├── jwt/                # Decode, crack, JWKS, checks, scanner
│   ├── pipeline/           # ScanContext, stages, merge helpers, runner
│   └── reporting/          # HTML/JSON/SARIF, findings feed, Burp/ZAP, CORS PoC, diff
├── tests/                  # Unit + offline integration (unittest)
├── testbed/vuln_api.py     # Local vulnerable Flask app (:5555)
└── reports/                # Generated output (gitignored)
```

<details>
<summary>Module map (collapsed)</summary>

```text
modules/extraction/   engine · patterns · secrets · params · http · scope · risk · ast · browser · sourcemaps · enrich · deobfuscator
modules/discovery/    spa · wayback · robots
modules/analysis/     validator · libraries · sinks · pii
modules/recon/        waf
modules/cors/         origins · classifier · probe · scanner
modules/jwt/          decode · crack · keys · checks · scanner
modules/pipeline/     context · stages · merge · runner
modules/reporting/    html · export · findings · builder · cors_poc · diff · sarif
tests/                test_cors · test_jwt · test_pipeline · test_integration · test_secrets · test_params_wordlist · test_sourcemaps · test_enrich · test_validator · test_pii · test_wayback · test_robots · test_sinks · test_patterns · test_spa_probe · test_diff · test_sarif · test_batch
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

# With coverage (optional)
pip install -r requirements-dev.txt
coverage run -m unittest discover -s tests -q
coverage report -m
```

- **917 tests** (unit + offline end-to-end integration), stdlib `unittest`, no network required
- Coverage includes extraction FP gates, source maps, enrichment, validation, PII, CORS probes/escalation/PNA,
  JWT decode/crack/JWKS, GraphQL introspection probe, secret live-verification, pipeline stage order,
  report schema (`schema_version: 1`), finding feeds, scan diff (JSON + HTML),
  scan diff, SARIF export, multi-target batch mode, the composite GitHub Action manifest,
  and the MCP server protocol/tools
- **CI**: GitHub Actions runs the suite on Python 3.10 and 3.12 with coverage on every push/PR
- Local vulnerable API for manual checks: `python testbed/vuln_api.py` (port **5555**)

### Sample results

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

## Scheduled scans

Keep a rolling baseline and alert on regressions with cron + `--diff`:

```bash
# Nightly scan of a target; rotate baseline weekly
# crontab -e
0 3 * * *  cd /opt/SurfaceSweep && ./venv/bin/python main.py https://target.example -f --validate --html -o reports/nightly.json --diff reports/baseline.json --fail-on high >> logs/nightly.log 2>&1

# Monday: promote last good report to baseline (only when no regression)
0 4 * * 1  cd /opt/SurfaceSweep && test -f reports/nightly.json && cp reports/nightly.json reports/baseline.json
```

- `--diff BASELINE.json` writes `*_diff.json` **and** a readable `*_diff.html` next to the scan report.
- `--fail-on high` exits `1` when HIGH/CRITICAL findings appear — wire that into mail/webhook wrappers.
- Offline baseline comparison (no network):

```bash
python -m modules.reporting.diff reports/baseline.json reports/nightly.json -o reports/nightly_diff.json
# → reports/nightly_diff.json + reports/nightly_diff.html
```

## GitHub Action

Run a scan in CI and surface findings in **GitHub code scanning** (SARIF) via the
composite action at [`action.yml`](action.yml):

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  surfacesweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: piyushpcs/SurfaceSweep@v1
        with:
          target: https://app.example.com
          args: "--scope app.example.com --jwt --cors"
          fail-on: "high"     # fail the job on HIGH/CRITICAL findings
```

| Input | Default | Purpose |
|-------|---------|---------|
| `target` | — (required) | URL to scan |
| `args` | `""` | Extra CLI flags |
| `output` | `surfacesweep-report.json` | JSON path; SARIF is written beside it as `<base>.sarif` |
| `sarif` | `true` | Generate a SARIF report |
| `upload-sarif` | `true` | Upload to GitHub code scanning |
| `fail-on` | `none` | Severity threshold for a non-zero exit |
| `python-version` | `3.12` | Runner Python |
| `browser` | `false` | Install Playwright Chromium for `-b` / `-f` |

Outputs: `json`, `sarif`, `exit-code`. A copy-ready workflow lives in
[`examples/github-actions-scan.yml`](examples/github-actions-scan.yml). Only scan
targets you are **authorized** to test.

Pin the action to a released major version (`@v1`) rather than `@main` so your
workflows are not affected by in-progress changes. See
[Releasing](#releasing-the-action) for the tag/version scheme.

### Releasing the Action

The action is consumed by a moving major-version tag (`@v1`) plus immutable
release tags (`v1.0.0`). To cut a release:

```bash
# Annotated release tag + moving major tag
git tag -a v1.0.0 -m "SurfaceSweep v1.0.0"
git tag -a v1     -m "SurfaceSweep v1 (latest 1.x)"
git push origin v1.0.0 v1
```

Then on GitHub open **Releases → Draft a release**, select the `v1.0.0` tag,
paste the [CHANGELOG.md](CHANGELOG.md) entry, and optionally tick **Publish this
Action to the GitHub Marketplace**. Keep the `version` field in
[`pyproject.toml`](pyproject.toml) in step with the tag.

## MCP server (agent-native recon)

SurfaceSweep ships an MCP server so agent tools (Claude Desktop, Cursor, …) can
drive it directly. It is dependency-free — JSON-RPC 2.0 over stdio using only the
standard library:

```bash
python mcp_server.py        # or, after `pip install .`: surfacesweep-mcp
```

Tools:

- `scan_url` — static recon (or headless when `browser: true`); returns a compact
  summary: counts, endpoints, redacted secrets, sinks, and risk.
- `check_scope` — confirm a URL is within an authorized scope before scanning.

Example client configuration (Claude Desktop):

```json
{
  "mcpServers": {
    "surfacesweep": {
      "command": "python",
      "args": ["/path/to/SurfaceSweep/mcp_server.py"]
    }
  }
}
```

stdout is reserved for the JSON-RPC stream; progress output is redirected to
stderr so the transport stays valid.

## Roadmap

- Additional secret-pattern tuning as new FP reports arrive
- Burp / ZAP / HAR import as alternate discovery sources

## Contributing

Issues and pull requests are welcome. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

1. Fork and create a feature branch
2. Keep changes focused; match existing code style
3. Add or update tests — `python -m unittest discover -s tests -q` must stay green
4. Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)
5. Open a PR describing the problem and the approach

## Security

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/piyushpcs/SurfaceSweep/security/advisories/new)
— see [SECURITY.md](SECURITY.md).

SurfaceSweep's own vulnerabilities (SSRF, credential leakage, destructive
requests) found and fixed during a self-assessment are documented in
[SECURITY-FINDINGS.md](SECURITY-FINDINGS.md).

## License

Licensed under the [MIT License](LICENSE).
