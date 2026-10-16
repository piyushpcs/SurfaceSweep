<div align="center">

# SurfaceSweep

**JavaScript attack-surface reconnaissance for security assessments**

Extract endpoints and secrets from a target's JavaScript, validate what is live,
probe CORS / JWT / GraphQL issues, and export findings to Burp, ZAP, HTML, JSON,
and SARIF.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-974%20passing-brightgreen)](#testing)
[![CI](https://github.com/piyushpcs/SurfaceSweep/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushpcs/SurfaceSweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/piyushpcs/SurfaceSweep)](https://github.com/piyushpcs/SurfaceSweep/commits/main)
[![Standard Readme](https://img.shields.io/badge/readme-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

[Features](#features) ·
[Install](#install) ·
[Usage](#usage) ·
[Options](#options) ·
[Demo](docs/DEMO.md) ·
[Architecture](#architecture) ·
[Testing](#testing) ·
[Roadmap](#roadmap) ·
[License](#license)

</div>

---

## Why SurfaceSweep?

Modern SPAs hide real API traffic in obfuscated bundles, source maps, lazy chunks,
and runtime XHR. SurfaceSweep fuses **static analysis (regex + AST)**, **headless
browser capture**, and **historical JS** into a single endpoint inventory, then
layers the checks that matter in an assessment. Every active stage is bounded and
rate-aware, so scans stay polite on authorized targets.

**See it in action:** [`docs/DEMO.md`](docs/DEMO.md) — a reproducible end-to-end
walkthrough (CLI, GitHub Action, and MCP server) against the bundled testbed.

## Features

### Extraction

- **Static (regex)** and **AST (tree-sitter)** extraction from HTML and JS; AST
  falls back to regex automatically.
- **Headless browser** capture of runtime XHR/fetch and lazy chunks (`--browser`);
  `--full` merges static + browser.
- **Recursive discovery** — webpack chunks, dynamic imports, **source maps** (inline
  and `sourcesContent` re-scan), and **JS deobfuscation** (Base64, hex, unicode,
  `eval`, `String.fromCharCode`).
- **Passive expansion** — Wayback historical JS, `robots.txt` / `sitemap.xml`, SPA
  router routes (React/Vue/Angular), and Burp / ZAP / HAR import (`--import`).

### Detection

- API endpoints and full URLs; **request parameters** (query keys, `URLSearchParams`,
  axios `params`, `FormData`, path templates).
- **120+ secret patterns** (AWS, OpenAI, Anthropic, Stripe, GitHub, Firebase, private
  keys, SMTP, OAuth, JWT, …) with entropy, placeholder, and proximity false-positive gates.
- **Dangerous sinks** — `innerHTML`, `eval`, `dangerouslySetInnerHTML`, open redirects.
- **Internal hosts**, **PII** (recon-only), **library versions + CVEs** (local DB +
  optional OSV.dev), and **WAF detection** (Cloudflare, Akamai, AWS, Imperva, …) with
  automatic pacing.
- Prototype-pollution gadgets (`__proto__`, `constructor.prototype`, recursive merges).

### Analysis & reporting

- **Validation** — live / restricted / dead / soft-404 / SPA-shell classification;
  method-aware, capped (`--max-validate`) and rate-limited (`--validate-rps`).
- **CORS** — spoofed-origin matrix, preflight + GET/POST, non-singleton ACAO, Private
  Network Access notes, redirect FP filter, standalone PoC HTML. A credential-less
  `ACAO: *` on public content is reported as informational.
- **JWT** — offline decode, weak-HMAC cracking, `alg=none`, hashcat/NDJSON export, and
  SSRF-guarded JWKS key-confusion checks.
- **GraphQL** introspection probe; opt-in **secret verification** against vendor APIs.
- **Reports** — JSON, HTML, and SARIF 2.1.0 (`schema_version: 1`) with executive
  summary, findings feed, risk score, and `meta.requests_sent` scan footprint.
- **Exports & diff** — Burp / ZAP CSV, path+parameter wordlist, and report comparison.
- **Authenticated scans** (`--cookie` / `-H`), applied only to **in-scope hosts**.

## Install

Requires **Python 3.10+**.

```bash
git clone https://github.com/piyushpcs/SurfaceSweep.git
cd SurfaceSweep
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium        # only needed for -b / -f
```

Optional editable install (exposes `surfacesweep` and `surfacesweep-mcp`):

```bash
pip install -e . --no-deps
surfacesweep --version
```

`tree-sitter` and `tree-sitter-javascript` ship prebuilt wheels (no compiler); if the
AST stack is unavailable, SurfaceSweep falls back to regex-only extraction.

## Usage

```bash
# Static (fast, no browser)
python main.py https://target.com

# Browser mode — captures runtime API calls
python main.py https://target.com --browser

# Full scan with validation + HTML report (best coverage)
python main.py https://target.com --full --validate --html
```

```bash
# Authenticated scan; credentials go only to in-scope hosts
python main.py https://target.com --cookie "session=abc123" -H "X-Api-Key: value"

# CORS misconfiguration scan with a custom Origin
python main.py https://target.com --cors --cors-origin https://evil.com --html

# JWT analysis, offline crack, and optional SSRF-guarded JWKS fetch
python main.py https://target.com --jwt --jwt-wordlist secrets.txt --jwt-network --html

# Seed discovery from proxy history (repeatable; format auto-detected)
python main.py https://target.com --full --import burp_items.xml --import capture.har

# Bound and pace active validation (defaults: 200 endpoints @ 5 req/s)
python main.py https://target.com --validate --max-validate 50 --validate-rps 2

# Burp / ZAP export, path+parameter wordlist, SARIF for code scanning
python main.py https://target.com -f --burp --zap --wordlist --sarif

# Batch scan (one URL per line, # comments ok)
python main.py --targets hosts.txt -o reports/batch.json --html --sarif
```

JSON reports default to `reports/surfacesweep_report.json` (`--html` adds a sibling
HTML file; batch mode writes one JSON per host). `reports/` is gitignored.

## Options

<details>
<summary><b>Full CLI reference</b></summary>

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
| `--vt, --validate-threads` | Validation threads (default: 10) |
| `--vtimeout` | Validation timeout in seconds (default: 5) |
| `--max-validate` | Max endpoints to actively validate, API-like first (default: 200, 0=unlimited) |
| `--validate-rps` | Validation rate limit req/s (default: 5, 0=unlimited; auto-throttled under a WAF) |
| `--import FILE` | Import endpoints from a Burp XML/CSV, ZAP CSV, or HAR file (repeatable; auto-detected) |
| `--burp` | Export endpoints as a Burp Suite CSV |
| `--zap` | Export endpoints as an OWASP ZAP CSV |
| `--wayback` | Include historical JS files from the Wayback Machine |
| `--waf` | Detect WAF and adjust scan speed |
| `--cve` | Detect JS library versions and check the local CVE database |
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
| `--cors-poc` | Write a standalone CORS PoC HTML next to the report |
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
| `--wordlist [FILE]` | Export a path/parameter wordlist (omit FILE → sibling of `-o`) |
| `--no-deobf` | Skip JS deobfuscation |
| `--regex-only` | Disable AST extraction, use regex only |
| `--proxy` | HTTP(S) proxy for all scan requests (e.g. `http://127.0.0.1:8080`) |
| `--insecure` | Disable TLS certificate verification |
| `--ua` | Custom User-Agent for HTTP requests |
| `--fail-on` | Exit 1 when any finding is at/above `none\|low\|medium\|high\|critical` (default: `none`) |
| `--version` | Print version and exit |
| `-q, --quiet` | Suppress progress output |

Exit codes: `0` success · `1` findings at/above `--fail-on` · `2` usage error · `3` runtime error

</details>

## Architecture

Pipeline stage order:

```text
waf_detect → wayback_fetch → scan → import → wayback_merge → waf_inject → cve → spa → jwt → validate → graphql → verify_secrets → cors → export → report
```

```text
SurfaceSweep/
├── main.py                 # CLI entry (args + headers only)
├── modules/
│   ├── extraction/         # Regex / AST / browser extraction, params, secrets, source maps, risk
│   ├── discovery/          # SPA routes, Wayback Machine, robots/sitemap, importers
│   ├── analysis/           # Validation, CVE/library, sinks, PII
│   ├── recon/              # WAF detection
│   ├── cors/               # Origin matrix, probes, classification, scanner
│   ├── jwt/                # Decode, crack, JWKS, checks, scanner
│   ├── pipeline/           # ScanContext, stages, merge helpers, runner
│   └── reporting/          # HTML / JSON / SARIF, findings feed, Burp/ZAP, CORS PoC, diff
├── tests/                  # Unit + offline integration (unittest)
├── testbed/vuln_api.py     # Local vulnerable Flask app (:5555)
└── reports/                # Generated output (gitignored)
```

Risk weights (CORS / JWT / CVE contribute; PII is recon-only):

| Severity | CRITICAL | HIGH | MEDIUM | LOW |
|----------|----------|------|--------|-----|
| Weight | 25 | 15 | 8 | 3 |

## Testing

```bash
source venv/bin/activate
python -m unittest discover -s tests -q

# Coverage (optional)
pip install -r requirements-dev.txt
coverage run -m unittest discover -s tests -q && coverage report -m
```

- **974 tests** — unit + offline end-to-end integration, stdlib `unittest`, no network required.
- Covers extraction FP gates, source maps, enrichment, validation, PII, CORS
  probes/escalation/PNA, JWT decode/crack/JWKS, GraphQL, secret verification, pipeline
  order, report schema and findings feed, scan diff, SARIF, batch mode, the GitHub
  Action manifest, the MCP server, and a Python 3.10 compatibility guard.
- **CI**: GitHub Actions runs the suite on Python 3.10 and 3.12 with coverage on every push/PR.
- Local vulnerable API for manual checks: `python testbed/vuln_api.py` (port **5555**).

### Sample results

| Feature | Result |
|---------|--------|
| Static scan (AST + regex) | 62 endpoints from 8 JS files |
| Browser scan | 31 endpoints, 2 XHR/fetch intercepted |
| Combined + validation | 74 → 41 live, 3 restricted, 40 dead filtered |
| AST vs regex alone | +17% endpoints (62 vs 53) |
| CVE (example) | jQuery 1.11.0 / Vue 2.1.5 → 4 CVEs; risk INFO → HIGH |
| SPA (example) | 20 routes (9 DOM, 7 BFS, 2 probe, 2 static) |

Full phase notes and per-feature validation logs live in the
[repository history](https://github.com/piyushpcs/SurfaceSweep/commits/main).

## Automation

### Scheduled scans

Keep a rolling baseline and alert on regressions with cron + `--diff`:

```bash
# Nightly scan; rotate baseline weekly
0 3 * * *  cd /opt/SurfaceSweep && ./venv/bin/python main.py https://target.example \
  -f --validate --html -o reports/nightly.json --diff reports/baseline.json \
  --fail-on high >> logs/nightly.log 2>&1

# Monday: promote the last good report to baseline (only when no regression)
0 4 * * 1  cd /opt/SurfaceSweep && test -f reports/nightly.json && \
  cp reports/nightly.json reports/baseline.json
```

`--diff BASELINE.json` writes `*_diff.json` **and** a readable `*_diff.html`;
`--fail-on high` exits `1` on HIGH/CRITICAL findings. Offline comparison:

```bash
python -m modules.reporting.diff reports/baseline.json reports/nightly.json -o reports/nightly_diff.json
```

### GitHub Action

The composite action [`action.yml`](action.yml) scans in CI and uploads SARIF to
GitHub code scanning:

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
          fail-on: "high"
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
[`examples/github-actions-scan.yml`](examples/github-actions-scan.yml). Pin to the
released major tag (`@v1`) rather than `@main`. Only scan targets you are
**authorized** to test.

<details>
<summary><b>Releasing the Action</b></summary>

The action is consumed by a moving major tag (`@v1`) plus immutable release tags:

```bash
git tag -a v1.0.3 -m "SurfaceSweep v1.0.3"
git tag -a v1     -m "SurfaceSweep v1 (latest 1.x)"
git push origin v1.0.3 v1
```

Then on GitHub open **Releases → Draft a release**, select the tag, paste the
[CHANGELOG.md](CHANGELOG.md) entry, and optionally publish to the Marketplace. Keep
the `version` in [`pyproject.toml`](pyproject.toml) in step with the tag.

</details>

### MCP server

SurfaceSweep ships a dependency-free MCP server (JSON-RPC 2.0 over stdio) so agent
tools such as Claude Desktop and Cursor can drive it:

```bash
python mcp_server.py        # or, after `pip install .`: surfacesweep-mcp
```

- `scan_url` — static recon (or headless with `browser: true`); returns a compact
  summary of counts, endpoints, redacted secrets, sinks, and risk.
- `check_scope` — confirm a URL is within an authorized scope before scanning.

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

stdout is reserved for the JSON-RPC stream; progress output goes to stderr.

## Roadmap

- Ongoing secret-pattern tuning as new false-positive reports arrive.
- Additional import formats beyond Burp / ZAP / HAR (e.g. mitmproxy, Caido).

## Contributing

Issues and PRs are welcome — by participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

1. Fork and create a feature branch.
2. Keep changes focused; match existing code style.
3. Add or update tests — `python -m unittest discover -s tests -q` must stay green.
4. Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`).
5. Open a PR describing the problem and the approach.

## Security

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/piyushpcs/SurfaceSweep/security/advisories/new)
— see [SECURITY.md](SECURITY.md). SurfaceSweep's own issues found and fixed during a
self-assessment (SSRF, credential leakage, destructive requests) are documented in
[SECURITY-FINDINGS.md](SECURITY-FINDINGS.md).

## License

Licensed under the [MIT License](LICENSE).
