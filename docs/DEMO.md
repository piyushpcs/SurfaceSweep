# SurfaceSweep — end-to-end demo

Every command and output below was run against the **bundled vulnerable testbed**
(`testbed/vuln_api.py`, port 5555). Reproduce it yourself — nothing here is
hand-written.

## 0. Setup

```bash
git clone https://github.com/piyushpcs/SurfaceSweep.git
cd SurfaceSweep
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium   # optional — only for -b / -f
```

## 1. Start the testbed

```bash
python testbed/vuln_api.py              # serves http://127.0.0.1:5555
```

The testbed is a deliberately vulnerable app: exposed secrets, a weak/none JWT,
dangerous sinks, internal-host references, and several CORS misconfigurations.

## 2. CLI scan (static + JWT + CORS + CVE)

```bash
python main.py http://127.0.0.1:5555 -d 2 --validate --jwt --cors --cve \
  --sarif --html -o reports/demo.json
```

### Console output (real, trimmed)

```text
[*] Fetching http://127.0.0.1:5555
[+] Found 1 external JS files, 1 inline scripts
    scanned http://127.0.0.1:5555/static/app.js — 21 endpoints found
[*] Depth 1: scanning 2 additional JS files
    scanned http://127.0.0.1:5555/static/vendor.def456.js — 1 endpoints found
    scanned http://127.0.0.1:5555/static/chunk-abc123.js — 2 endpoints found

[+] Internal paths found: 23
[+] Out-of-scope URLs (informational only): 10
[+] Extraction: AST (tree-sitter) + regex
[!] 9 unique potential secret(s) found — review manually!
[!] 3 unique JWT(s) found — run with --jwt to analyze
[!] 8 obfuscated string(s) decoded
[!] 4 dangerous sink pattern(s) found
[!] 5 internal/private host reference(s) found
[!] 1 potential PII item(s) found
[+] Risk level: HIGH (score: 141)

[*] --- JWT Analysis ---
[+] JWT findings: 2 critical, 3 high, 4 medium (3 token(s) analyzed)
    [!] CRITICAL HS256  weak_hmac_secret: HMAC secret cracked: 'secret' (offline forgery possible)
    [!] CRITICAL none   alg_none: Algorithm 'none' allows signature bypass (unsecured JWT)

[*] --- Endpoint Validation ---
[+] Validation complete:
    Live: 22
    Restricted (401/403): 0
    Dead (404): 1

[*] --- CORS Scan ---
    [!] CRITICAL http://127.0.0.1:5555/api/v2/admin/settings ... ACAO=https://evil.com
    [!] CRITICAL http://127.0.0.1:5555/api/v2/null-cred origins=null ACAO=null
    [!] MEDIUM   http://127.0.0.1:5555/api/v1/public ... ACAO=*
[+] CORS findings: 20 critical, 0 high, 1 medium (21 URL(s) flagged, 461 probe hits)
[!] CRITICAL: reflected origin + credentials — data theft possible
[+] Risk: HIGH (score: 784) including CORS boost
[+] Report saved to reports/demo.json
[+] SARIF exported: reports/demo.sarif (46 result(s))
```

> `--cve` runs too; the testbed pins no JS libraries, so it reports `cves: 0`.

### Report summary (`reports/demo.json`)

```json
{
  "risk_level": "HIGH",
  "risk_score": 784,
  "severity_counts": { "CRITICAL": 23, "HIGH": 3, "MEDIUM": 16, "INFO": 2 },
  "total_findings": 44,
  "modules_covered": ["cors", "internal_hosts", "jwt", "pii", "secrets", "sinks", "validation"]
}
```

### Representative findings

| Kind | Example |
|------|---------|
| Database URL | `postgres://admin:…@db.internal.com:5432/myapp` |
| Exposed env vars | `NEXT_PUBLIC_API_URL`, `REACT_APP_SECRET_KEY` |
| JWT — `alg=none` | CRITICAL, signature bypass |
| JWT — HS256 | CRITICAL, secret cracked offline (`'secret'`) |
| Sink | `eval` (HIGH), `setTimeout(string)` (HIGH), `location.hash` → `location.href` (HIGH), `innerHTML` (MEDIUM) |

Inspect: `reports/demo.html` (readable), `reports/demo.json`, `reports/demo.sarif`
(code scanning). Add `--burp` / `--zap` for CSV exports, or `--diff baseline.json`
to compare against a previous scan.

## 3. GitHub Action (CI + code scanning)

The same scan runs in CI via the composite action — findings land in GitHub
**code scanning** (SARIF). See
[`examples/github-actions-scan.yml`](../examples/github-actions-scan.yml):

```yaml
- uses: piyushpcs/SurfaceSweep@v1
  with:
    target: https://app.example.com
    args: "--scope app.example.com --jwt --cors"
    fail-on: "high"        # non-zero exit on HIGH/CRITICAL
```

`--fail-on` gates the job; the SARIF report is uploaded with
`github/codeql-action/upload-sarif`.

## 4. MCP server (agent clients)

SurfaceSweep also runs as a dependency-free MCP server over stdio, so agent
tools can call it. This is a **real** JSON-RPC session:

```console
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"demo","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_url","arguments":{"target":"http://127.0.0.1:5555","limit":5}}}' \
  | python mcp_server.py
```

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"surfacesweep","version":"1.0.0"}}}
```

`scan_url` returns a compact summary (endpoints, redacted secrets, sinks, risk):

```json
{
  "target": "http://127.0.0.1:5555",
  "risk": "HIGH",
  "risk_score": 141,
  "counts": {
    "js_files": 3, "internal_paths": 23, "secrets": 9,
    "jwts": 3, "sinks": 4, "internal_hosts": 5
  },
  "endpoints": ["/admin/debug/config", "/api/v1/public", "/api/v2/admin/settings"],
  "secrets": [
    { "type": "Database URL", "match": "post…" },
    { "type": "JWT", "match": "eyJh…" }
  ],
  "sinks": [
    { "sink": "eval", "severity": "HIGH" },
    { "sink": "setTimeout string", "severity": "HIGH" }
  ]
}
```

Companion tool `check_scope` lets an agent verify authorization before scanning:

```json
{ "url": "http://127.0.0.1:5555/api/v2/users", "scope": "127.0.0.1", "in_scope": true }
```

> **Scope note:** `scan_url` runs the **static extractor only** (fast, no
> browser), so its risk score reflects extraction — not the full CLI pipeline
> (`--jwt`, `--cors`, …). Use the CLI/Action for the complete assessment.

## 5. Safety reminder

Only run SurfaceSweep against systems you are **authorized** to test. Credentials
passed with `--cookie` / `-H` are sent **only** to in-scope hosts, mutation verbs
are downgraded to `OPTIONS`, and the crawler will not follow JavaScript to
cloud-metadata or link-local addresses — but the tool is a live scanner, not a
toy. See [SECURITY.md](../SECURITY.md) and
[SECURITY-FINDINGS.md](../SECURITY-FINDINGS.md).
