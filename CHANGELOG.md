# Changelog

All notable changes to SurfaceSweep are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-10-16

### Fixed

- Restored Python 3.10 support. `modules/common/result.py` imported
  `typing.NotRequired` (added in Python 3.11), so the package failed to import —
  taking 66 tests with it — on the project's declared 3.10 floor. `ScanResult`
  is a `TypedDict` with `total=False`, so every key was already optional and the
  qualifier was redundant; it has been removed.
- Added a static compatibility test that fails if any module imports a symbol
  newer than the declared Python 3.10 floor, so this cannot silently regress.

## [1.0.0] - 2026-10-16

First tagged release. SurfaceSweep extracts, analyses, and reports the
JavaScript attack surface of a web target for authorized security assessment.

### Added

- **Extraction** — AST (tree-sitter) + regex endpoint discovery, recursive JS
  crawling, source-map unwrapping, deobfuscation, SPA route discovery, service
  worker / chunk harvesting, Wayback history, and an optional headless-browser
  mode that captures runtime `fetch`/XHR calls.
- **Detection** — secret scanning (cloud keys, tokens, private keys, …),
  dangerous-sink detection, JWT analysis (alg/none, weak HMAC cracking,
  SSRF-guarded JWKS fetch), CVE lookup (local DB + OSV), GraphQL introspection
  probing, CORS misconfiguration scanning, and endpoint validation to filter
  soft-404s and SPA shells.
- **Reporting** — JSON (`schema_version: 1`), HTML, **SARIF 2.1.0**, Burp/ZAP
  CSV, path/parameter wordlists, scan diff (JSON + HTML), and multi-target
  batch mode.
- **Automation**
  - `--fail-on <severity>` for CI gating.
  - A composite **GitHub Action** (`action.yml`) that scans a target, writes
    SARIF, uploads it to GitHub code scanning, and optionally fails the job on a
    severity threshold.
  - A dependency-free **MCP server** (`mcp_server.py`) exposing `scan_url` and
    `check_scope` tools for agent clients over stdio.

### Security

- SSRF/metadata fetch guard (blocks link-local and cloud-metadata endpoints).
- Credentials (`--cookie` / `-H`) are bound to scope and only ever sent to
  in-scope hosts.
- Scope-enforced JS crawling; DNS-rebinding-resistant JWKS fetching with a size
  cap; TLS downgrade only as a fallback.
- Mutation-verb requests (POST/PUT/PATCH/DELETE) are downgraded to `OPTIONS`
  during validation so scans never mutate target state.
- See [SECURITY-FINDINGS.md](SECURITY-FINDINGS.md) for the full self-assessment.

[1.0.1]: https://github.com/piyushpcs/SurfaceSweep/releases/tag/v1.0.1
[1.0.0]: https://github.com/piyushpcs/SurfaceSweep/releases/tag/v1.0.0
