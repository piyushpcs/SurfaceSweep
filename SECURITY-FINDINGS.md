# Security Findings — SurfaceSweep self-assessment

This document records security issues found by auditing SurfaceSweep's own
code, with impact, root cause, and the fix applied. It exists because a
reconnaissance tool that is itself unsafe is worse than no tool: these issues
turned the scanner into an SSRF pivot, a credential-leak, and a source of
destructive requests against the target.

Status: **all findings below are fixed** and covered by regression tests in
`tests/test_hardening.py` (plus updated assertions in `tests/test_validator.py`
and `tests/test_jwt.py`). Test suite: 883 passing.

Severity uses CVSS-style ratings for the tool's real deployment context
(authorized penetration testing / bug-bounty recon).

---

## SF-01 — SSRF / unbounded cross-domain JavaScript crawl (HIGH, 8.6)

**Location:** `modules/extraction/engine.py` — `run_extractor` / `scan_js_urls`

**Impact:** The crawler followed every `<script src>` and every JS-referenced
chunk regardless of host. A target (or any file on it) could point the scanner
at `http://169.254.169.254/…`, `http://internal.corp/…`, or an attacker server,
causing the scanner to fetch internal resources and use the operator's network
position as an SSRF pivot. Response bodies were then scanned for secrets,
amplifying the issue.

**Root cause:** No scope filter on the fetch path. `--scope` only affected how
results were *classified* (`in_scope_urls` / `out_of_scope_urls`), never what
was *fetched*.

**Fix:** `scan_js_urls` now filters to the target's registrable domain
(default) or the caller's `--scope`. Off-scope JS is not fetched. Relative /
protocol-relative references remain in scope.

**Tests:** `tests/test_hardening.py::TestCrawlerScope::test_off_scope_linked_js_not_fetched`

---

## SF-02 — Cloud-instance metadata reachable from the fetch layer (HIGH, 8.2)

**Location:** `modules/extraction/http.py` — `fetch_with_retry`

**Impact:** Even with SF-01 fixed, a redirect or a discovered URL could still
reach the cloud metadata service (`169.254.169.254`, `fd00:ec2::254`,
`100.100.100.200`, GCP metadata hostnames), a direct path to instance
credentials.

**Root cause:** No denylist for metadata / link-local endpoints.

**Fix:** `is_blocked_fetch_target(url)` rejects metadata and link-local hosts;
`fetch_with_retry` raises `ConnectionError` for them. Loopback/private ranges
stay allowed **on purpose** — local testbeds and authorized internal
assessments legitimately target them.

**Tests:** `tests/test_hardening.py::TestFetchSafety`

---

## SF-03 — Target credentials leaked to third-party hosts (HIGH, 7.4)

**Location:** `modules/extraction/http.py`, `modules/extraction/browser.py`,
`modules/pipeline/stages.py`

**Impact:** Two paths leaked the target's authenticated session:
1. `--cookie` / `-H` headers were applied as process-wide defaults, so they
   were also sent to **any** host the scan touched — CDNs, source-map hosts,
   and, worst of all, the vendor APIs probed by `--verify-secrets`
   (e.g. `api.stripe.com`, `api.github.com`). A target's session cookie
   exfiltrated to unrelated third parties is a real data-protection incident.
2. Browser mode ignored `--cookie` / `-H` entirely, so login-gated apps yielded
   nothing on the core scan.

**Root cause:** Auth headers were treated as global request defaults with no
scope binding, and the browser context was never given credentials.

**Fix:**
- Auth headers are stored separately and attached **only when the request host
  is within scope** (`HttpClient._merge_headers` + `configure_auth`).
- `--verify-secrets` no longer forwards target headers to vendor APIs.
- Browser mode loads the `Cookie` header into the Playwright context and passes
  other headers via `extra_http_headers`.

**Tests:** `tests/test_hardening.py::TestScopedAuth`,
`TestBrowserCookieParse`, `TestNoCredentialLeakToVendors`.
End-to-end: a cookie-gated local app yields its HTML+JS and endpoints with
`--cookie`, and nothing without it.

---

## SF-04 — Validation issues state-changing requests on a guess (HIGH, 7.1)

**Location:** `modules/analysis/validator.py` — `resolve_validation_method`

**Impact:** Endpoints whose verbs were *inferred from the path*
(`…/create` → POST, `…/update` → PUT, `…/delete/1` → DELETE) were sent live
during validation. A scan could therefore create, modify, or delete data on the
target — unacceptable for a recon tool, and a scope/authorization violation.

**Root cause:** Only inferred `DELETE` was downgraded to `OPTIONS`; POST/PUT/
PATCH were sent as-is.

**Fix:** Every inferred mutation verb (POST/PUT/PATCH/DELETE) is downgraded to
`OPTIONS` (a safe existence probe). Browser-*observed* verbs are still reused,
since those reflect real application traffic.

**Tests:** `tests/test_hardening.py::TestValidationNeverMutates`,
`tests/test_validator.py` (updated).

---

## SF-05 — DNS-rebinding TOCTOU in JWKS fetch (MEDIUM, 5.9)

**Location:** `modules/jwt/keys.py` — `is_safe_jwt_fetch_url` /
`_get_with_safe_redirects`

**Impact:** The SSRF guard resolved the host and checked it was public, but the
HTTP stack resolved it *again* at connect time. A hostile `jku`/`x5u` host
could return a public IP to the guard and an internal IP to the connection
(classic DNS rebinding).

**Root cause:** Validation and connection used independent DNS lookups.

**Fix:** The host is resolved once, validated, and then pinned for the request
(`_pin_dns` forces `getaddrinfo` to the approved IPs). Redirect hops are
re-validated and re-pinned. A 1 MB response cap also bounds hostile payloads.

**Tests:** `tests/test_hardening.py::TestDnsPinning`,
`tests/test_jwt.py::test_helper_source_has_allow_redirects_false`.

---

## SF-06 — Global TLS downgrade (MEDIUM, 5.3)

**Location:** `modules/extraction/http.py` (`RelaxedTLSAdapter`),
`modules/cors/scanner.py`

**Impact:** The CORS scanner mounted a `SECLEVEL=0` adapter (legacy ciphers,
weak DH) on **every** probe, silently downgrading TLS for all CORS traffic.
For a tool that now attaches session cookies, that weakens confidentiality of
authenticated requests and enables downgrade attacks.

**Root cause:** The relaxed-TLS workaround for legacy hosts was applied
unconditionally rather than as a fallback.

**Fix:** Sessions use normal TLS. `probe._do_request` retries through the
relaxed session **only** when the failure is a cipher-policy rejection
(`is_tls_policy_error`). Same fallback-only policy as the main fetch path.

**Tests:** `tests/test_hardening.py::TestProbeTlsFallback`

---

## SF-07 — Broken secret detection (LOW, correctness)

**Location:** `modules/extraction/secrets.py`, `modules/extraction/verify.py`

**Impact / root cause:**
- `Private Key` regex had a capturing optional group, so bare PKCS#8 keys
  (`-----BEGIN PRIVATE KEY-----`) never matched (matched group was `None`).
- `Exposed Env Var` treated the env **name** as the secret value, so short
  prefixes (e.g. `VITE_KEY`) failed the length gate and were dropped.
- `GitHub PAT (classic)` matched exactly 36 chars, truncating longer tokens.
- `npm Token` verifier label didn't match the extractor's `NPM Token`, so npm
  tokens were never verified.

**Fix:** Non-capturing groups / correct group indices; `{36,}` PAT length;
label corrected to `NPM Token`.

**Tests:** `tests/test_hardening.py::TestSecretExtractionFixes`

---

## SF-08 — Report/export integrity & injection (LOW–MEDIUM)

**Location:** `modules/reporting/`

**Impact / root cause:**
- Burp/ZAP CSV export crashed on a bare filename (`os.path.dirname("x.csv")`
  is `""` → `makedirs("")` raised).
- Exported cells were not neutralized against CSV/spreadsheet formula
  injection (`=`, `+`, `-`, `@`, tab, CR) — a target-controlled path like
  `/=cmd` becomes a live formula when opened in a spreadsheet.
- HTML report emitted a stray `<td>` in secret-verification rows.
- SARIF reported every secret at `HIGH` regardless of type.

**Fix:** `_write_csv` guard (create parent only if present) + `_csv_safe`
prefix; corrected markup; type-aware `secret_severity()` in SARIF.

**Tests:** `tests/test_hardening.py::TestExportHardening`,
`TestSarifSeverity`

---

## SF-09 — Robustness: one error killed the whole scan (MEDIUM, availability)

**Location:** `modules/pipeline/runner.py`

**Impact:** Any stage exception aborted the pipeline before the report stage,
so a single failure produced no report at all — losing all prior findings.

**Fix:** Each stage runs under isolation; failures are recorded in
`ctx.stage_errors`, surfaced in the result's `errors`, and the scan continues
so a report is still written. Report/meta stamping was also corrected so the
saved report lists every stage (including `report`).

**Tests:** `tests/test_hardening.py::TestStageIsolation`

---

## SF-10 — Concurrency and data-integrity defects (LOW)

**Location:** `modules/extraction/http.py`, `modules/cors/scanner.py`,
`modules/pipeline/merge.py`, `modules/analysis/libraries.py`,
`modules/discovery/wayback.py`

**Impact / root cause:**
- Response cache mutated without a lock from worker threads.
- CORS used one shared `requests.Session` across thread-pool workers
  (not thread-safe).
- `merge_sinks` re-flattened already-deduped sinks with `count=1`, zeroing
  hit counts.
- OSV `querybatch` results were mapped by the wrong index (libs without an
  npm name shifted the mapping).
- Wayback aborted on an unexpected API shape (`TypeError`).

**Fix:** Cache lock; per-thread CORS sessions; correct count-preserving merge;
query-position-based OSV mapping; defensive Wayback parsing.

**Tests:** covered by the existing suite (cache, CORS, sinks, batch) plus
`tests/test_hardening.py::TestOsvIndexMapping`.

---

## Residual risks / out of scope

- **DNS rebinding for general fetches** is fully pinned only on the JWKS path.
  The main crawler relies on scope enforcement (SF-01); redirects to a
  rebinding host outside scope are not fetched, but a same-registrable-domain
  host that rebinds remains a theoretical vector.
- **Passive-only scanning** is a design goal; SF-04 removes the one active
  behavior (inferred mutation verbs), but authored plugins could still perform
  active probes if added.
- **Report files may contain secrets** found on the target — handle output
  artifacts accordingly.
