# SurfaceSweep — Portfolio & interview kit

Use this to present the project truthfully. Everything here maps to code that
exists and to `SECURITY-FINDINGS.md`.

---

## Resume entry

**SurfaceSweep — JavaScript reconnaissance & attack-surface scanner** (Python, solo project)

- Built a passive JS recon tool (static + headless-browser modes) that extracts
  endpoints, secrets, JWTs, dangerous sinks, and CORS/JWT misconfigurations from
  a web target, exporting to JSON/HTML/SARIF/Burp/ZAP.
- **Audited and hardened the tool against its own class of bugs** — fixed an SSRF
  pivot in the crawler, a cloud-metadata fetch path, target-credential leakage to
  third-party APIs, and a validator that issued state-changing POST/PUT/DELETE,
  each with a regression test (883 tests passing).
- Implemented scope-bound authentication: `--cookie`/`-H` now reach the initial
  HTML/JS fetch and the browser context, while credentials are sent **only** to
  in-scope hosts.
- Closed a DNS-rebinding TOCTOU in the JWKS fetcher by pinning the validated IP
  for the request; made legacy-TLS support fallback-only to avoid global
  downgrades.

### One-line variant
> Built and self-audited a JS attack-surface scanner (Python, 883 tests) — fixed
> SSRF, credential-leakage, and destructive-request bugs in my own tool and
> documented them in a public security write-up.

---

## STAR stories (interview talking points)

**1. "I found an SSRF in my own tool."**
- *Situation:* The crawler followed any `<script src>` to extract endpoints.
- *Task:* Make it safe to point at untrusted targets.
- *Action:* Realized `--scope` only classified results, never gated fetches.
  Added scope enforcement on the fetch path + a metadata/link-local denylist.
- *Result:* A target can no longer use the scanner as an SSRF pivot; regression
  test proves off-scope JS is never fetched.

**2. "My scanner was modifying the targets."**
- *Situation:* Validation inferred HTTP verbs from paths (`/delete/1`).
- *Task:* Confirm endpoints are live without changing state.
- *Action:* Only `DELETE` was downgraded; I extended it so every inferred
  mutation verb (POST/PUT/PATCH/DELETE) becomes a safe `OPTIONS` probe. Observed
  (browser) verbs are still reused because those are real app traffic.
- *Result:* A scan can never create/update/delete data from a guess.

**3. "Credentials were leaving the target's scope."**
- *Situation:* `--cookie` became a process-wide default header.
- *Task:* Authenticate scans without leaking the session.
- *Action:* Bound auth headers to scope; stripped them from vendor verification
  calls; wired cookies/headers into the browser context.
- *Result:* Login-gated apps now scan properly, and the cookie never reaches
  CDNs or third-party APIs.

**4. "A guard that didn't actually protect anything."**
- *Situation:* The JWKS SSRF guard resolved the host, but the HTTP stack
  resolved it again (DNS rebinding).
- *Task:* Make the guard match what actually connects.
- *Action:* Resolved once, validated, and pinned the IP for the request.
- *Result:* TOCTOU window closed; also added a response-size cap.

---

## Blog / write-up outline

**Title:** *I audited my own recon tool and found the bugs every scanner has*

1. Why a scanner is a security-sensitive program (SSRF pivot, credential leak,
   active requests).
2. Bug #1: the SSRF crawl — how `--scope` lied (classification ≠ enforcement).
3. Bug #2: my validator was deleting data from test targets.
4. Bug #3: cookies leaking to `api.stripe.com` via `--verify-secrets`.
5. Bug #4: a DNS-rebinding TOCTOU in the JWKS fetcher.
6. The fix pattern: **default-safe, scope-bound, fallback-only**.
7. What I'd test next (rebinding on the main crawler, fuzzing the parsers).
8. Link `SECURITY-FINDINGS.md` and the regression tests.

---

## LinkedIn post draft

> I built a JavaScript recon tool — then found SSRF, credential-leakage, and
> destructive-request bugs *in my own tool*.
>
> Recon scanners are security-sensitive: they carry your cookies and your
> network position. A crawler that follows any `<script src>` is an SSRF pivot.
> A validator that guesses `POST` from `/create` mutates the target. Auth
> headers treated as global defaults leak your session to third-party APIs.
>
> I fixed all three — default-safe, scope-bound, fallback-only — and wrote it up
> with regression tests. 883 tests passing.
>
> The lesson: "passive" tools still need a threat model. 🧵 #appsec #pentesting

---

## Honest claims checklist (don't overclaim)

- ✅ "883 tests passing" (verified).
- ✅ "Scope-bound authenticated scans" (verified with a cookie-gated app).
- ✅ "SSRF, credential-leak, and destructive-request fixes" (in `SECURITY-FINDINGS.md`).
- ⚠️ Say "self-assessed," not "penetration-tested by a third party."
- ⚠️ Browser-mode auth is implemented and unit-tested; state that it requires
  `playwright install chromium` to exercise.
- ❌ Do **not** claim CVSS-scored findings as if externally validated.
