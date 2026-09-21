import re
import json
import time
import requests
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_registrable_domain(url):
    """Extract the registered domain (e.g. 'example.com' from 'sub.example.com')."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or urlparse(url).netloc


def is_same_scope(url, target_domain):
    return get_registrable_domain(url) == target_domain

# ---- Patterns ----

ENDPOINT_PATTERN = re.compile(
    r'["\'](/[a-zA-Z0-9_\-./]*(?:api|v[0-9]|admin|auth|graphql|internal|user|account|token)[a-zA-Z0-9_\-./]*)["\']',
    re.IGNORECASE
)

GENERIC_PATH_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-./]{2,80})["\']')

FULL_URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./%?=&]*)?')

# NEW: catches URLs passed as arguments to common HTTP call patterns —
# fetch("/api/x"), axios.get('/path'), $.ajax({url: "..."}), $.post("/x"), http.request("/x")
CALL_PATTERN = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:ajax|get|post)|http\.request)\s*\(\s*'
    r'(?:\{[^}]*url\s*:\s*)?["\']([^"\']{2,150})["\']',
    re.IGNORECASE
)

SECRET_PATTERNS = {
    "AWS Access Key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "Generic API Key":    re.compile(r'["\']api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,45})["\']', re.IGNORECASE),
    "Bearer Token":       re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
    "Google API Key":     re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    "Slack Token":        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Firebase URL":       re.compile(r'[a-zA-Z0-9-]+\.firebaseio\.com'),
    "Generic Secret":     re.compile(r'["\'](secret|token|apikey)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,})["\']', re.IGNORECASE),
    # NEW patterns
    "GitHub Token":       re.compile(r'gh[po]_[a-zA-Z0-9]{36,}'),
    "GitLab Token":       re.compile(r'glpat-[a-zA-Z0-9_\-]{20}'),
    "Stripe Live Key":    re.compile(r'[sp]k_live_[a-zA-Z0-9]{24,}'),
    "Heroku API Key":     re.compile(r'["\']heroku[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9\-]{20,})["\']', re.IGNORECASE),
    "NPM Token":          re.compile(r'npm_[a-zA-Z0-9]{36}'),
    "Exposed Env Var":    re.compile(r'(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\s*[:=]\s*["\']([^"\']{4,100})["\']'),
}

NOISE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".svg", ".gif", ".css", ".woff", ".woff2", ".ttf", ".ico")

COMMON_FALSE_POSITIVES = {"loading", "null", "undefined", "true", "false", "none", "test", "example", "placeholder"}

# Patterns to discover other JS files referenced inside JS code (webpack chunks, dynamic imports, etc.)
JS_REFERENCE_PATTERN = re.compile(
    r'''(?:src|import|require|from|chunk|loadScript|importScripts)\s*(?:\(|[=:]?\s*)['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',
    re.IGNORECASE
)
WEBPACK_CHUNK_PATTERN = re.compile(r'''['"]([^'"]*(?:chunk|vendor|main|app|bundle)[^'"]*\.js)['"]''', re.IGNORECASE)


class RateLimiter:
    """Simple token-bucket rate limiter."""
    def __init__(self, requests_per_second=5):
        self.min_interval = 1.0 / requests_per_second
        self._last = 0.0
        self._lock = __import__("threading").Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


def fetch_with_retry(url, timeout=10, max_retries=3, limiter=None, headers=None):
    """Fetch a URL with exponential backoff on 429/5xx errors."""
    if headers is None:
        headers = {"User-Agent": "SurfaceSweep/1.0"}

    for attempt in range(max_retries):
        if limiter:
            limiter.wait()
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                time.sleep(retry_after)
                continue
            if resp.status_code >= 500 and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            resp.raise_for_status()
            return resp
        except requests.ConnectionError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
    return None


def is_noise(path):
    return any(path.lower().endswith(ext) for ext in NOISE_EXTENSIONS)


def is_likely_real_secret(value):
    if value.lower() in COMMON_FALSE_POSITIVES:
        return False
    if len(value) < 10:
        return False
    return True


def get_page(base_url, timeout=10, limiter=None):
    resp = fetch_with_retry(base_url, timeout=timeout, limiter=limiter)
    if resp is None:
        raise requests.ConnectionError(f"Failed to fetch {base_url} after retries")
    return resp.text


def get_js_sources(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    external, inline = [], []

    for script in soup.find_all("script"):
        if script.get("src"):
            external.append(urljoin(base_url, script["src"]))
        elif script.string:
            inline.append(script.string)

    return external, inline


def check_source_map(js_url, timeout=8, limiter=None):
    map_url = js_url + ".map"
    try:
        resp = fetch_with_retry(map_url, timeout=timeout, limiter=limiter)
        if resp is not None and resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            body_start = resp.text.strip()[:1]
            if "json" in content_type.lower() or body_start == "{":
                return map_url
    except requests.RequestException:
        pass
    return None


def discover_js_chunks(js_content, base_js_url):
    """Find references to other JS files inside a JS file's content."""
    candidates = set()
    for match in JS_REFERENCE_PATTERN.findall(js_content):
        candidates.add(match)
    for match in WEBPACK_CHUNK_PATTERN.findall(js_content):
        candidates.add(match)

    resolved = set()
    for path in candidates:
        if path.startswith("http://") or path.startswith("https://"):
            resolved.add(path)
        elif path.startswith("//"):
            resolved.add("https:" + path)
        elif path.startswith("/"):
            parsed = urlparse(base_js_url)
            resolved.add(f"{parsed.scheme}://{parsed.netloc}{path}")
        else:
            resolved.add(urljoin(base_js_url, path))
    return resolved


def extract_from_text(content, source_label):
    """Run all regex passes over a blob of JS text. Returns structured findings."""
    endpoints = set()
    secrets = []

    for match in ENDPOINT_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match):
            endpoints.add(match)

    for match in GENERIC_PATH_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match) and len(match) > 3:
            endpoints.add(match)

    for match in FULL_URL_PATTERN.findall(content):
        if not is_noise(match):
            endpoints.add(match)

    # NEW: function-call based extraction — catches fetch()/axios()/$.ajax() etc.
    for match in CALL_PATTERN.findall(content):
        if match.startswith("//"):
            continue
        if not is_noise(match) and len(match) > 1:
            endpoints.add(match)

    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            # for patterns with capture groups, use the group; else use full match
            value = m.group(1) if m.groups() else m.group(0)
            if not is_likely_real_secret(value):
                continue
            secrets.append({
                "type": label,
                "match": m.group(0)[:80],
                "source": source_label
            })

    return endpoints, secrets


def deduplicate_secrets(all_secrets):
    """
    Same secret appearing in multiple files should be one entry with
    a list of sources, not N duplicate entries.
    """
    dedup = {}
    for s in all_secrets:
        key = (s["type"], s["match"])
        if key not in dedup:
            dedup[key] = {"type": s["type"], "match": s["match"], "sources": []}
        if s["source"] not in dedup[key]["sources"]:
            dedup[key]["sources"].append(s["source"])
    return list(dedup.values())


def fetch_and_extract(js_url, timeout=10, limiter=None):
    try:
        resp = fetch_with_retry(js_url, timeout=timeout, limiter=limiter)
        if resp is None:
            return {"source": js_url, "error": "Failed after retries", "endpoints": set(), "secrets": [], "linked_js": set()}

        content_type = resp.headers.get("Content-Type", "")
        text = resp.text if "json" not in content_type.lower() else ""
        endpoints, secrets = extract_from_text(text, js_url) if text else (set(), [])
        source_map = check_source_map(js_url, limiter=limiter)
        linked_js = discover_js_chunks(text, js_url) if text else set()

        return {
            "source": js_url,
            "endpoints": endpoints,
            "secrets": secrets,
            "source_map_found": source_map,
            "linked_js": linked_js
        }
    except requests.RequestException as e:
        return {"source": js_url, "error": str(e), "endpoints": set(), "secrets": [], "linked_js": set()}


def calculate_risk_summary(result):
    """Simple scoring so the report isn't just a flat data dump."""
    score = 0
    score += len(result.get("secrets_found", [])) * 10
    score += len(result.get("source_maps_found", [])) * 5
    score += len(result.get("internal_paths", [])) * 1

    if score >= 30:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    return {"score": score, "level": level}


def run_extractor(base_url, threads=6, verbose=True, max_depth=1):
    """
    Main entry point. Returns a structured dict — ready for JSON export
    or feeding straight into a dashboard later.

    max_depth: how many hops into referenced JS files to follow (0 = base HTML only,
               1 = JS referenced from HTML, 2 = JS referenced from those JS files, etc.)
    """
    result = {
        "target": base_url,
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "source_maps_found": [],
        "errors": [],
        "scan_depth": max_depth
    }

    target_domain = get_registrable_domain(base_url)
    limiter = RateLimiter(requests_per_second=5)

    if verbose:
        print(f"[*] Fetching {base_url}")

    try:
        html = get_page(base_url, limiter=limiter)
    except requests.RequestException as e:
        result["errors"].append(f"Failed to fetch base URL: {e}")
        return result

    external_js, inline_js = get_js_sources(base_url, html)
    if verbose:
        print(f"[+] Found {len(external_js)} external JS files, {len(inline_js)} inline scripts")

    all_endpoints = set()
    all_secrets = []

    for i, content in enumerate(inline_js):
        eps, secs = extract_from_text(content, f"inline_script_{i}")
        all_endpoints.update(eps)
        all_secrets.extend(secs)
    result["inline_scripts_scanned"] = len(inline_js)

    visited_js = set()

    def scan_js_urls(js_urls, depth):
        nonlocal all_endpoints, all_secrets
        if not js_urls or depth > max_depth:
            return

        new_urls = [u for u in js_urls if u not in visited_js]
        visited_js.update(new_urls)

        if verbose and depth > 0:
            print(f"[*] Depth {depth}: scanning {len(new_urls)} additional JS files")

        linked_at_this_level = set()

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_and_extract, url, limiter=limiter): url for url in new_urls}
            for future in as_completed(futures):
                data = future.result()
                if "error" in data:
                    result["errors"].append(f"{data['source']}: {data['error']}")
                    if verbose:
                        print(f"    [!] failed: {data['source']} — {data['error']}")
                    continue

                result["js_files_scanned"].append(data["source"])
                all_endpoints.update(data["endpoints"])
                all_secrets.extend(data["secrets"])

                if data["source_map_found"]:
                    result["source_maps_found"].append(data["source_map_found"])
                    if verbose:
                        print(f"    [!] Source map exposed: {data['source_map_found']}")

                linked_at_this_level.update(data.get("linked_js", set()))

                if verbose:
                    print(f"    scanned {data['source']} — {len(data['endpoints'])} endpoints found")

        if linked_at_this_level:
            scan_js_urls(linked_at_this_level, depth + 1)

    scan_js_urls(external_js, depth=0)

    result["internal_paths"] = sorted([e for e in all_endpoints if e.startswith("/")])
    result["in_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and is_same_scope(e, target_domain)
    ])
    result["out_of_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and not is_same_scope(e, target_domain)
    ])
    result["secrets_found"] = deduplicate_secrets(all_secrets)
    result["risk_summary"] = calculate_risk_summary(result)

    if verbose:
        print(f"\n[+] Internal paths found: {len(result['internal_paths'])}")
        print(f"[+] In-scope external URLs: {len(result['in_scope_urls'])}")
        print(f"[+] Out-of-scope URLs (informational only): {len(result['out_of_scope_urls'])}")
        if result["secrets_found"]:
            print(f"[!] {len(result['secrets_found'])} unique potential secret(s) found — review manually!")
        if result["source_maps_found"]:
            print(f"[!] {len(result['source_maps_found'])} exposed source map(s)")
        print(f"[+] Risk level: {result['risk_summary']['level']} (score: {result['risk_summary']['score']})")

    return result


def save_report(result, filename="reports/surfacesweep_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Report saved to {filename}")
    except OSError as e:
        print(f"[!] Failed to save report to {filename}: {e}")


def save_html_report(result, filename="reports/surfacesweep_report.html"):
    """Generate a self-contained HTML report for easy viewing and sharing."""
    risk = result.get("risk_summary", {})
    risk_color = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60", "INFO": "#3498db"}.get(risk.get("level", ""), "#999")

    def render_list(items, empty_msg="None found"):
        if not items:
            return f'<p class="muted">{empty_msg}</p>'
        return "<ul>" + "".join(f"<li><code>{item}</code></li>" for item in items) + "</ul>"

    def render_secrets(secrets):
        if not secrets:
            return '<p class="muted">No secrets detected</p>'
        rows = []
        for s in secrets:
            sources = ", ".join(s.get("sources", [s.get("source", "unknown")]))
            rows.append(f'<tr><td><span class="badge badge-high">{s["type"]}</span></td>'
                        f'<td><code>{s["match"]}</code></td>'
                        f'<td class="muted">{sources}</td></tr>')
        return '<table><thead><tr><th>Type</th><th>Match</th><th>Sources</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SurfaceSweep Report — {result.get('target', 'unknown')}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.6; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.15rem; margin: 1.5rem 0 0.5rem; color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }}
  .target {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .risk {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 600; color: #fff; background: {risk_color}; font-size: 0.9rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .stat {{ background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; color: #58a6ff; }}
  .stat .label {{ font-size: 0.8rem; color: #8b949e; margin-top: 0.25rem; }}
  ul {{ list-style: none; padding: 0; }}
  li {{ padding: 0.25rem 0; }}
  code {{ background: #161b22; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th {{ text-align: left; padding: 0.5rem; border-bottom: 2px solid #21262d; color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ padding: 0.5rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }}
  .badge-high {{ background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }}
  .muted {{ color: #8b949e; }}
  .errors {{ background: #e74c3c11; border: 1px solid #e74c3c33; border-radius: 6px; padding: 1rem; margin-top: 1rem; }}
  .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d; color: #484f58; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<h1>SurfaceSweep — Attack Surface Report</h1>
<p class="target">Target: {result.get('target', 'N/A')} | Scan depth: {result.get('scan_depth', 0)} | Risk: <span class="risk">{risk.get('level', 'N/A')}</span> (score: {risk.get('score', 0)})</p>

<div class="stats">
  <div class="stat"><div class="num">{len(result.get('js_files_scanned', []))}</div><div class="label">JS Files Scanned</div></div>
  <div class="stat"><div class="num">{result.get('inline_scripts_scanned', 0)}</div><div class="label">Inline Scripts</div></div>
  <div class="stat"><div class="num">{len(result.get('internal_paths', []))}</div><div class="label">Internal Paths</div></div>
  <div class="stat"><div class="num">{len(result.get('secrets_found', []))}</div><div class="label">Secrets Found</div></div>
  <div class="stat"><div class="num">{len(result.get('source_maps_found', []))}</div><div class="label">Exposed Source Maps</div></div>
</div>

<h2>Internal Paths</h2>
{render_list(result.get('internal_paths', []), 'No internal paths discovered')}

<h2>In-Scope URLs</h2>
{render_list(result.get('in_scope_urls', []), 'No in-scope URLs found')}

<h2>Out-of-Scope URLs (informational)</h2>
{render_list(result.get('out_of_scope_urls', []), 'None')}

<h2>Secrets / Leaked Keys</h2>
{render_secrets(result.get('secrets_found', []))}

<h2>Exposed Source Maps</h2>
{render_list(result.get('source_maps_found', []), 'None found')}

<h2>JS Files Scanned</h2>
{render_list(result.get('js_files_scanned', []))}

{"<h2>Errors</h2><div class='errors'>" + "".join(f"<p>" + e + "</p>" for e in result.get('errors', [])) + "</div>" if result.get('errors') else ""}

<div class="footer">Generated by SurfaceSweep</div>
</body>
</html>"""

    try:
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] HTML report saved to {filename}")
    except OSError as e:
        print(f"[!] Failed to save HTML report to {filename}: {e}")


if __name__ == "__main__":
    print("This module is meant to be imported, not run directly. Use main.py instead.")


def merge_results(static_result, browser_result):
    """
    Combine results from static scan and browser scan into a single unified report.
    Deduplicates endpoints, secrets, and source maps across both modes.
    """
    merged = {
        "target": static_result.get("target", browser_result.get("target")),
        "scan_mode": "full",
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "secrets_found": [],
        "source_maps_found": [],
        "network_requests": [],
        "intercepted_endpoints": [],
        "errors": [],
        "scan_depth": static_result.get("scan_depth", 0)
    }

    seen_js = set()
    for js in static_result.get("js_files_scanned", []) + browser_result.get("js_files_scanned", []):
        if js not in seen_js:
            merged["js_files_scanned"].append(js)
            seen_js.add(js)

    merged["inline_scripts_scanned"] = (
        static_result.get("inline_scripts_scanned", 0) +
        browser_result.get("inline_scripts_scanned", 0)
    )

    seen_maps = set()
    for m in static_result.get("source_maps_found", []) + browser_result.get("source_maps_found", []):
        if m not in seen_maps:
            merged["source_maps_found"].append(m)
            seen_maps.add(m)

    merged["network_requests"] = browser_result.get("network_requests", [])
    merged["intercepted_endpoints"] = browser_result.get("intercepted_endpoints", [])

    all_endpoints = set()
    all_endpoints.update(static_result.get("internal_paths", []))
    all_endpoints.update(static_result.get("in_scope_urls", []))
    all_endpoints.update(static_result.get("out_of_scope_urls", []))
    all_endpoints.update(browser_result.get("internal_paths", []))
    all_endpoints.update(browser_result.get("in_scope_urls", []))
    all_endpoints.update(browser_result.get("out_of_scope_urls", []))

    target_domain = get_registrable_domain(merged["target"])
    merged["internal_paths"] = sorted([e for e in all_endpoints if e.startswith("/") and not e.startswith("//")])
    merged["in_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and is_same_scope(e, target_domain)
    ])
    merged["out_of_scope_urls"] = sorted([
        e for e in all_endpoints if e.startswith("http") and not is_same_scope(e, target_domain)
    ])

    all_secrets = []
    all_secrets.extend(static_result.get("secrets_found", []))
    all_secrets.extend(browser_result.get("secrets_found", []))
    flat_secrets = []
    for s in all_secrets:
        for src in s.get("sources", [s.get("source", "unknown")]):
            flat_secrets.append({"type": s["type"], "match": s["match"], "source": src})
    merged["secrets_found"] = deduplicate_secrets(flat_secrets)

    merged["errors"] = list(set(
        static_result.get("errors", []) + browser_result.get("errors", [])
    ))

    merged["risk_summary"] = calculate_risk_summary(merged)

    return merged