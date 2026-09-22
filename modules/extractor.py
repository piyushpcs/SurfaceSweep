import re
import json
import time
import requests
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.deobfuscator import deobfuscate
from modules.report import save_report, save_html_report


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
    "GitHub Token":       re.compile(r'gh[po]_[a-zA-Z0-9]{36,}'),
    "GitLab Token":       re.compile(r'glpat-[a-zA-Z0-9_\-]{20}'),
    "Stripe Live Key":    re.compile(r'[sp]k_live_[a-zA-Z0-9]{24,}'),
    "Heroku API Key":     re.compile(r'["\']heroku[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9\-]{20,})["\']', re.IGNORECASE),
    "NPM Token":          re.compile(r'npm_[a-zA-Z0-9]{36}'),
    "Exposed Env Var":    re.compile(r'(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\s*[:=]\s*["\']([^"\']{4,100})["\']'),
    "Private Key":        re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----'),
    "JWT Secret":         re.compile(r'["\'](?:jwt[_-]?secret|signing[_-]?key|hmac[_-]?key|jwt[_-]?key)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/+=]{10,})["\']', re.IGNORECASE),
    "Database URL":       re.compile(r'(mysql|postgres|postgresql|mongodb|redis|amqp|mssql):\/\/[^\s"\'<>]{10,}', re.IGNORECASE),
    "SMTP Credentials":   re.compile(r'["\'](?:smtp[_-]?pass|mail[_-]?password|email[_-]?password)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']', re.IGNORECASE),
    "Basic Auth":         re.compile(r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}'),
    "Generic Password":   re.compile(r'["\'](password|passwd|pwd|pass)["\']\s*[:=]\s*["\']([^\s"\']{6,})["\']', re.IGNORECASE),
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


def extract_from_text(content, source_label, do_deobfuscate=True):
    """Run all regex passes over a blob of JS text. Returns structured findings."""
    deobf_findings = []
    if do_deobfuscate:
        content, deobf_findings = deobfuscate(content)

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

    return endpoints, secrets, deobf_findings

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
        endpoints, secrets, deobf = extract_from_text(text, js_url) if text else (set(), [], [])
        source_map = check_source_map(js_url, limiter=limiter)
        linked_js = discover_js_chunks(text, js_url) if text else set()

        return {
            "source": js_url,
            "endpoints": endpoints,
            "secrets": secrets,
            "source_map_found": source_map,
            "linked_js": linked_js,
            "deobfuscation_findings": deobf
        }
    except requests.RequestException as e:
        return {"source": js_url, "error": str(e), "endpoints": set(), "secrets": [], "linked_js": set(), "deobfuscation_findings": []}


def calculate_risk_summary(result):
    """Simple scoring so the report isn't just a flat data dump."""
    score = 0
    score += len(result.get("secrets_found", [])) * 10
    score += len(result.get("source_maps_found", [])) * 5
    score += len(result.get("deobfuscation_findings", [])) * 3
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


def run_extractor(base_url, threads=6, verbose=True, max_depth=1, deobfuscate=True):
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
        "deobfuscation_findings": [],
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
        eps, secs, deobf = extract_from_text(content, f"inline_script_{i}", do_deobfuscate=deobfuscate)
        all_endpoints.update(eps)
        all_secrets.extend(secs)
        result["deobfuscation_findings"].extend(deobf)
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
                result["deobfuscation_findings"].extend(data.get("deobfuscation_findings", []))

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
        if result["deobfuscation_findings"]:
            print(f"[!] {len(result['deobfuscation_findings'])} obfuscated string(s) decoded")
        print(f"[+] Risk level: {result['risk_summary']['level']} (score: {result['risk_summary']['score']})")

    return result


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
        "deobfuscation_findings": [],
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

    seen_deobf = set()
    for d in static_result.get("deobfuscation_findings", []) + browser_result.get("deobfuscation_findings", []):
        key = (d.get("type"), d.get("decoded"))
        if key not in seen_deobf:
            merged["deobfuscation_findings"].append(d)
            seen_deobf.add(key)
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