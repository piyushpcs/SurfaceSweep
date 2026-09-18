import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- Patterns ----

# Paths with common API-ish keywords
ENDPOINT_PATTERN = re.compile(
    r'["\'](/[a-zA-Z0-9_\-./]*(?:api|v[0-9]|admin|auth|graphql|internal|user|account|token)[a-zA-Z0-9_\-./]*)["\']',
    re.IGNORECASE
)

# Any quoted absolute path — broader net, more noise, but catches what the above misses
GENERIC_PATH_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-./]{2,80})["\']')

FULL_URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./%?=&]*)?')

# Secrets / keys that commonly leak in JS — real bug bounty finding category
SECRET_PATTERNS = {
    "AWS Access Key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "Generic API Key":    re.compile(r'["\']api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,45})["\']', re.IGNORECASE),
    "Bearer Token":       re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
    "Google API Key":     re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    "Slack Token":        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Firebase URL":       re.compile(r'[a-zA-Z0-9-]+\.firebaseio\.com'),
    "Generic Secret":     re.compile(r'["\'](secret|token|apikey)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,})["\']', re.IGNORECASE),
}

# Noise to filter out — extensions/paths that are never useful endpoints
NOISE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".svg", ".gif", ".css", ".woff", ".woff2", ".ttf", ".ico")


def is_noise(path):
    return any(path.lower().endswith(ext) for ext in NOISE_EXTENSIONS)


def get_page(base_url, timeout=10):
    resp = requests.get(base_url, timeout=timeout, headers={"User-Agent": "SurfaceSweep/1.0"})
    resp.raise_for_status()
    return resp.text


def get_js_sources(base_url, html):
    """Return (external_js_urls, inline_script_contents)."""
    soup = BeautifulSoup(html, "html.parser")
    external, inline = [], []

    for script in soup.find_all("script"):
        if script.get("src"):
            external.append(urljoin(base_url, script["src"]))
        elif script.string:
            inline.append(script.string)

    return external, inline


def check_source_map(js_url, timeout=8):
    """Many builds leave .js.map files publicly accessible — these leak full source."""
    map_url = js_url + ".map"
    try:
        resp = requests.head(map_url, timeout=timeout)
        if resp.status_code == 200:
            return map_url
    except requests.RequestException:
        pass
    return None


def extract_from_text(content, source_label):
    """Run all regex passes over a blob of JS text. Returns structured findings."""
    endpoints = set()
    secrets = []

    for match in ENDPOINT_PATTERN.findall(content):
        if not is_noise(match):
            endpoints.add(match)

    for match in GENERIC_PATH_PATTERN.findall(content):
        if not is_noise(match) and len(match) > 3:
            endpoints.add(match)

    for match in FULL_URL_PATTERN.findall(content):
        if not is_noise(match):
            endpoints.add(match)

    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            secrets.append({
                "type": label,
                "match": m.group(0)[:80],  # truncate for safety/display
                "source": source_label
            })

    return endpoints, secrets


def fetch_and_extract(js_url, timeout=10):
    try:
        resp = requests.get(js_url, timeout=timeout, headers={"User-Agent": "SurfaceSweep/1.0"})
        endpoints, secrets = extract_from_text(resp.text, js_url)
        source_map = check_source_map(js_url)
        return {
            "source": js_url,
            "endpoints": endpoints,
            "secrets": secrets,
            "source_map_found": source_map
        }
    except requests.RequestException as e:
        return {"source": js_url, "error": str(e), "endpoints": set(), "secrets": []}


def run_extractor(base_url, threads=6, verbose=True):
    """
    Main entry point. Returns a structured dict — ready for JSON export
    or feeding straight into a dashboard later.
    """
    result = {
        "target": base_url,
        "js_files_scanned": [],
        "inline_scripts_scanned": 0,
        "endpoints": [],
        "secrets_found": [],
        "source_maps_found": [],
        "errors": []
    }

    if verbose:
        print(f"[*] Fetching {base_url}")

    try:
        html = get_page(base_url)
    except requests.RequestException as e:
        result["errors"].append(f"Failed to fetch base URL: {e}")
        return result

    external_js, inline_js = get_js_sources(base_url, html)
    if verbose:
        print(f"[+] Found {len(external_js)} external JS files, {len(inline_js)} inline scripts")

    all_endpoints = set()
    all_secrets = []

    # Inline scripts first — no network needed
    for i, content in enumerate(inline_js):
        eps, secs = extract_from_text(content, f"inline_script_{i}")
        all_endpoints.update(eps)
        all_secrets.extend(secs)
    result["inline_scripts_scanned"] = len(inline_js)

    # External JS files — concurrent fetch
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(fetch_and_extract, url): url for url in external_js}
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

            if verbose:
                print(f"    scanned {data['source']} — {len(data['endpoints'])} endpoints found")

    result["endpoints"] = sorted(all_endpoints)
    result["secrets_found"] = all_secrets

    if verbose:
        print(f"\n[+] Total unique endpoints: {len(result['endpoints'])}")
        if all_secrets:
            print(f"[!] {len(all_secrets)} potential secret(s) found — review manually!")
        if result["source_maps_found"]:
            print(f"[!] {len(result['source_maps_found'])} exposed source map(s)")

    return result


def save_report(result, filename="surfacesweep_report.json"):
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Report saved to {filename}")
    