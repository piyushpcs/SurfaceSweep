"""
JavaScript library version detection and CVE lookup.

Detects library versions from JS file content (version banners) and
URLs/filenames, then checks against:
  1. Local curated vulnerable-version database (fast, offline)
  2. OSV.dev API for additional CVEs (optional, requires network)
"""

import re
import requests
from modules.common.console import detail, info, ok, warn


# ---- Version detection patterns (from JS file content) ----

LIBRARY_PATTERNS = {
    "jQuery": [
        re.compile(r'jQuery v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
        re.compile(r'jQuery(?:\s+JavaScript\s+Library)?\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "Bootstrap": [
        re.compile(r'Bootstrap v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "Lodash": [
        re.compile(r'lodash\s+([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.-]*)', re.IGNORECASE),
        re.compile(r"VERSION\s*=\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]"),
    ],
    "Underscore.js": [
        re.compile(r'Underscore\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "AngularJS": [
        re.compile(r'AngularJS\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
        re.compile(r'angular\.version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']', re.IGNORECASE),
    ],
    "Angular": [
        re.compile(r'ng-version=["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    ],
    "React": [
        re.compile(r'React\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
        re.compile(r'React\.version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    ],
    "Vue.js": [
        re.compile(r'Vue\.js\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
        re.compile(r"version\s*:\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]"),
    ],
    "moment.js": [
        re.compile(r"moment\.version\s*=\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]"),
        re.compile(r'moment\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "Handlebars": [
        re.compile(r'Handlebars\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
        re.compile(r'Handlebars\.VERSION\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    ],
    "axios": [
        re.compile(r'axios\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "FancyBox": [
        re.compile(r'fancy[Bb]ox\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
    "FlexSlider": [
        re.compile(r'FlexSlider\s+v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE),
    ],
}

# ---- Version detection from URL/filename ----

FILENAME_PATTERNS = {
    "jQuery": re.compile(r'(?:^|/)jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "Bootstrap": re.compile(r'(?:^|/)bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "Lodash": re.compile(r'(?:^|/)lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "Underscore.js": re.compile(r'(?:^|/)underscore[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "moment.js": re.compile(r'(?:^|/)moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "Handlebars": re.compile(r'(?:^|/)handlebars[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "axios": re.compile(r'(?:^|/)axios[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "Vue.js": re.compile(r'(?:^|/)vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "React": re.compile(r'(?:^|/)react(?:-dom)?[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "FancyBox": re.compile(r'(?:^|/)fancybox[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
    "FlexSlider": re.compile(r'(?:^|/)flexslider[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.IGNORECASE),
}

# CDN path patterns: /ajax/libs/jquery/1.10.2/jquery.min.js
CDN_PATTERNS = {
    "jQuery": re.compile(r'ajax\.googleapis\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)/', re.IGNORECASE),
    "Bootstrap": re.compile(r'ajax\.googleapis\.com/ajax/libs/twitter-bootstrap/(\d+\.\d+\.\d+)/', re.IGNORECASE),
}


# ---- Curated vulnerable version database ----
# Format: library -> list of { vulnerable_below, cves, severity, description }
# "vulnerable_below" means ALL versions < this are vulnerable (simplest check).
# For ranges, use "vulnerable_range" with (min, max) exclusive max.

VULNERABILITIES = [
    {
        "library": "jQuery",
        "vulnerable_below": "3.5.0",
        "cves": ["CVE-2020-11022", "CVE-2020-11023"],
        "severity": "MEDIUM",
        "cvss": 6.9,
        "description": "XSS via htmlPrefilter in .html(), .append(), .after() with untrusted HTML",
        "fixed_in": "3.5.0",
    },
    {
        "library": "jQuery",
        "vulnerable_below": "3.4.0",
        "cves": ["CVE-2019-11358"],
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "Prototype pollution in jQuery.extend(true, {}, ...)",
        "fixed_in": "3.4.0",
    },
    {
        "library": "jQuery",
        "vulnerable_below": "1.9.0",
        "cves": ["CVE-2012-6708", "CVE-2015-9251"],
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "XSS: $() does not distinguish selectors from HTML; .load() cross-domain script XSS",
        "fixed_in": "1.9.0 / 3.0.0",
    },
    {
        "library": "Bootstrap",
        # CVE-2019-8331: fixed in 3.4.1 (3.x line) and 4.3.1 (4.x line).
        # vulnerable_below alone would flag fixed 3.4.1+ as < 4.3.1.
        "vulnerable_ranges": [
            {"from": "0", "below": "3.4.1"},
            {"from": "4.0.0", "below": "4.3.1"},
        ],
        "cves": ["CVE-2019-8331"],
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "XSS in tooltip/popover data-template, data-content, data-title attributes",
        "fixed_in": "4.3.1 / 3.4.1",
    },
    {
        "library": "Lodash",
        "vulnerable_below": "4.17.21",
        "cves": ["CVE-2021-23337", "CVE-2020-8203"],
        "severity": "HIGH",
        "cvss": 7.4,
        "description": "Command injection via _.template; prototype pollution in _.zipObjectDeep / _.set / _.pick",
        "fixed_in": "4.17.21",
    },
    {
        "library": "moment.js",
        "vulnerable_below": "2.29.4",
        "cves": ["CVE-2022-31129"],
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "ReDoS in RFC2822 date parsing (quadratic complexity)",
        "fixed_in": "2.29.4",
        "vulnerable_from": "2.18.0",
    },
    {
        "library": "Handlebars",
        "vulnerable_below": "4.7.7",
        "cves": ["CVE-2019-19919", "CVE-2021-23369", "CVE-2021-23383"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "RCE via Handlebars.compile() of untrusted templates",
        "fixed_in": "4.7.7",
    },
    {
        "library": "Underscore.js",
        "vulnerable_below": "1.12.1",
        "cves": ["CVE-2021-23358"],
        "severity": "HIGH",
        "cvss": 7.2,
        "description": "Arbitrary code execution via _.template() with unsanitized variable property",
        "fixed_in": "1.12.1 / 1.13.1",
    },
    {
        "library": "AngularJS",
        "vulnerable_below": "1.7.9",
        "cves": ["CVE-2019-10768"],
        "severity": "HIGH",
        "cvss": 7.1,
        "description": "Prototype pollution in angular.merge() via __proto__",
        "fixed_in": "1.7.9",
    },
    {
        "library": "AngularJS",
        "vulnerable_below": "99.0.0",  # all AngularJS 1.x affected
        "cves": ["CVE-2022-25844"],
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "ReDoS via custom locale posPre (AngularJS is EOL, no fix)",
        "fixed_in": "N/A (EOL)",
        "vulnerable_from": "1.7.0",
    },
    {
        "library": "axios",
        "vulnerable_below": "1.7.4",
        "cves": ["CVE-2024-39338"],
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "SSRF: path-relative URLs treated as protocol-relative",
        "fixed_in": "1.7.4",
        "vulnerable_from": "1.3.2",
    },
    {
        "library": "FancyBox",
        "vulnerable_below": "99.0.0",  # all versions potentially affected
        "cves": ["CVE-2024-5020"],
        "severity": "MEDIUM",
        "cvss": 6.4,
        "description": "Stored DOM XSS via insufficient attribute escaping",
        "fixed_in": "See vendor advisory",
        "vulnerable_from": "1.3.4",
    },
    {
        "library": "React",
        "vulnerable_below": "16.5.0",
        "cves": ["CVE-2018-6341"],
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "XSS: ReactDOMServer does not escape user-supplied attribute names (SSR only)",
        "fixed_in": "16.5.0",
        "vulnerable_from": "16.0.0",
    },
    {
        "library": "Vue.js",
        "vulnerable_below": "99.0.0",  # Vue 2 all EOL
        "cves": ["CVE-2024-6783"],
        "severity": "MEDIUM",
        "cvss": 4.8,
        "description": "XSS via prototype pollution in staticClass/staticStyle (Vue 2 EOL)",
        "fixed_in": "Vue 3 only",
        "vulnerable_from": "2.0.0",
        "max_version": "2.7.16",
    },
]


def _parse_version(version_str):
    """Parse version string to tuple of ints for comparison."""
    try:
        parts = re.findall(r'\d+', version_str)
        return tuple(int(p) for p in parts[:4]) if parts else (0,)
    except (ValueError, AttributeError):
        return (0,)


def _version_lt(v1, v2):
    """Check if version v1 < v2."""
    t1, t2 = _parse_version(v1), _parse_version(v2)
    # Pad to same length
    max_len = max(len(t1), len(t2))
    t1 = t1 + (0,) * (max_len - len(t1))
    t2 = t2 + (0,) * (max_len - len(t2))
    return t1 < t2


def _version_gte(v1, v2):
    """Check if version v1 >= v2."""
    return not _version_lt(v1, v2)


def _version_lte(v1, v2):
    """Check if version v1 <= v2."""
    return _version_lt(v1, v2) or _parse_version(v1) == _parse_version(v2)


def detect_libraries_from_content(content, source_url=""):
    """
    Detect library versions from JS file content and URL.
    Returns list of {library, version, source}.
    """
    found = {}

    # From content (banner patterns)
    for lib_name, patterns in LIBRARY_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(content)
            if match:
                version = match.group(1)
                if lib_name not in found:
                    found[lib_name] = {
                        "library": lib_name,
                        "version": version,
                        "source": "content",
                        "file": source_url,
                    }
                break  # First pattern match wins per library

    # From URL/filename (only if not already found in content)
    for lib_name, pattern in FILENAME_PATTERNS.items():
        if lib_name not in found:
            match = pattern.search(source_url)
            if match:
                found[lib_name] = {
                    "library": lib_name,
                    "version": match.group(1),
                    "source": "filename",
                    "file": source_url,
                }

    # From CDN URLs
    for lib_name, pattern in CDN_PATTERNS.items():
        if lib_name not in found:
            match = pattern.search(source_url)
            if match:
                found[lib_name] = {
                    "library": lib_name,
                    "version": match.group(1),
                    "source": "cdn_url",
                    "file": source_url,
                }

    return list(found.values())


def _matches_vulnerability(version: str, vuln: dict) -> bool:
    """
    Return True when version is affected by vuln entry.

    Supports:
      - vulnerable_from / max_version bounds
      - vulnerable_below (all versions < bound)
      - vulnerable_ranges: list of {from, below} half-open intervals
        (numeric comparison — never lexicographic)
    """
    if "vulnerable_from" in vuln and not _version_gte(version, vuln["vulnerable_from"]):
        return False
    if "max_version" in vuln and not _version_lte(version, vuln["max_version"]):
        return False

    if "vulnerable_ranges" in vuln:
        for rng in vuln["vulnerable_ranges"]:
            lo = rng.get("from", "0")
            hi = rng.get("below")
            if hi is None:
                continue
            if _version_gte(version, lo) and _version_lt(version, hi):
                return True
        return False

    if "vulnerable_below" in vuln:
        return _version_lt(version, vuln["vulnerable_below"])

    # No version constraint — treat as always matching for this library
    return True


def check_vulnerabilities(libraries):
    """
    Check detected libraries against local vulnerable-version database.
    Returns list of vulnerability findings, merged per (library, version)
    so overlapping CVE entries are not double-counted in risk scoring.
    """
    raw = []

    for lib in libraries:
        lib_name = lib["library"]
        version = lib["version"]

        for vuln in VULNERABILITIES:
            if vuln["library"] != lib_name:
                continue
            if not _matches_vulnerability(version, vuln):
                continue

            raw.append({
                "library": lib_name,
                "version": version,
                "cves": list(vuln["cves"]),
                "severity": vuln["severity"],
                "cvss": vuln.get("cvss"),
                "description": vuln["description"],
                "fixed_in": vuln.get("fixed_in", "unknown"),
                "source_file": lib.get("file", ""),
            })

    # Merge findings for the same library+version (union CVEs, keep max severity)
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    merged: dict = {}
    for f in raw:
        key = (f["library"], f["version"])
        if key not in merged:
            merged[key] = f
            continue
        existing = merged[key]
        existing["cves"] = sorted(set(existing["cves"]) | set(f["cves"]))
        if severity_rank.get(f["severity"], 0) > severity_rank.get(existing["severity"], 0):
            existing["severity"] = f["severity"]
            existing["description"] = f["description"]
            existing["fixed_in"] = f["fixed_in"]
        if f.get("cvss") and (not existing.get("cvss") or f["cvss"] > existing["cvss"]):
            existing["cvss"] = f["cvss"]

    return list(merged.values())


def query_osv(libraries, timeout=10):
    """
    Query OSV.dev for additional CVEs not in local database.
    Returns dict mapping library name -> list of OSV findings.
    """
    if not libraries:
        return {}

    # Build batch query
    queries = []
    lib_map = {}  # index -> library info

    for i, lib in enumerate(libraries):
        # Map our library names to npm package names
        npm_name = {
            "jQuery": "jquery",
            "Bootstrap": "bootstrap",
            "Lodash": "lodash",
            "Underscore.js": "underscore",
            "moment.js": "moment",
            "Handlebars": "handlebars",
            "axios": "axios",
            "Vue.js": "vue",
            "React": "react",
            "AngularJS": "angular",
        }.get(lib["library"])

        if npm_name:
            queries.append({
                "package": {"name": npm_name, "ecosystem": "npm"},
                "version": lib["version"],
            })
            lib_map[i] = lib

    if not queries:
        return {}

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return {}

    results = {}
    for i, result in enumerate(data.get("results", [])):
        if i not in lib_map:
            continue
        lib = lib_map[i]
        vulns = result.get("vulns", [])
        if vulns:
            findings = []
            for v in vulns[:5]:  # Limit to 5 per library
                findings.append({
                    "id": v.get("id", ""),
                    "summary": v.get("summary", "")[:200],
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                })
            results[lib["library"]] = {
                "version": lib["version"],
                "vulns": findings,
            }

    return results


def scan_for_libraries(js_files, content_map=None, use_osv=False, verbose=True):
    """
    Scan a list of JS files for library versions and vulnerabilities.

    Args:
        js_files: list of JS file URLs
        content_map: dict mapping URL -> content (if already fetched)
        use_osv: whether to query OSV.dev API
        verbose: print progress

    Returns:
        {
            "libraries": [ {library, version, source, file}, ... ],
            "vulnerabilities": [ {library, version, cves, severity, ...}, ... ],
            "osv_results": { lib_name: {version, vulns: [...]}, ... }
        }
    """
    all_libraries = []
    seen = set()

    for js_url in js_files:
        content = content_map.get(js_url, "") if content_map else ""
        libs = detect_libraries_from_content(content, js_url)
        for lib in libs:
            key = (lib["library"], lib["version"])
            if key not in seen:
                seen.add(key)
                all_libraries.append(lib)

    # Check local vulnerability database
    vulns = check_vulnerabilities(all_libraries)

    # Query OSV if requested
    osv_results = {}
    if use_osv and all_libraries:
        if verbose:
            info(f" Querying OSV.dev for {len(all_libraries)} library version(s)...")
        osv_results = query_osv(all_libraries)
        if verbose:
            total_osv = sum(len(v.get("vulns", [])) for v in osv_results.values())
            ok(f" OSV: {total_osv} additional vulnerability record(s) found")

    if verbose and all_libraries:
        ok(f" Detected {len(all_libraries)} library version(s):")
        for lib in all_libraries:
            detail(f"{lib['library']} {lib['version']} ({lib['source']})")
        if vulns:
            warn(f" {len(vulns)} known vulnerability(ies) detected:")
            for v in vulns:
                cve_str = ", ".join(v["cves"][:2])
                detail(f"[!] {v['library']} {v['version']} — {v['severity']}: {cve_str}")

    return {
        "libraries": all_libraries,
        "vulnerabilities": vulns,
        "osv_results": osv_results,
    }
