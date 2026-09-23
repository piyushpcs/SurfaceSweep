"""
Scan-level JWT orchestration: collect tokens from a result, run analysis,
build summaries, export NDJSON/hashcat, and compute risk boost.
"""

import json

from modules.jwt.checks import SEVERITY_ORDER, analyze_jwt
from modules.jwt.crack import build_crack_candidates, export_hashcat
from modules.jwt.decode import decode_jwt, deduplicate_jwts, extract_jwts
from modules.jwt.keys import collect_jku_urls, fetch_jwks_keys


def collect_jwts_from_result(result):
    """
    Gather unique JWTs from secrets_found (type JWT) and any raw jwt fields.
    Secrets module stores match truncated to 80 — re-extract from sources if needed.
    """
    tokens = []
    seen = set()
    for s in result.get("secrets_found", []):
        if s.get("type") != "JWT":
            continue
        for src in s.get("sources", [s.get("source", "unknown")]):
            tok = s.get("match", "")
            if tok.count(".") >= 2 and tok not in seen:
                dec = decode_jwt(tok)
                if not dec.get("error") and tok not in seen:
                    seen.add(tok)
                    tokens.append({"token": tok, "source": src})
    for item in result.get("jwts_found", []) or []:
        tok = item.get("token", "")
        if tok and tok not in seen:
            dec = decode_jwt(tok)
            if not dec.get("error"):
                seen.add(tok)
                tokens.append({"token": tok, "source": item.get("source", "unknown")})
    return tokens


def export_jwt_findings(jwt_result, path):
    """
    Write one JSON object per analyzed token (NDJSON) for tooling.
    Returns count of lines written.
    """
    written = 0
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for a in (jwt_result or {}).get("findings", []):
                fh.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
                written += 1
    except OSError:
        return 0
    return written


def jwt_summary(analyses, severity_counts, candidates_meta, exported=0):
    """Compact summary block for JSON consumers (parity with CORS schema)."""
    cracked = sum(1 for a in analyses if a.get("cracked_secret"))
    issue_counts = {}
    for a in analyses:
        for f in a.get("findings", []):
            issue = f.get("issue", "unknown")
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    summary = {
        "tokens_analyzed": len(analyses),
        "severity_counts": severity_counts,
        "cracked_secrets": cracked,
        "candidate_secrets_tried": (candidates_meta or {}).get("total", 0),
        "issue_counts": dict(sorted(issue_counts.items(), key=lambda kv: -kv[1])),
    }
    if exported:
        summary["hashcat_exported"] = exported
    return summary


def analyze_result_jwts(result, verbose=True, wordlist_path=None, target=None,
                        hashcat_path=None, export_path=None, network=False,
                        network_timeout=5.0):
    """
    Run JWT analysis over a full scan result.
    Args:
        wordlist_path: optional extra newline-delimited secret wordlist
        target: target URL — derive host-based HMAC mutations
        hashcat_path: if set, export HS* tokens in hashcat mode 16500 format
        export_path: if set, write per-token findings as NDJSON
        network: fetch jku/x5u JWKS over the network (SSRF-guarded) for
                 RS256→HS256 key-confusion checks (CLI: --jwt-network)
        network_timeout: seconds for each JWKS fetch when network=True
    Returns:
      {
        "schema_version": 1,
        "tokens_analyzed": n,
        "findings": [analyze_jwt dicts...],
        "severity_counts": {...},
        "summary": {...},
        "candidate_secrets_tried": n,
        "crack_meta": {...},
        "hashcat_exported": n,
        "findings_exported": n,
        "jku_fetches": n,           # when network=True
        "network_key_materials": n  # when network=True
      }
    """
    if verbose:
        print("[*] --- JWT Analysis ---")

    candidates, crack_meta = build_crack_candidates(
        result, wordlist_path=wordlist_path, target=target
    )

    tokens = collect_jwts_from_result(result)

    hashcat_n = 0
    if hashcat_path and tokens:
        hashcat_n = export_hashcat([t["token"] for t in tokens], hashcat_path)
        if verbose and hashcat_n:
            print(f"[+] Exported {hashcat_n} HS* JWT(s) for hashcat (-m 16500): {hashcat_path}")

    # Optional network: fetch jku/x5u JWKS → PEM key materials for confusion PoC
    network_materials = []
    jku_fetches = 0
    if network and tokens:
        jku_urls = collect_jku_urls(tokens)
        for u in jku_urls:
            jku_fetches += 1
            network_materials.extend(fetch_jwks_keys(u, timeout=network_timeout))
        network_materials = list(dict.fromkeys(network_materials))
        if verbose and jku_urls:
            print(f"[*] Network JWKS: {jku_fetches} jku/x5u URL(s), "
                  f"{len(network_materials)} RSA key(s) retrieved")
        if verbose and jku_urls and not network_materials:
            print("[*] Network JWKS: no usable RSA keys (SSRF guard, fetch error, or non-RSA)")

    if not tokens:
        if verbose:
            print("[*] No complete JWTs found in scan results")
        empty = {
            "schema_version": 1,
            "tokens_analyzed": 0,
            "findings": [],
            "severity_counts": {},
            "summary": jwt_summary([], {}, crack_meta),
            "candidate_secrets_tried": len(candidates),
            "crack_meta": crack_meta,
        }
        if hashcat_n:
            empty["hashcat_exported"] = hashcat_n
        if network:
            empty["jku_fetches"] = jku_fetches
            empty["network_key_materials"] = len(network_materials)
        if export_path:
            empty["findings_exported"] = export_jwt_findings(empty, export_path)
        return empty

    analyses = []
    for item in tokens:
        a = analyze_jwt(
            item["token"],
            source=item.get("source", "unknown"),
            candidate_secrets=candidates,
            key_materials=network_materials,
        )
        analyses.append(a)

    # Prefer longest/full tokens: drop LOW malformed duplicates when a sibling decoded cleanly
    analyses = [a for a in analyses if not (
        a["findings"] and a["findings"][0].get("issue") == "malformed_jwt"
        and any(x["findings"] and x["findings"][0].get("issue") != "malformed_jwt"
                for x in analyses)
    )]

    analyses.sort(key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a.get("alg", "")))

    severity_counts = {}
    for a in analyses:
        for f in a["findings"]:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if verbose:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        med = severity_counts.get("MEDIUM", 0)
        print(f"[+] JWT findings: {crit} critical, {high} high, {med} medium "
              f"({len(analyses)} token(s) analyzed)")
        if crack_meta.get("total"):
            print(f"[*] Crack candidates: {crack_meta['total']} "
                  f"(builtin={crack_meta['builtin']}, scan={crack_meta['scan_secrets']}, "
                  f"wordlist={crack_meta['wordlist']}, mutations={crack_meta['target_mutations']})")
        for a in analyses:
            if a["severity"] in ("CRITICAL", "HIGH"):
                top = a["findings"][0]
                print(f"    [!] {a['severity']:8s} {a['alg'] or '?':6s} {top['issue']}: {top['detail'][:90]}")

    out = {
        "schema_version": 1,
        "tokens_analyzed": len(analyses),
        "findings": analyses,
        "severity_counts": severity_counts,
        "summary": jwt_summary(analyses, severity_counts, crack_meta, exported=hashcat_n),
        "candidate_secrets_tried": len(candidates),
        "crack_meta": crack_meta,
    }
    if hashcat_n:
        out["hashcat_exported"] = hashcat_n
    if network:
        out["jku_fetches"] = jku_fetches
        out["network_key_materials"] = len(network_materials)
        out["summary"]["jku_fetches"] = jku_fetches
        out["summary"]["network_key_materials"] = len(network_materials)
    if export_path:
        out["findings_exported"] = export_jwt_findings(out, export_path)
        if verbose and out["findings_exported"]:
            print(f"[+] Wrote {out['findings_exported']} per-token finding(s) (NDJSON): {export_path}")
    return out


def jwt_risk_boost(jwt_result):
    """Risk points from JWT findings (by severity count across all findings)."""
    counts = (jwt_result or {}).get("severity_counts", {})
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    return sum(counts.get(sev, 0) * w for sev, w in weights.items())


# Re-export for convenience (used by pipeline merge paths)
__all__ = [
    "analyze_result_jwts",
    "collect_jwts_from_result",
    "export_jwt_findings",
    "jwt_summary",
    "jwt_risk_boost",
    "deduplicate_jwts",
    "extract_jwts",
    "decode_jwt",
]
