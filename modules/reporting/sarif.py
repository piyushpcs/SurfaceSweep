"""
SARIF 2.1.0 export for SurfaceSweep.

Maps scan findings (secrets, library CVEs, dangerous sinks, CORS, JWT)
into a SARIF log suitable for GitHub code scanning / SARIF consumers.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from modules.common.console import ok, warn
from modules.common.constants import secret_severity

__all__ = ["build_sarif", "export_sarif"]

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "SurfaceSweep"

# SARIF level: error | warning | note | none
_LEVEL_BY_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

_RULES: Dict[str, Dict[str, Any]] = {
    "secret-leak": {
        "id": "secret-leak",
        "name": "LeakedSecret",
        "shortDescription": {"text": "Secret or API key found in JavaScript"},
        "fullDescription": {
            "text": "A credential-looking string was extracted from client-side code."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "secret"], "precision": "high"},
    },
    "vulnerable-library": {
        "id": "vulnerable-library",
        "name": "VulnerableLibrary",
        "shortDescription": {"text": "JavaScript library with known CVE"},
        "fullDescription": {
            "text": "A bundled library version matches a known vulnerable range."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "dependency", "cve"]},
    },
    "dangerous-sink": {
        "id": "dangerous-sink",
        "name": "DangerousSink",
        "shortDescription": {"text": "Dangerous JavaScript sink"},
        "fullDescription": {
            "text": "Pattern that often leads to XSS, code injection, or open redirect."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "xss"]},
    },
    "cors-misconfig": {
        "id": "cors-misconfig",
        "name": "CORSMisconfiguration",
        "shortDescription": {"text": "CORS misconfiguration"},
        "fullDescription": {
            "text": "Access-Control-Allow-Origin policy allows unintended cross-origin access."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "cors"]},
    },
    "jwt-issue": {
        "id": "jwt-issue",
        "name": "JWTIssue",
        "shortDescription": {"text": "JWT algorithm / claim issue"},
        "fullDescription": {
            "text": "Weak HMAC, alg=none, expiry, or key-confusion signal on a JWT."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "jwt"]},
    },
}


def _level(severity: Optional[str]) -> str:
    return _LEVEL_BY_SEVERITY.get(str(severity or "").upper(), "warning")


def _result(
    rule_id: str,
    message: str,
    level: str,
    *,
    locations_uri: str = "",
    properties: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
    }
    if locations_uri:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": locations_uri},
                },
            }
        ]
    if properties:
        result["properties"] = properties
    return result


def _first_source(item: Dict[str, Any]) -> str:
    sources = item.get("sources")
    if isinstance(sources, list) and sources:
        return str(sources[0])
    if item.get("source"):
        return str(item["source"])
    if item.get("file"):
        return str(item["file"])
    return ""


def _collect_results(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    target = str(result.get("target") or "")

    for s in result.get("secrets_found") or []:
        if not isinstance(s, dict):
            continue
        typ = s.get("type") or "secret"
        sev = s.get("severity") or secret_severity(typ)
        findings.append(_result(
            "secret-leak",
            f"Potential secret ({typ})",
            _level(sev),
            locations_uri=_first_source(s) or target,
            properties={"severity": str(sev).upper(), "secret_type": typ},
        ))

    for v in result.get("library_vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cve = v.get("cve") or v.get("id") or "unknown"
        lib = v.get("library") or v.get("package") or "library"
        ver = v.get("version") or ""
        sev = v.get("severity") or "MEDIUM"
        title = v.get("title") or v.get("summary") or ""
        msg = f"{lib} {ver} — {cve}"
        if title:
            msg = f"{msg}: {title}"
        findings.append(_result(
            "vulnerable-library",
            msg,
            _level(sev),
            locations_uri=_first_source(v) or target,
            properties={"severity": str(sev).upper(), "cve": cve, "library": lib},
        ))

    for sink in result.get("sinks_found") or []:
        if not isinstance(sink, dict):
            continue
        name = sink.get("sink") or "sink"
        sev = sink.get("severity") or "MEDIUM"
        desc = sink.get("description") or name
        findings.append(_result(
            "dangerous-sink",
            f"{name}: {desc}",
            _level(sev),
            locations_uri=_first_source(sink) or target,
            properties={"severity": str(sev).upper(), "sink": name},
        ))

    cors = result.get("cors") or {}
    for f in cors.get("findings") or []:
        if not isinstance(f, dict):
            continue
        sev = f.get("severity") or "MEDIUM"
        if str(sev).upper() in ("", "INFO", "ERROR"):
            continue
        url = f.get("url") or target
        acao = f.get("acao") or ""
        detail = f.get("detail") or "CORS misconfiguration"
        findings.append(_result(
            "cors-misconfig",
            f"{detail} (ACAO={acao})",
            _level(sev),
            locations_uri=url,
            properties={"severity": str(sev).upper()},
        ))

    jwt_block = result.get("jwt") or {}
    for alg in jwt_block.get("findings") or []:
        if not isinstance(alg, dict):
            continue
        for f in alg.get("findings") or []:
            if not isinstance(f, dict):
                continue
            sev = f.get("severity") or "MEDIUM"
            if str(sev).upper() in ("", "INFO", "ERROR"):
                continue
            title = f.get("title") or f.get("issue") or f.get("type") or "JWT issue"
            findings.append(_result(
                "jwt-issue",
                str(title),
                _level(sev),
                locations_uri=target,
                properties={"severity": str(sev).upper()},
            ))

    return findings


def build_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from a SurfaceSweep scan result."""
    results = _collect_results(result or {})
    target = str((result or {}).get("target") or "")
    invocations = [{
        "executionSuccessful": True,
        "commandLine": f"SurfaceSweep {target}".strip(),
    }]
    meta = (result or {}).get("meta") or {}
    if meta.get("finished_at"):
        invocations[0]["endTimeUtc"] = str(meta["finished_at"])

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://github.com/piyushpcs/SurfaceSweep",
                        "rules": list(_RULES.values()),
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"uri": target or "https://localhost/"},
                },
                "invocations": invocations,
                "results": results,
            }
        ],
    }


def export_sarif(result: Dict[str, Any], filename: str) -> bool:
    """Write SARIF JSON to filename. Returns True on success."""
    try:
        parent = os.path.dirname(filename)
        if parent:
            os.makedirs(parent, exist_ok=True)
        log = build_sarif(result)
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(log, fh, indent=2, sort_keys=True)
            fh.write("\n")
        n = len(log["runs"][0]["results"])
        ok(f" SARIF exported: {filename} ({n} result(s))")
        return True
    except OSError as e:
        warn(f" Failed to export SARIF: {e}")
        return False
