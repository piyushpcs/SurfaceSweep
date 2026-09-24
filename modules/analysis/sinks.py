"""
Dangerous sink detection — flags JS patterns that often lead to XSS,
open redirects, code injection, or other client-side vulnerabilities.
"""

import re

# sink name -> (compiled regex, severity, description)
SINK_PATTERNS = {
    "innerHTML": (
        re.compile(r'\.innerHTML\s*='),
        "MEDIUM",
        "Direct innerHTML assignment (XSS risk if value is user-controlled)",
    ),
    "outerHTML": (
        re.compile(r'\.outerHTML\s*='),
        "MEDIUM",
        "Direct outerHTML assignment (XSS risk)",
    ),
    "insertAdjacentHTML": (
        re.compile(r'\.insertAdjacentHTML\s*\('),
        "MEDIUM",
        "insertAdjacentHTML with HTML string (XSS risk)",
    ),
    "document.write": (
        re.compile(r'document\.write(?:ln)?\s*\('),
        "MEDIUM",
        "document.write / writeln (XSS risk, blocks parsing)",
    ),
    "eval": (
        re.compile(r'(?<![\w.$])eval\s*\('),
        "HIGH",
        "eval() executes arbitrary code from string",
    ),
    "new Function": (
        re.compile(r'new\s+Function\s*\('),
        "HIGH",
        "new Function() compiles and runs a string as code",
    ),
    "setTimeout string": (
        re.compile(r'set(?:Timeout|Interval)\s*\(\s*["\'`]'),
        "HIGH",
        "setTimeout/setInterval with string argument (implicit eval)",
    ),
    "dangerouslySetInnerHTML": (
        re.compile(r'dangerouslySetInnerHTML'),
        "HIGH",
        "React dangerouslySetInnerHTML (XSS if prop is user-controlled)",
    ),
    "v-html (Vue)": (
        re.compile(r'v-html\s*='),
        "MEDIUM",
        "Vue v-html directive renders raw HTML (XSS risk)",
    ),
    "jQuery .html()": (
        re.compile(r'\$\([^)]*\)\s*\.\s*html\s*\('),
        "MEDIUM",
        "jQuery .html() sets innerHTML from string",
    ),
    "jQuery append": (
        re.compile(r'\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\('),
        "LOW",
        "jQuery DOM insertion methods may parse HTML strings",
    ),
    "open redirect": (
        re.compile(r'(?:window\.location|location\.href|location\.assign|location\.replace)\s*(?:=|\()\s*["\'`]?[^"\'`\s)]*(?:URLSearchParams|location\.search|location\.hash|\+)', re.IGNORECASE),
        "MEDIUM",
        "Navigation to URL built from query/hash — open redirect risk",
    ),
    "postMessage": (
        re.compile(r'window\.postMessage\s*\('),
        "LOW",
        "postMessage — verify targetOrigin and message validation",
    ),
    "window.open": (
        re.compile(r'window\.open\s*\('),
        "LOW",
        "window.open — check for open-redirect / tabnabbing",
    ),
    "innerHTML concat": (
        re.compile(r'\.innerHTML\s*[+]='),
        "MEDIUM",
        "innerHTML concatenation (XSS risk)",
    ),
    "document.createElement + write": (
        re.compile(r'document\.createElement\([^)]*\)[\s\S]{0,120}\.write\s*\('),
        "MEDIUM",
        "createElement followed by write — DOM XSS pattern",
    ),
    "location.hash sink": (
        re.compile(r'(?:innerHTML|document\.write|insertAdjacentHTML)[\s\S]{0,80}location\.(?:hash|search)', re.IGNORECASE),
        "HIGH",
        "Sink reads from location.hash/search — reflected DOM XSS",
    ),
    # ---- Prototype pollution ----
    "__proto__ assignment": (
        re.compile(r'__proto__["\']?\s*\]?'),
        "HIGH",
        "Reference to __proto__ can pollute Object.prototype",
    ),
    "constructor.prototype": (
        re.compile(r'\.constructor\s*(?:\.\s*prototype|\[\s*[\'"]prototype[\'"]\s*\])|\bconstructor\s*(?:\.\s*prototype|\[\s*[\'"]prototype[\'"]\s*\])'),
        "HIGH",
        "constructor.prototype write enables prototype pollution",
    ),
    "Object.assign to untrusted": (
        re.compile(r'Object\.assign\s*\(\s*(?:\{\s*\}|this|window|globalThis|module\.exports)\s*,'),
        "MEDIUM",
        "Object.assign into shared object — pollution risk if source is user-controlled",
    ),
    "recursive merge": (
        re.compile(r'\b(?:merge|extend|deepExtend|defaultsDeep|deepMerge)\s*\([^;]{0,200}(?:for\s*\(|Object\.keys|Object\.entries)', re.IGNORECASE),
        "MEDIUM",
        "Recursive merge helper — classic prototype-pollution gadget when keys are untrusted",
    ),
    "JSON.parse + assign key": (
        re.compile(r'(?:for\s*\([^)]*(?:in\b|of\b)[^)]*\)[\s\S]{0,120}(?:target|obj|config|dest)\s*(?:\[|[.][A-Za-z_$])[^=]{0,40}=)', re.IGNORECASE),
        "MEDIUM",
        "Dynamic key assignment in loop — review for __proto__/constructor pollution",
    ),
}


def detect_sinks(content, source_label):
    """
    Detect dangerous JS sinks in content.
    Returns list of {sink, severity, description, source}.
    """
    findings = []
    for name, (pattern, severity, description) in SINK_PATTERNS.items():
        matches = pattern.findall(content)
        if matches:
            findings.append({
                "sink": name,
                "severity": severity,
                "description": description,
                "count": len(matches),
                "source": source_label,
            })
    return findings


def deduplicate_sinks(all_findings):
    """Merge duplicate sink findings across sources; keep sources list and total count."""
    dedup = {}
    for f in all_findings:
        key = (f["sink"], f.get("severity"))
        if key not in dedup:
            dedup[key] = dict(f, sources=[f["source"]], count=f.get("count", 1))
            dedup[key].pop("source", None)
        else:
            if f["source"] not in dedup[key]["sources"]:
                dedup[key]["sources"].append(f["source"])
            dedup[key]["count"] += f.get("count", 1)
    return list(dedup.values())
