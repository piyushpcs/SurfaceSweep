"""
Live secret verification — opt-in, read-only API probes (Phase F4).

Given extracted secrets, call a small set of vendor "whoami"/list endpoints
that are safe GETs. A 2xx confirms the credential works; 401/403 rejects it.
Never mutates remote state; never probes unlisted hosts.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from modules.common.console import detail, info, ok, warn
from modules.extraction.http import request_kwargs

__all__ = [
    "VERIFIERS",
    "extract_credential",
    "verify_secret",
    "verify_secrets",
]

# Cap how many secrets we hit remotely in one scan (opt-in flag already).
MAX_VERIFY = 25

# Secret types that are structural/placeholder/noisy — never worth a live call.
SKIP_TYPES = {
    "High-Entropy String",
    "Generic API Key",
    "Generic Secret",
    "Generic Password",
    "Exposed Env Var",
    "Access Token Env",
    "Process Env Fallback",
    "Client Secret Query",
    "Session Cookie",
    "CSRF Token",
    "JWT",
    "JWT Secret",
    "Private Key",
    "Database URL",
    "MongoDB SRV",
    "SMTP Credentials",
    "Encryption Key",
    "Authorization Header",
    "X-API-Key Header",
    "Bearer Token",
    "Webhook Secret",
    "Stripe Webhook Secret",
    "Stripe Publishable",
    "Discord Webhook",
    "Slack Webhook",
}

# Vendor types → (method-free builder, confirm_statuses, reject_statuses)
# Builders return (url, headers) for a GET probe using the credential.
# All probes are GET-only, read-only, against known public vendor APIs.


def _bearer(url: str, header: str = "Authorization", scheme: str = "Bearer"):
    def build(token: str):
        return url, {header: f"{scheme} {token}".strip()}
    return build


def _github(token: str):
    return "https://api.github.com/user", {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def _gitlab(token: str):
    return "https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": token}


def _slack(token: str):
    return "https://slack.com/api/auth.test", {"Authorization": f"Bearer {token}"}


def _sendgrid(token: str):
    return "https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {token}"}


def _anthropic(token: str):
    return (
        "https://api.anthropic.com/v1/models",
        {"x-api-key": token, "anthropic-version": "2023-06-01"},
    )


# type → (builder, confirmed if status in, rejected if status in, label)
VERIFIERS: Dict[str, tuple] = {
    "OpenAI API Key": (
        _bearer("https://api.openai.com/v1/models"),
        (200,), (401, 403), "OpenAI",
    ),
    "OpenAI Project Key": (
        _bearer("https://api.openai.com/v1/models"),
        (200,), (401, 403), "OpenAI",
    ),
    "Anthropic API Key": (
        _anthropic,
        (200,), (401, 403), "Anthropic",
    ),
    "GitHub Token": (
        _github, (200,), (401, 403), "GitHub",
    ),
    "GitHub PAT (classic)": (
        _github, (200,), (401, 403), "GitHub",
    ),
    "GitHub PAT (fine-grained)": (
        _github, (200,), (401, 403), "GitHub",
    ),
    "GitHub OAuth Token": (
        _github, (200,), (401, 403), "GitHub",
    ),
    "GitLab Token": (
        _gitlab, (200,), (401, 403), "GitLab",
    ),
    "Stripe Live Key": (
        _bearer("https://api.stripe.com/v1/balance"),
        (200,), (401, 403), "Stripe",
    ),
    "SendGrid API Key": (
        _sendgrid, (200,), (401, 403), "SendGrid",
    ),
    "Slack Token": (
        _slack, (200,), (401, 403), "Slack",
    ),
    "DigitalOcean Token": (
        _bearer("https://api.digitalocean.com/v2/account"),
        (200,), (401, 403), "DigitalOcean",
    ),
    "Hugging Face Token": (
        _bearer("https://huggingface.co/api/whoami-v2"),
        (200,), (401, 403), "Hugging Face",
    ),
    "Vercel Token": (
        _bearer("https://api.vercel.com/v2/user"),
        (200,), (401, 403), "Vercel",
    ),
    "Netlify Token": (
        _bearer("https://api.netlify.com/api/v1/me"),
        (200,), (401, 403), "Netlify",
    ),
    "npm Token": (
        _bearer("https://registry.npmjs.org/-/npm/v1/user"),
        (200,), (401, 403), "npm",
    ),
}

_BEARER_STRIP = re.compile(r"(?i)^\s*bearer\s+")


def extract_credential(match_text: str) -> str:
    """Pull the bare credential out of a match fragment (quotes/Bearer stripped)."""
    s = str(match_text or "").strip().strip("'\"")
    s = _BEARER_STRIP.sub("", s)
    return s


def verify_secret(
    secret: Dict[str, Any],
    *,
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
    session: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """
    Probe one secret against its vendor API. Returns a result dict, or None
    when the type has no verifier / is skipped.

    Result: {type, match, vendor, status, http_status, detail, url}
    status ∈ confirmed | rejected | error
    """
    typ = str(secret.get("type") or "")
    if typ in SKIP_TYPES or typ not in VERIFIERS:
        return None

    builder, confirmed_codes, rejected_codes, vendor = VERIFIERS[typ]
    token = extract_credential(secret.get("match") or "")
    if not token or len(token) < 8:
        return None

    try:
        url, extra_headers = builder(token)
    except Exception as exc:  # builder bug — treat as skip
        return {
            "type": typ, "match": token[:12] + "…", "vendor": vendor,
            "status": "error", "http_status": None,
            "detail": f"builder error: {exc}", "url": "",
        }

    req_headers = dict(headers or {})
    req_headers.update(extra_headers)
    # Preserve proxy/TLS/UA from process config without clobbering auth headers
    kwargs = request_kwargs(headers=req_headers)
    kwargs["timeout"] = timeout
    do_get = session.get if session is not None else None

    try:
        if do_get is None:
            from modules.extraction.http import request_tls
            resp = request_tls("GET", url, **kwargs)
        else:
            resp = do_get(url, **kwargs)
        code = int(getattr(resp, "status_code", 0) or 0)
    except Exception as exc:
        return {
            "type": typ, "match": token[:12] + "…", "vendor": vendor,
            "status": "error", "http_status": None,
            "detail": str(exc)[:160], "url": url,
        }

    if code in confirmed_codes:
        # Slack auth.test returns 200 with ok:false for bad tokens
        if vendor == "Slack":
            try:
                body = resp.json()
            except Exception:
                body = {}
            if isinstance(body, dict) and body.get("ok") is False:
                return {
                    "type": typ, "match": token[:12] + "…", "vendor": vendor,
                    "status": "rejected", "http_status": code,
                    "detail": str(body.get("error") or "auth.test ok=false")[:120],
                    "url": url,
                }
        status = "confirmed"
        detail_msg = "credential accepted"
    elif code in rejected_codes:
        status = "rejected"
        detail_msg = "credential rejected"
    else:
        status = "error"
        detail_msg = f"unexpected HTTP {code}"

    return {
        "type": typ,
        "match": token[:12] + "…" if len(token) > 12 else token,
        "vendor": vendor,
        "status": status,
        "http_status": code,
        "detail": detail_msg,
        "url": url,
    }


def verify_secrets(
    secrets: List[Dict[str, Any]],
    *,
    timeout: float = 5.0,
    verbose: bool = False,
    headers: Optional[Dict[str, str]] = None,
    session: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Verify up to MAX_VERIFY secrets. Returns the result["secret_verification"]
    block: results, findings (confirmed only), counts, summary.
    """
    results: List[Dict[str, Any]] = []
    skipped = 0
    checked = 0

    for s in secrets or []:
        if checked >= MAX_VERIFY:
            skipped += 1
            continue
        typ = str(s.get("type") or "")
        if typ in SKIP_TYPES or typ not in VERIFIERS:
            skipped += 1
            continue
        r = verify_secret(s, timeout=timeout, headers=headers, session=session)
        if r is None:
            skipped += 1
            continue
        results.append(r)
        checked += 1
        if verbose:
            if r["status"] == "confirmed":
                ok(f"  Confirmed {typ} against {r['vendor']}")
            elif r["status"] == "rejected":
                detail(f"  Rejected {typ} at {r['vendor']}")
            else:
                warn(f"  {typ} probe error: {r.get('detail', '')}")

    confirmed = [r for r in results if r["status"] == "confirmed"]
    rejected = [r for r in results if r["status"] == "rejected"]
    errors = [r for r in results if r["status"] == "error"]

    findings = [{
        "severity": "HIGH",
        "url": "",
        "detail": (
            f"Confirmed live {r['type']} via {r['vendor']} "
            f"(HTTP {r['http_status']})"
        ),
        "type": r["type"],
        "vendor": r["vendor"],
        "match": r["match"],
        "http_status": r["http_status"],
    } for r in confirmed]

    if verbose and not confirmed and checked:
        info(f"  {checked} credential(s) probed — none confirmed")

    return {
        "results": results,
        "findings": findings,
        "secrets_checked": checked,
        "confirmed": len(confirmed),
        "rejected": len(rejected),
        "errors": len(errors),
        "skipped": skipped,
        "summary": {
            "secrets_checked": checked,
            "confirmed": len(confirmed),
            "rejected": len(rejected),
            "errors": len(errors),
            "skipped": skipped,
        },
    }
