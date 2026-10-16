"""
HTTP utilities: rate limiting, retry, fetching, and process-wide client config.

A single process-wide :class:`HttpClient` holds config, the response-text
cache, and fetch/retry logic. Module-level functions delegate to the default
instance so existing call sites and tests stay unchanged.
"""

from __future__ import annotations

import threading
import time
from email.utils import parsedate_to_datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from modules.common.constants import DEFAULT_USER_AGENT
from modules.common.netguard import (
    BlockedTarget,
    is_blocked_fetch_target,
    pin_dns,
    resolve_fetch_ips,
)
from modules.extraction.scope import is_same_scope

__all__ = [
    "DEFAULT_USER_AGENT",
    "HttpClient",
    "RateLimiter",
    "RelaxedTLSAdapter",
    "cache_text",
    "clear_text_cache",
    "configure_auth",
    "configure_http",
    "default_headers",
    "fetch_text",
    "fetch_with_retry",
    "follow_redirects",
    "get_cached_text",
    "get_page",
    "is_blocked_fetch_target",
    "is_cert_error",
    "is_tls_policy_error",
    "parse_retry_after",
    "request_kwargs",
    "request_tls",
    "reset_http_config",
    "relaxed_session",
    "session_request",
]

_TEXT_CACHE_MAX = 512

# HTTP status codes that carry a Location to follow.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# Bound on redirect chains (matches the JWKS fetcher's spirit).
_MAX_REDIRECTS = 5


def _assert_fetch_allowed(url: str):
    """
    Validate a single fetch target; returns ``(host, validated_ips)``.

    Raises ``requests.ConnectionError`` for a malformed URL, a non-HTTP(S)
    scheme, a metadata/link-local hostname, or a host whose DNS resolves to a
    blocked address. ``validated_ips`` may be ``None`` when the host does not
    resolve (the request then fails on its own; a missing record is not an
    SSRF signal).
    """
    if is_blocked_fetch_target(url):
        raise requests.ConnectionError(
            f"Refused to fetch blocked link-local/metadata target: {url}"
        )
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise requests.ConnectionError(f"Refused to fetch malformed URL: {url}") from exc
    if parsed.scheme not in ("http", "https"):
        raise requests.ConnectionError(f"Refused to fetch non-HTTP(S) URL: {url}")
    host = parsed.hostname
    if not host:
        raise requests.ConnectionError(f"Refused to fetch URL without a host: {url}")
    try:
        ips = resolve_fetch_ips(host)
    except BlockedTarget as exc:
        raise requests.ConnectionError(str(exc)) from exc
    return host, ips


def follow_redirects(send, method, url, allow_redirects=True, max_redirects=_MAX_REDIRECTS):
    """
    Issue ``send(method, url)`` and follow redirects safely.

    Every hop — the initial URL *and* each ``Location`` — is validated (name
    check, DNS resolution, IP check) and DNS-pinned, so a target cannot steer
    the scanner at the metadata service via a 302. ``send`` must be side-effect
    free beyond the single request and must not follow redirects itself
    (callers pass ``allow_redirects=False``).

    Returns the final ``requests.Response``; raises
    ``requests.ConnectionError`` when the initial URL or any hop is blocked.
    """
    current = url
    resp = None
    for _ in range(max_redirects + 1):
        host, ips = _assert_fetch_allowed(current)
        with pin_dns(host, ips):
            resp = send(method, current)

        code = getattr(resp, "status_code", None)
        if not allow_redirects or code not in _REDIRECT_CODES:
            return resp
        headers = getattr(resp, "headers", None) or {}
        location = headers.get("Location")
        if not location:
            return resp
        try:
            nxt = urljoin(current, location)
        except ValueError:
            return resp
        if urlparse(nxt).scheme not in ("http", "https"):
            return resp
        if code == 303 and method.upper() not in ("GET", "HEAD"):
            method = "GET"
        current = nxt
    return resp


def session_request(session, method, url, allow_redirects=True, **kwargs):
    """
    ``session.request`` with per-hop SSRF validation.

    Follows redirects one hop at a time, re-validating and DNS-pinning each
    target. TLS-policy fallback stays with the caller (CORS probes opt in via
    their own wrapper) so this stays a thin transport shim.
    """
    def send(m, u):
        return session.request(m, u, allow_redirects=False, **kwargs)

    return follow_redirects(send, method, url, allow_redirects=allow_redirects)


def is_tls_policy_error(exc: BaseException) -> bool:
    """
    True when a ConnectionError looks like a server rejecting our TLS
    cipher policy (common on legacy gov/enterprise hosts that only offer
    static-RSA / SECLEVEL≤1 suites while Python defaults to SECLEVEL=2).
    """
    if not isinstance(exc, requests.RequestException):
        return False
    text = str(exc).lower()
    return "connection reset" in text or "connection aborted" in text


def is_cert_error(exc: BaseException) -> bool:
    """
    True when a failure is a certificate verification problem (expired,
    self-signed, hostname mismatch). These are non-transient — retrying
    only wastes the full retry budget.
    """
    if not isinstance(exc, requests.RequestException):
        return False
    text = str(exc).lower()
    return (
        "certificate verify failed" in text
        or "certificate has expired" in text
        or "self-signed certificate" in text
        or "sslerror" in text and "certificate" in text
    )


class RelaxedTLSAdapter(HTTPAdapter):
    """HTTPS adapter with OpenSSL security level 0 (legacy cipher suites)."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # urllib3 applies CERT_NONE to the shared external ssl_context, which
        # raises ValueError while check_hostname is True. Disabling it here
        # lets verify=False work; when verification is still on urllib3 does
        # its own hostname matching instead.
        if not verify:
            ctx = None
            for holder in (getattr(conn, "conn_kw", None),
                           getattr(conn, "connection_pool_kw", None)):
                if isinstance(holder, dict) and holder.get("ssl_context") is not None:
                    ctx = holder["ssl_context"]
                    break
            if ctx is None:
                ctx = getattr(conn, "ssl_context", None)
            if ctx is not None and getattr(ctx, "check_hostname", False):
                ctx.check_hostname = False
        super().cert_verify(conn, url, verify, cert)


_relaxed_local = threading.local()


def relaxed_session() -> requests.Session:
    """Thread-local Session mounted with RelaxedTLSAdapter (connection reuse)."""
    sess = getattr(_relaxed_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.mount("https://", RelaxedTLSAdapter())
        _relaxed_local.session = sess
    return sess


def request_tls(method: str, url: str, **kwargs):
    """
    HTTP request with automatic TLS-policy fallback and SSRF-safe redirects.

    Applies process-wide proxy/insecure config when the caller did not
    override them, then tries the default stack first; on a connection
    reset/abort that looks like cipher-policy rejection, retries once via
    relaxed_session(). Redirects are followed one hop at a time with each
    target re-validated and DNS-pinned (see :func:`follow_redirects`).
    """
    allow_redirects = kwargs.pop("allow_redirects", True)
    if "verify" not in kwargs and _client.insecure:
        kwargs["verify"] = False
    if "proxies" not in kwargs and _client.proxy:
        kwargs["proxies"] = {"http": _client.proxy, "https": _client.proxy}

    def send(m, u):
        try:
            return requests.request(m, u, allow_redirects=False, **kwargs)
        except requests.ConnectionError as exc:
            if not is_tls_policy_error(exc):
                raise
            return relaxed_session().request(m, u, allow_redirects=False, **kwargs)

    return follow_redirects(send, method, url, allow_redirects=allow_redirects)


def parse_retry_after(value: Optional[str], default: float = 2.0, cap: float = 60.0) -> float:
    """
    Parse a Retry-After header value (delta-seconds or HTTP-date) into seconds.

    Never raises. Result is clamped to [0, cap].
    """
    if value is None:
        return float(default)
    raw = str(value).strip()
    if not raw:
        return float(default)
    try:
        seconds = float(raw)
    except ValueError:
        seconds = None
    if seconds is None:
        try:
            when = parsedate_to_datetime(raw)
            if when is not None:
                now = time.time()
                target = when.timestamp()
                seconds = target - now
        except (TypeError, ValueError, IndexError):
            seconds = float(default)
    if seconds is None or seconds != seconds:  # None or NaN
        seconds = float(default)
    if seconds < 0:
        seconds = 0.0
    if seconds > cap:
        seconds = float(cap)
    return float(seconds)


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, requests_per_second: float = 5):
        self.min_interval = 1.0 / requests_per_second
        self._last = 0.0
        self._lock = __import__("threading").Lock()

    def wait(self) -> None:
        # Reserve the next slot under the lock, then sleep outside so
        # concurrent callers are not serialized for the full sleep duration.
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay < 0:
                delay = 0.0
            self._last = now + delay
        if delay > 0:
            time.sleep(delay)


class HttpClient:
    """
    Configurable HTTP client with retry, rate-limit hooks, and a bounded
    response-text cache shared across pipeline stages.
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        insecure: bool = False,
        user_agent: Optional[str] = None,
        cache_max: int = _TEXT_CACHE_MAX,
    ) -> None:
        self.proxy = proxy or None
        self.insecure = bool(insecure)
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.cache_max = cache_max
        self._cache: dict = {}
        self._cache_lock = threading.Lock()
        # Credentials (Cookie / Authorization / -H) + the only scope they may
        # be sent to. Kept separate so they never leak to third-party hosts.
        self.auth_headers: dict = {}
        self.auth_scope: Optional[str] = None

    def configure(
        self,
        proxy: Optional[str] = None,
        insecure: bool = False,
        user_agent: Optional[str] = None,
    ) -> None:
        """Set process-wide HTTP defaults (proxy, TLS verify, User-Agent)."""
        self.proxy = proxy or None
        self.insecure = bool(insecure)
        if user_agent:
            self.user_agent = user_agent

    def reset(self) -> None:
        """Restore defaults and drop the response cache (tests)."""
        self.proxy = None
        self.insecure = False
        self.user_agent = DEFAULT_USER_AGENT
        self.auth_headers = {}
        self.auth_scope = None
        self.clear_cache()

    def set_auth(self, headers: Optional[dict] = None,
                 scope: Optional[str] = None) -> None:
        """
        Store credentials that are only sent to hosts inside `scope`.

        Keeps a target's cookies/Authorization from being sent to unrelated
        hosts the scan happens to touch (CDNs, vendor APIs, source-map hosts).
        """
        self.auth_headers = dict(headers or {})
        self.auth_scope = scope or None

    def _scope_ok(self, url: str) -> bool:
        if not self.auth_scope:
            return True
        try:
            return is_same_scope(url, self.auth_scope)
        except Exception:
            return False

    def _merge_headers(self, url: str, headers: Optional[dict]) -> dict:
        """Caller headers win; in-scope auth defaults fill the gaps."""
        base = dict(headers) if headers is not None else {"User-Agent": self.user_agent}
        if self.auth_headers and self._scope_ok(url):
            for key, value in self.auth_headers.items():
                base.setdefault(key, value)
        return base

    def default_headers(self) -> dict:
        return {"User-Agent": self.user_agent}

    def request_kwargs(self, headers: Optional[dict] = None) -> dict:
        """Build kwargs for requests.get/post from the client config."""
        kwargs: dict = {"headers": headers if headers is not None else self.default_headers()}
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        if self.insecure:
            kwargs["verify"] = False
        return kwargs

    def clear_cache(self) -> None:
        """Drop all cached response bodies (tests / new scan)."""
        with self._cache_lock:
            self._cache.clear()

    def get_cached_text(self, url: str) -> Optional[str]:
        with self._cache_lock:
            return self._cache.get(url)

    def cache_text(self, url: str, text: str) -> None:
        """Store a response body for later stages (FIFO eviction)."""
        if not url:
            return
        with self._cache_lock:
            if url in self._cache:
                self._cache[url] = text
                return
            if len(self._cache) >= self.cache_max:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[url] = text

    def fetch_text(self, url, timeout=10, limiter=None, headers=None) -> Optional[str]:
        """
        GET a URL and return its text body, using the client cache.

        Returns None on cache miss + fetch failure — never raises.
        """
        cached = self.get_cached_text(url)
        if cached is not None:
            return cached
        try:
            resp = self.fetch_with_retry(url, timeout=timeout, limiter=limiter, headers=headers)
        except requests.RequestException:
            return None
        if resp is None:
            return None
        text = resp.text
        self.cache_text(url, text)
        return text

    def fetch_with_retry(self, url, timeout=10, max_retries=3, limiter=None, headers=None):
        """
        Fetch a URL with exponential backoff on 429/5xx and transient network errors.

        Redirects are followed one hop at a time; each target is re-validated
        and DNS-pinned, and credentials are re-scoped per hop so a redirect to
        a third-party host never receives the target's auth headers. Returns
        the final Response on success. Raises the last ConnectionError/Timeout
        after retries are exhausted. Returns None only if the 429/5xx retry
        budget is fully consumed without a non-retryable response.
        """
        def send(method, hop_url):
            return self._fetch_once(
                hop_url,
                timeout=timeout,
                max_retries=max_retries,
                limiter=limiter,
                raw_headers=headers,
            )

        resp = follow_redirects(send, "GET", url, allow_redirects=True)
        if resp is None:
            return None
        try:
            self.cache_text(url, resp.text)
        except Exception:
            pass
        return resp

    def _fetch_once(self, url, timeout=10, max_retries=3, limiter=None,
                    raw_headers=None):
        """
        Fetch one URL (no redirect following) with the retry/backoff budget.

        ``raw_headers`` are the caller's headers before scope merging; they are
        merged per URL so in-scope auth is attached only to in-scope hops.
        """
        req_headers = self._merge_headers(url, raw_headers)

        used_relaxed = False
        for attempt in range(max_retries):
            if limiter:
                limiter.wait()
            try:
                kwargs = self.request_kwargs(headers=req_headers)
                if used_relaxed:
                    resp = relaxed_session().get(
                        url, timeout=timeout, allow_redirects=False, **kwargs
                    )
                else:
                    resp = requests.get(
                        url, timeout=timeout, allow_redirects=False, **kwargs
                    )
                if resp.status_code == 429:
                    if attempt >= max_retries - 1:
                        return None
                    time.sleep(parse_retry_after(resp.headers.get("Retry-After")))
                    continue
                if resp.status_code >= 500 and attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                resp.raise_for_status()
                return resp
            except requests.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
            except requests.ConnectionError as exc:
                if is_tls_policy_error(exc) and not used_relaxed:
                    used_relaxed = True
                    continue
                if is_cert_error(exc):
                    raise
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
        return None

    def get_page(self, base_url, timeout=10, limiter=None, headers=None):
        """Fetch HTML page content. Raises ConnectionError if retries are exhausted."""
        resp = self.fetch_with_retry(base_url, timeout=timeout, limiter=limiter, headers=headers)
        if resp is None:
            raise requests.ConnectionError(f"Failed to fetch {base_url} after retries")
        return resp.text


# Process-wide default client (configured once from CLI flags).
_client = HttpClient()


def configure_http(
    proxy: Optional[str] = None,
    insecure: bool = False,
    user_agent: Optional[str] = None,
) -> None:
    """Set process-wide HTTP defaults (proxy, TLS verify, User-Agent)."""
    _client.configure(proxy=proxy, insecure=insecure, user_agent=user_agent)


def configure_auth(headers: Optional[dict] = None,
                   scope: Optional[str] = None) -> None:
    """
    Register credentials (Cookie / Authorization / -H) for a scan.

    They are attached only to requests whose host is within `scope`, so a
    target's session is never leaked to third-party hosts.
    """
    _client.set_auth(headers, scope)


def reset_http_config() -> None:
    """Restore defaults (tests)."""
    _client.reset()


def default_headers() -> dict:
    return _client.default_headers()


def request_kwargs(headers: Optional[dict] = None) -> dict:
    return _client.request_kwargs(headers=headers)


def clear_text_cache() -> None:
    _client.clear_cache()


def get_cached_text(url: str) -> Optional[str]:
    return _client.get_cached_text(url)


def cache_text(url: str, text: str) -> None:
    _client.cache_text(url, text)


def fetch_text(url, timeout=10, limiter=None, headers=None) -> Optional[str]:
    return _client.fetch_text(url, timeout=timeout, limiter=limiter, headers=headers)


def fetch_with_retry(url, timeout=10, max_retries=3, limiter=None, headers=None):
    return _client.fetch_with_retry(
        url, timeout=timeout, max_retries=max_retries, limiter=limiter, headers=headers
    )


def get_page(base_url, timeout=10, limiter=None, headers=None):
    return _client.get_page(base_url, timeout=timeout, limiter=limiter, headers=headers)
