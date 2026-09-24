"""
HTTP utilities: rate limiting, retry, fetching, and process-wide client config.
"""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime
from typing import Optional

import requests

DEFAULT_USER_AGENT = "SurfaceSweep/1.0"

# Process-wide defaults applied by fetch_with_retry / get_page when the
# caller does not override headers. Configured once from CLI flags.
_http_config: dict = {
    "proxy": None,
    "insecure": False,
    "user_agent": DEFAULT_USER_AGENT,
}

# Process-wide response-text cache keyed by URL. Avoids re-fetching the same
# JS file across stages (scan → browser → CVE → SPA). Bounded FIFO.
_TEXT_CACHE: dict = {}
_TEXT_CACHE_MAX = 512


def configure_http(
    proxy: Optional[str] = None,
    insecure: bool = False,
    user_agent: Optional[str] = None,
) -> None:
    """Set process-wide HTTP defaults (proxy, TLS verify, User-Agent)."""
    _http_config["proxy"] = proxy or None
    _http_config["insecure"] = bool(insecure)
    if user_agent:
        _http_config["user_agent"] = user_agent


def reset_http_config() -> None:
    """Restore defaults (tests)."""
    _http_config["proxy"] = None
    _http_config["insecure"] = False
    _http_config["user_agent"] = DEFAULT_USER_AGENT
    clear_text_cache()


def default_headers() -> dict:
    return {"User-Agent": _http_config["user_agent"]}


def request_kwargs(headers: Optional[dict] = None) -> dict:
    """Build kwargs for requests.get/post from the process-wide config."""
    kwargs: dict = {"headers": headers if headers is not None else default_headers()}
    if _http_config["proxy"]:
        kwargs["proxies"] = {
            "http": _http_config["proxy"],
            "https": _http_config["proxy"],
        }
    if _http_config["insecure"]:
        kwargs["verify"] = False
    return kwargs


def clear_text_cache() -> None:
    """Drop all cached response bodies (tests / new scan)."""
    _TEXT_CACHE.clear()


def get_cached_text(url: str) -> Optional[str]:
    return _TEXT_CACHE.get(url)


def cache_text(url: str, text: str) -> None:
    """Store a response body for later stages (FIFO eviction)."""
    if not url:
        return
    if url in _TEXT_CACHE:
        _TEXT_CACHE[url] = text
        return
    if len(_TEXT_CACHE) >= _TEXT_CACHE_MAX:
        oldest = next(iter(_TEXT_CACHE))
        del _TEXT_CACHE[oldest]
    _TEXT_CACHE[url] = text


def fetch_text(url, timeout=10, limiter=None, headers=None) -> Optional[str]:
    """
    GET a URL and return its text body, using the process-wide cache.

    Returns None on cache miss + fetch failure (connection errors, timeout
    exhaustion, 429 budget) — never raises. Matches the contract callers
    of the old per-stage try/except loops relied on.
    """
    cached = get_cached_text(url)
    if cached is not None:
        return cached
    try:
        resp = fetch_with_retry(url, timeout=timeout, limiter=limiter, headers=headers)
    except requests.RequestException:
        return None
    if resp is None:
        return None
    text = resp.text
    cache_text(url, text)
    return text


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


def fetch_with_retry(url, timeout=10, max_retries=3, limiter=None, headers=None):
    """
    Fetch a URL with exponential backoff on 429/5xx and transient network errors.

    Returns the final Response on success (including 4xx that raise_for_status
    accepts or re-raises as HTTPError). Raises the last ConnectionError/Timeout
    after retries are exhausted. Returns None only if the 429/5xx retry budget
    is fully consumed without a non-retryable response.
    """
    req_headers = headers if headers is not None else default_headers()

    for attempt in range(max_retries):
        if limiter:
            limiter.wait()
        try:
            kwargs = request_kwargs(headers=req_headers)
            resp = requests.get(url, timeout=timeout, **kwargs)
            if resp.status_code == 429:
                if attempt >= max_retries - 1:
                    return None
                time.sleep(parse_retry_after(resp.headers.get("Retry-After")))
                continue
            if resp.status_code >= 500 and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            resp.raise_for_status()
            try:
                cache_text(url, resp.text)
            except Exception:
                pass
            return resp
        except requests.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise
        except requests.ConnectionError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise
    return None


def get_page(base_url, timeout=10, limiter=None, headers=None):
    """Fetch HTML page content. Raises ConnectionError if retries are exhausted."""
    resp = fetch_with_retry(base_url, timeout=timeout, limiter=limiter, headers=headers)
    if resp is None:
        raise requests.ConnectionError(f"Failed to fetch {base_url} after retries")
    return resp.text
