"""
HTTP utilities: rate limiting, retry, fetching.
"""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime
from typing import Optional

import requests


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
    if headers is None:
        headers = {"User-Agent": "SurfaceSweep/1.0"}

    for attempt in range(max_retries):
        if limiter:
            limiter.wait()
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
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
