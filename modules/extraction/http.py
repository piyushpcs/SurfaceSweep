"""
HTTP utilities: rate limiting, retry, fetching.
"""

import time
import requests


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


def get_page(base_url, timeout=10, limiter=None):
    """Fetch HTML page content."""
    resp = fetch_with_retry(base_url, timeout=timeout, limiter=limiter)
    if resp is None:
        raise requests.ConnectionError(f"Failed to fetch {base_url} after retries")
    return resp.text
