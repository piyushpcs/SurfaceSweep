"""Unit tests for HTTP retry / Retry-After parsing (Phase A Step 2)."""

import time
import unittest
from unittest import mock

import requests

from modules.extraction.http import (
    RateLimiter,
    clear_text_cache,
    fetch_text,
    fetch_with_retry,
    get_page,
    get_cached_text,
    parse_retry_after,
)


class TestParseRetryAfter(unittest.TestCase):
    def test_none_returns_default(self):
        self.assertEqual(parse_retry_after(None, default=2.0), 2.0)

    def test_empty_returns_default(self):
        self.assertEqual(parse_retry_after("", default=3.0), 3.0)
        self.assertEqual(parse_retry_after("   ", default=3.0), 3.0)

    def test_integer_seconds(self):
        self.assertEqual(parse_retry_after("5"), 5.0)
        self.assertEqual(parse_retry_after("0"), 0.0)
        self.assertEqual(parse_retry_after("12.5"), 12.5)

    def test_http_date_past_clamped_to_zero(self):
        self.assertEqual(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), 0.0)

    def test_http_date_future_approx(self):
        # ~2 hours in the future — capped at default cap 60
        from email.utils import formatdate
        future = formatdate(time.time() + 7200, usegmt=True)
        self.assertEqual(parse_retry_after(future, cap=60.0), 60.0)

    def test_garbage_returns_default(self):
        self.assertEqual(parse_retry_after("not-a-date", default=4.0), 4.0)
        self.assertEqual(parse_retry_after("NaN", default=4.0), 4.0)

    def test_negative_clamped(self):
        self.assertEqual(parse_retry_after("-10"), 0.0)

    def test_cap_applied(self):
        self.assertEqual(parse_retry_after("9999", cap=30.0), 30.0)


def _resp(status_code=200, headers=None, text="ok"):
    r = mock.Mock(spec=requests.Response)
    r.status_code = status_code
    r.headers = headers or {}
    r.text = text

    def _raise():
        if status_code >= 400:
            raise requests.HTTPError(f"{status_code}")

    r.raise_for_status = mock.Mock(side_effect=_raise)
    return r


class TestFetchWithRetry(unittest.TestCase):
    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_success_first_try(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(200)
        resp = fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)
        sleep_mock.assert_not_called()

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_retry_after_http_date_does_not_raise(self, get_mock, sleep_mock):
        """Non-integer Retry-After (HTTP-date) must not crash the scan."""
        from email.utils import formatdate
        past = formatdate(time.time() - 100, usegmt=True)
        get_mock.side_effect = [
            _resp(429, headers={"Retry-After": past}),
            _resp(200),
        ]
        resp = fetch_with_retry("https://x.test/a.js", max_retries=3)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(get_mock.call_count, 2)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_retry_after_garbage_falls_back(self, get_mock, sleep_mock):
        get_mock.side_effect = [
            _resp(429, headers={"Retry-After": "soon"}),
            _resp(200),
        ]
        resp = fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_timeout_is_retryable(self, get_mock, sleep_mock):
        get_mock.side_effect = [
            requests.Timeout("t"),
            _resp(200),
        ]
        resp = fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(get_mock.call_count, 2)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_timeout_exhausted_raises(self, get_mock, sleep_mock):
        get_mock.side_effect = requests.Timeout("t")
        with self.assertRaises(requests.Timeout):
            fetch_with_retry("https://x.test/a.js", max_retries=2)
        self.assertEqual(get_mock.call_count, 2)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_connection_error_exhausted_raises(self, get_mock, sleep_mock):
        get_mock.side_effect = requests.ConnectionError("refused")
        with self.assertRaises(requests.ConnectionError):
            fetch_with_retry("https://x.test/a.js", max_retries=2)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_5xx_retries_then_success(self, get_mock, sleep_mock):
        get_mock.side_effect = [_resp(503), _resp(200)]
        resp = fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_429_budget_exhausted_returns_none(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(429, headers={"Retry-After": "1"})
        self.assertIsNone(fetch_with_retry("https://x.test/a.js", max_retries=2))

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_404_raises_http_error(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(404)
        with self.assertRaises(requests.HTTPError):
            fetch_with_retry("https://x.test/a.js")


class TestGetPage(unittest.TestCase):
    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_returns_text(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(200, text="<html></html>")
        self.assertEqual(get_page("https://x.test/"), "<html></html>")

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_none_after_retries_raises_connection_error(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(429)
        with self.assertRaises(requests.ConnectionError):
            get_page("https://x.test/")

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_connection_error_propagates(self, get_mock, sleep_mock):
        get_mock.side_effect = requests.ConnectionError("down")
        with self.assertRaises(requests.ConnectionError):
            get_page("https://x.test/")


class TestFutureResultGuards(unittest.TestCase):
    """Stage workers must not crash the whole scan on one bad future."""

    def test_engine_future_guard_present(self):
        import inspect
        from modules.extraction import engine
        src = inspect.getsource(engine)
        self.assertIn("except Exception as e:", src)
        self.assertIn('result["errors"].append', src)

    def test_validator_future_guard_present(self):
        import inspect
        from modules.analysis import validator
        src = inspect.getsource(validator)
        self.assertIn("except Exception as e:", src)

    def test_wayback_future_guard_present(self):
        import inspect
        from modules.discovery import wayback
        src = inspect.getsource(wayback)
        self.assertIn("except Exception as e:", src)

    def test_cors_future_guard_present(self):
        import inspect
        from modules.cors import scanner
        src = inspect.getsource(scanner)
        self.assertIn("except Exception:", src)

    def test_spa_future_guard_present(self):
        import inspect
        from modules.discovery import spa
        src = inspect.getsource(spa)
        self.assertIn("except Exception:", src)


class TestRateLimiterStillWorks(unittest.TestCase):
    def test_min_interval_enforced(self):
        limiter = RateLimiter(requests_per_second=50)  # 0.02s interval
        t0 = time.monotonic()
        for _ in range(4):
            limiter.wait()
        elapsed = time.monotonic() - t0
        self.assertGreaterEqual(elapsed, 0.05)


if __name__ == "__main__":
    unittest.main()
