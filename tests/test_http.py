"""Unit tests for HTTP retry / Retry-After parsing (Phase A Step 2)."""

import time
import unittest
from unittest import mock

import requests

from modules.extraction.http import (
    HttpClient,
    RateLimiter,
    RelaxedTLSAdapter,
    clear_text_cache,
    configure_http,
    fetch_text,
    fetch_with_retry,
    get_page,
    get_cached_text,
    is_cert_error,
    is_tls_policy_error,
    note_request,
    parse_retry_after,
    request_count,
    request_tls,
    relaxed_session,
    reset_http_config,
    reset_request_count,
)


class TestRequestFootprint(unittest.TestCase):
    """Process-wide HTTP request counter (scan footprint)."""

    def setUp(self):
        reset_request_count()

    def tearDown(self):
        reset_request_count()

    def test_starts_at_zero(self):
        self.assertEqual(request_count(), 0)

    def test_notes_and_counts(self):
        note_request()
        note_request(3)
        self.assertEqual(request_count(), 4)

    def test_reset(self):
        note_request(5)
        reset_request_count()
        self.assertEqual(request_count(), 0)

    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_counts_a_send(self, req_mock):
        reset_request_count()
        resp = mock.Mock(status_code=200, headers={})
        req_mock.return_value = resp
        request_tls("GET", "https://example.com/", allow_redirects=False)
        self.assertEqual(request_count(), 1)



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


class TestTlsPolicyFallback(unittest.TestCase):
    def tearDown(self):
        reset_http_config()

    def test_is_tls_policy_error_reset(self):
        exc = requests.ConnectionError(
            "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
        )
        self.assertTrue(is_tls_policy_error(exc))

    def test_is_tls_policy_error_refused_not_tls(self):
        self.assertFalse(is_tls_policy_error(requests.ConnectionError("refused")))

    def test_is_tls_policy_error_non_request_exception(self):
        self.assertFalse(is_tls_policy_error(ValueError("connection reset")))

    def test_is_cert_error_expired(self):
        exc = requests.ConnectionError(
            "HTTPSConnectionPool(host='x.test', port=443): Max retries exceeded "
            "(Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate has expired (_ssl.c:1082)')))"
        )
        self.assertTrue(is_cert_error(exc))

    def test_is_cert_error_self_signed(self):
        exc = requests.exceptions.SSLError(
            "certificate verify failed: self-signed certificate (_ssl.c:1082)"
        )
        self.assertTrue(is_cert_error(exc))

    def test_is_cert_error_reset_not_cert(self):
        exc = requests.ConnectionError(
            "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
        )
        self.assertFalse(is_cert_error(exc))

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_cert_error_not_retried(self, get_mock, sleep_mock):
        exc = requests.exceptions.SSLError(
            "certificate verify failed: certificate has expired (_ssl.c:1082)"
        )
        get_mock.side_effect = exc
        with self.assertRaises(requests.exceptions.SSLError):
            fetch_with_retry("https://expired.test/", max_retries=3)
        self.assertEqual(get_mock.call_count, 1)
        sleep_mock.assert_not_called()

    @mock.patch("modules.extraction.http.relaxed_session")
    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_falls_back_on_reset(self, request_mock, relaxed_mock):
        reset = requests.ConnectionError(
            "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
        )
        ok = _resp(200)
        request_mock.side_effect = [reset, ok]
        relaxed_mock.return_value.request.return_value = ok

        resp = request_tls("GET", "https://legacy.test/")
        self.assertEqual(resp.status_code, 200)
        relaxed_mock.return_value.request.assert_called_once()

    @mock.patch("modules.extraction.http.relaxed_session")
    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_reraise_non_tls_error(self, request_mock, relaxed_mock):
        request_mock.side_effect = requests.ConnectionError("refused")
        with self.assertRaises(requests.ConnectionError):
            request_tls("GET", "https://x.test/")
        relaxed_mock.assert_not_called()

    @mock.patch("modules.extraction.http.relaxed_session")
    @mock.patch("modules.extraction.http.requests.get")
    def test_fetch_retries_via_relaxed_session_on_tls_reset(self, get_mock, relaxed_mock):
        reset = requests.ConnectionError(
            "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
        )
        get_mock.side_effect = reset
        relaxed_mock.return_value.get.return_value = _resp(200)

        resp = fetch_with_retry("https://legacy.test/a.js")
        self.assertEqual(resp.status_code, 200)
        relaxed_mock.return_value.get.assert_called_once()

    def test_relaxed_session_mounts_adapter(self):
        sess = relaxed_session()
        self.assertIsInstance(sess, requests.Session)
        adapter = sess.get_adapter("https://example.com/")
        self.assertIsInstance(adapter, RelaxedTLSAdapter)

    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_applies_insecure_config(self, request_mock):
        request_mock.return_value = _resp(200)
        reset_http_config()
        request_tls("GET", "https://self-signed.test/")
        self.assertNotIn("verify", request_mock.call_args.kwargs)
        configure_http(insecure=True)
        request_tls("GET", "https://self-signed.test/")
        self.assertIs(request_mock.call_args.kwargs.get("verify"), False)

    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_respects_caller_verify_override(self, request_mock):
        request_mock.return_value = _resp(200)
        configure_http(insecure=True)
        request_tls("GET", "https://x.test/", verify=True)
        self.assertIs(request_mock.call_args.kwargs.get("verify"), True)

    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_applies_proxy_config(self, request_mock):
        request_mock.return_value = _resp(200)
        reset_http_config()
        configure_http(proxy="http://127.0.0.1:8080")
        request_tls("GET", "https://x.test/")
        proxies = request_mock.call_args.kwargs.get("proxies")
        self.assertEqual(proxies.get("https"), "http://127.0.0.1:8080")


class TestRelaxedAdapterCertVerify(unittest.TestCase):
    """verify=False must work on RelaxedTLSAdapter's external ssl_context."""

    @staticmethod
    def _pool(ctx):
        conn = mock.MagicMock()
        conn.conn_kw = {"ssl_context": ctx}
        del conn.ssl_context  # only conn_kw carries it for pool connections
        return conn

    def test_insecure_disables_check_hostname(self):
        from urllib3.util.ssl_ import create_urllib3_context

        ctx = create_urllib3_context()
        self.assertTrue(ctx.check_hostname)
        adapter = RelaxedTLSAdapter()
        conn = self._pool(ctx)
        adapter.cert_verify(conn, "https://x.test/", False, None)
        self.assertFalse(ctx.check_hostname)
        # urllib3 applies CERT_NONE to the context during connect(); the
        # critical contract is that check_hostname no longer blocks it.
        self.assertEqual(conn.cert_reqs, "CERT_NONE")

    def test_secure_leaves_check_hostname_enabled(self):
        from urllib3.util.ssl_ import create_urllib3_context

        ctx = create_urllib3_context()
        adapter = RelaxedTLSAdapter()
        adapter.cert_verify(self._pool(ctx), "https://x.test/", True, None)
        self.assertTrue(ctx.check_hostname)
        self.assertNotEqual(ctx.verify_mode, __import__("ssl").CERT_NONE)

    def test_insecure_session_request_does_not_raise(self):
        # Before the fix: ValueError "Cannot set verify_mode to CERT_NONE
        # when check_hostname is enabled" on every request.
        adapter = RelaxedTLSAdapter()
        ctx = __import__("ssl").create_default_context()
        conn = mock.MagicMock()
        conn.conn_kw = {"ssl_context": ctx}
        del conn.ssl_context
        adapter.cert_verify(conn, "https://x.test/", False, None)
        self.assertFalse(ctx.check_hostname)


class TestHttpClient(unittest.TestCase):
    def test_configure_and_reset_roundtrip(self):
        client = HttpClient()
        client.configure(proxy="http://p:1", insecure=True, user_agent="X")
        self.assertEqual(client.proxy, "http://p:1")
        self.assertTrue(client.insecure)
        self.assertEqual(client.default_headers(), {"User-Agent": "X"})
        kwargs = client.request_kwargs()
        self.assertEqual(kwargs["proxies"]["https"], "http://p:1")
        self.assertIs(kwargs.get("verify"), False)
        client.reset()
        self.assertIsNone(client.proxy)
        self.assertFalse(client.insecure)
        self.assertEqual(client.user_agent, "SurfaceSweep/1.0")

    def test_cache_fifo_eviction(self):
        client = HttpClient(cache_max=2)
        client.cache_text("https://a", "1")
        client.cache_text("https://b", "2")
        client.cache_text("https://c", "3")
        self.assertIsNone(client.get_cached_text("https://a"))
        self.assertEqual(client.get_cached_text("https://b"), "2")
        self.assertEqual(client.get_cached_text("https://c"), "3")

    def test_cache_empty_url_ignored(self):
        client = HttpClient()
        client.cache_text("", "x")
        self.assertIsNone(client.get_cached_text(""))

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_instance_fetch_with_retry(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(200)
        client = HttpClient()
        resp = client.fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(client.get_cached_text("https://x.test/a.js"), "ok")

    def test_default_client_is_shared(self):
        from modules.extraction import http as http_mod

        self.assertIsInstance(http_mod._client, HttpClient)
        before = len(http_mod._client._cache)
        http_mod.cache_text("https://shared.test/x.js", "body")
        self.assertEqual(http_mod.get_cached_text("https://shared.test/x.js"), "body")
        self.assertGreaterEqual(len(http_mod._client._cache), before + 1)


if __name__ == "__main__":
    unittest.main()
