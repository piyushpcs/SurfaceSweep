"""
Regression tests for redirect-based SSRF and DNS-name SSRF bypasses (SF-11).

The metadata guard used to be applied to the initial URL only, while the HTTP
client followed redirects by default — so a target could answer
``302 Location: http://169.254.169.254/...`` and have the metadata body
fetched and scanned. The guard was also a hostname *string* check, so a DNS
name resolving to a link-local address slipped past it.

These tests pin the fixes: every redirect hop is re-validated, and hosts are
resolved + IP-checked (and pinned) before connecting.
"""

import socket
import unittest
from unittest import mock

import requests

from modules.common.netguard import is_blocked_ip
from modules.extraction.http import (
    fetch_with_retry,
    follow_redirects,
    is_blocked_fetch_target,
    request_tls,
)


def _resp(status_code=200, headers=None, text="ok", url="https://x.test/"):
    r = mock.Mock(spec=requests.Response)
    r.status_code = status_code
    r.headers = headers or {}
    r.text = text
    r.url = url

    def _raise():
        if status_code >= 400:
            raise requests.HTTPError(f"{status_code}")

    r.raise_for_status = mock.Mock(side_effect=_raise)
    return r


def _gai_to(addr):
    def _fake(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    return _fake


class TestBlockedIp(unittest.TestCase):
    def test_metadata_and_link_local_blocked(self):
        for ip in (
            "169.254.169.254",
            "169.254.1.1",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "fe80::1%en0",
            "::ffff:169.254.169.254",
            "0.0.0.0",
        ):
            self.assertTrue(is_blocked_ip(ip), ip)

    def test_public_and_private_allowed(self):
        # Private / loopback stay allowed (local testbeds, internal tests).
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.5", "8.8.8.8", "::1"):
            self.assertFalse(is_blocked_ip(ip), ip)

    def test_unparseable_is_blocked(self):
        self.assertTrue(is_blocked_ip("not-an-ip"))


class TestRedirectSsrf(unittest.TestCase):
    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_fetch_refuses_redirect_to_metadata(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(
            302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
        )
        with self.assertRaises(requests.ConnectionError):
            fetch_with_retry("https://x.test/a.js")
        # The metadata hop was never requested.
        self.assertEqual(get_mock.call_count, 1)
        requested = [c.args[0] for c in get_mock.call_args_list]
        self.assertNotIn("http://169.254.169.254/latest/meta-data/", requested)

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_fetch_follows_safe_redirect(self, get_mock, sleep_mock):
        get_mock.side_effect = [
            _resp(302, headers={"Location": "https://cdn.test/final.js"}),
            _resp(200, text="final"),
        ]
        resp = fetch_with_retry("https://x.test/a.js")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(get_mock.call_count, 2)
        self.assertEqual(
            get_mock.call_args_list[1].args[0], "https://cdn.test/final.js"
        )

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_metadata_blocked_at_final_hop(self, get_mock, sleep_mock):
        get_mock.side_effect = [
            _resp(302, headers={"Location": "https://safe.test/hop"}),
            _resp(
                302,
                headers={"Location": "http://100.100.100.200/latest/meta-data/"},
            ),
            _resp(200),
        ]
        with self.assertRaises(requests.ConnectionError):
            fetch_with_retry("https://x.test/a.js")
        self.assertEqual(get_mock.call_count, 2)

    @mock.patch("modules.extraction.http.requests.get")
    def test_fetch_refuses_hostname_resolving_to_link_local(self, get_mock):
        with mock.patch("socket.getaddrinfo", side_effect=_gai_to("169.254.169.254")):
            with self.assertRaises(requests.ConnectionError):
                fetch_with_retry("https://metadata-alias.test/x.js")
        get_mock.assert_not_called()

    @mock.patch("modules.extraction.http.time.sleep")
    @mock.patch("modules.extraction.http.requests.get")
    def test_private_testbed_still_allowed(self, get_mock, sleep_mock):
        get_mock.return_value = _resp(200, text="local")
        with mock.patch("socket.getaddrinfo", side_effect=_gai_to("127.0.0.1")):
            resp = fetch_with_retry("http://internal.test/x.js")
        self.assertEqual(resp.status_code, 200)
        get_mock.assert_called_once()

    @mock.patch("modules.extraction.http.requests.request")
    def test_request_tls_refuses_redirect_to_metadata(self, request_mock):
        request_mock.return_value = _resp(
            301, headers={"Location": "http://169.254.169.254/"}
        )
        with self.assertRaises(requests.ConnectionError):
            request_tls("GET", "https://x.test/")
        self.assertEqual(request_mock.call_count, 1)

    def test_follow_redirects_validates_every_hop(self):
        seen = []

        def send(method, url):
            seen.append(url)
            if url == "https://start.test/":
                return _resp(302, headers={"Location": "http://169.254.169.254/"})
            return _resp(200)

        with self.assertRaises(requests.ConnectionError):
            follow_redirects(send, "GET", "https://start.test/")
        self.assertEqual(seen, ["https://start.test/"])

    def test_follow_redirects_disabled_single_request(self):
        seen = []

        def send(method, url):
            seen.append(url)
            return _resp(302, headers={"Location": "https://next.test/"})

        resp = follow_redirects(
            send, "GET", "https://start.test/", allow_redirects=False
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(seen, ["https://start.test/"])

    def test_metadata_hostname_still_blocked_direct(self):
        self.assertTrue(is_blocked_fetch_target("http://metadata.google.internal/x"))


if __name__ == "__main__":
    unittest.main()
