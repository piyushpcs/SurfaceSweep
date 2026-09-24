"""Unit tests for SPA common-route probe hardening (Phase C — C10)."""

import unittest
from unittest import mock

import requests

from modules.discovery.spa import probe_route


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class TestProbeRoute(unittest.TestCase):
    def test_head_200_no_get_fallback(self):
        session = mock.Mock()
        session.head.return_value = _Resp(200)
        self.assertEqual(probe_route("https://x.test/admin", session=session), 200)
        session.get.assert_not_called()

    def test_head_401_counts_as_exists(self):
        session = mock.Mock()
        session.head.return_value = _Resp(401)
        self.assertEqual(probe_route("https://x.test/admin", session=session), 401)
        session.get.assert_not_called()

    def test_head_405_falls_back_to_get(self):
        session = mock.Mock()
        session.head.return_value = _Resp(405)
        session.get.return_value = _Resp(200)
        self.assertEqual(probe_route("https://x.test/api", session=session), 200)
        session.get.assert_called_once()

    def test_head_404_get_200(self):
        session = mock.Mock()
        session.head.return_value = _Resp(404)
        session.get.return_value = _Resp(200)
        self.assertEqual(probe_route("https://x.test/hidden", session=session), 200)

    def test_both_404_returns_none(self):
        session = mock.Mock()
        session.head.return_value = _Resp(404)
        session.get.return_value = _Resp(404)
        self.assertIsNone(probe_route("https://x.test/nope", session=session))

    def test_head_405_get_404_returns_none(self):
        session = mock.Mock()
        session.head.return_value = _Resp(405)
        session.get.return_value = _Resp(404)
        self.assertIsNone(probe_route("https://x.test/nope", session=session))

    def test_network_error_returns_none(self):
        session = mock.Mock()
        session.head.side_effect = requests.ConnectionError("down")
        session.get.side_effect = requests.ConnectionError("down")
        self.assertIsNone(probe_route("https://x.test/x", session=session))

    def test_head_reset_falls_back_to_get(self):
        session = mock.Mock()
        session.head.side_effect = requests.ConnectionError(
            "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
        )
        session.get.return_value = _Resp(200)
        self.assertEqual(probe_route("https://x.test/admin", session=session), 200)
        session.get.assert_called_once()


class TestCrawlSpaHangHardening(unittest.TestCase):
    """BFS crawl must not use networkidle (hangs on long-poll/SSE apps)."""

    def test_bfs_crawl_uses_domcontentloaded(self):
        import inspect
        from modules.discovery import spa

        src = inspect.getsource(spa.crawl_spa_routes)
        self.assertIn('wait_until="domcontentloaded"', src)
        self.assertNotIn('wait_until="networkidle", timeout=10000', src)


if __name__ == "__main__":
    unittest.main()
