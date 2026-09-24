"""Unit tests for GraphQL introspection probe (Phase F3)."""

import unittest
from argparse import Namespace
from unittest import mock

import requests

from modules.discovery.graphql import (
    INTROSPECTION_QUERY,
    collect_graphql_candidates,
    probe_graphql_endpoints,
    probe_introspection,
)
from modules.pipeline import ScanContext
from modules.pipeline.stages import stage_graphql


class _Resp:
    def __init__(self, status_code=200, payload=None, text="", raise_json=False):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


def _schema_payload(n_types=3):
    types = [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(n_types)]
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": types,
            }
        }
    }


class TestProbeIntrospection(unittest.TestCase):
    def test_query_contains_schema(self):
        self.assertIn("__schema", INTROSPECTION_QUERY)

    @mock.patch("modules.discovery.graphql.request_kwargs", create=True)
    def test_open_introspection_detected(self, _rk=None):
        session = mock.Mock()
        session.post.return_value = _Resp(200, _schema_payload(5))
        r = probe_introspection("https://x.test/graphql", session=session)
        self.assertTrue(r["introspection_enabled"])
        self.assertEqual(r["query_type"], "Query")
        self.assertEqual(r["mutation_type"], "Mutation")
        self.assertEqual(r["type_count"], 5)
        self.assertEqual(r["status"], 200)
        session.post.assert_called_once()

    def test_blocked_introspection_not_enabled(self):
        session = mock.Mock()
        session.post.return_value = _Resp(
            200, {"errors": [{"message": "introspection disabled"}]}
        )
        r = probe_introspection("https://x.test/graphql", session=session)
        self.assertFalse(r["introspection_enabled"])
        self.assertIn("blocked", r["error"] or "")

    def test_non_json_response(self):
        session = mock.Mock()
        session.post.return_value = _Resp(200, None, text="<html>", raise_json=True)
        r = probe_introspection("https://x.test/graphql", session=session)
        self.assertFalse(r["introspection_enabled"])
        self.assertEqual(r["error"], "non-JSON response")

    def test_connection_error_swallowed(self):
        session = mock.Mock()
        session.post.side_effect = requests.ConnectionError("down")
        r = probe_introspection("https://x.test/graphql", session=session)
        self.assertFalse(r["introspection_enabled"])
        self.assertIn("down", r["error"])

    def test_post_sends_json_query(self):
        session = mock.Mock()
        session.post.return_value = _Resp(200, _schema_payload())
        probe_introspection("https://x.test/graphql", session=session)
        args, kwargs = session.post.call_args
        self.assertEqual(args[0], "https://x.test/graphql")
        self.assertIn("query", kwargs["json"])
        self.assertEqual(kwargs["json"]["query"], INTROSPECTION_QUERY)
        self.assertEqual(kwargs["headers"].get("Content-Type"), "application/json")


class TestProbeGraphqlEndpoints(unittest.TestCase):
    @mock.patch("modules.discovery.graphql.probe_introspection")
    def test_findings_for_open_endpoint(self, probe_mock):
        probe_mock.return_value = {
            "url": "https://x.test/graphql",
            "status": 200,
            "introspection_enabled": True,
            "query_type": "Query",
            "mutation_type": None,
            "type_count": 12,
            "types": ["Query"],
            "error": None,
        }
        out = probe_graphql_endpoints(
            ["https://x.test/graphql"], verbose=False
        )
        self.assertEqual(out["introspection_open"], 1)
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["severity"], "HIGH")
        self.assertIn("introspection", out["findings"][0]["detail"].lower())

    @mock.patch("modules.discovery.graphql.probe_introspection")
    def test_no_finding_when_blocked(self, probe_mock):
        probe_mock.return_value = {
            "url": "https://x.test/graphql",
            "status": 200,
            "introspection_enabled": False,
            "query_type": None,
            "mutation_type": None,
            "type_count": 0,
            "types": [],
            "error": "introspection blocked",
        }
        out = probe_graphql_endpoints(
            ["https://x.test/graphql"], verbose=False
        )
        self.assertEqual(out["introspection_open"], 0)
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["endpoints_tested"], 1)


class TestCollectCandidates(unittest.TestCase):
    def test_collects_from_endpoints_and_tags(self):
        result = {
            "internal_paths": ["/graphql", "/api/users", "/api/gql"],
            "in_scope_urls": [],
            "intercepted_endpoints": [
                {"url": "https://x.test/graphql", "method": "POST", "tags": ["graphql"]},
                {"url": "https://x.test/other", "method": "GET", "tags": []},
            ],
        }
        cands = collect_graphql_candidates(result, "https://x.test")
        self.assertTrue(any("graphql" in u for u in cands))
        self.assertFalse(any(u.endswith("/other") for u in cands))

    def test_fallback_common_paths_when_none_found(self):
        cands = collect_graphql_candidates(
            {"internal_paths": ["/api/users"], "in_scope_urls": []},
            "https://x.test",
        )
        self.assertIn("https://x.test/graphql", cands)

    def test_empty_without_target(self):
        cands = collect_graphql_candidates({}, "")
        self.assertEqual(cands, [])


class TestStageGraphql(unittest.TestCase):
    def _args(self, **kw):
        base = dict(
            target="https://example.com",
            graphql=True,
            graphql_timeout=5.0,
        )
        base.update(kw)
        return Namespace(**base)

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.probe_graphql_endpoints")
    @mock.patch("modules.pipeline.stages.collect_graphql_candidates")
    def test_stage_writes_result(self, collect_mock, probe_mock, risk_mock):
        collect_mock.return_value = ["https://example.com/graphql"]
        probe_mock.return_value = {
            "endpoints": [{
                "url": "https://example.com/graphql",
                "status": 200,
                "introspection_enabled": True,
                "type_count": 3,
                "query_type": "Query",
                "error": None,
            }],
            "findings": [{
                "severity": "HIGH",
                "url": "https://example.com/graphql",
                "detail": "open",
            }],
            "endpoints_tested": 1,
            "introspection_open": 1,
            "summary": {"endpoints_tested": 1, "introspection_open": 1},
        }
        risk_mock.return_value = {"level": "HIGH", "score": 40}
        ctx = ScanContext(self._args(), verbose=False)
        ctx.result = {"target": "https://example.com", "internal_paths": []}
        stage_graphql(ctx)
        self.assertEqual(ctx.result["graphql"]["introspection_open"], 1)
        self.assertEqual(len(ctx.result["graphql"]["findings"]), 1)
        risk_mock.assert_called_once()
        probe_mock.assert_called_once()

    @mock.patch("modules.pipeline.stages.calculate_risk_summary")
    @mock.patch("modules.pipeline.stages.probe_graphql_endpoints")
    @mock.patch("modules.pipeline.stages.collect_graphql_candidates")
    def test_stage_empty_candidates(self, collect_mock, probe_mock, risk_mock):
        collect_mock.return_value = []
        risk_mock.return_value = {"level": "INFO", "score": 0}
        ctx = ScanContext(self._args(), verbose=False)
        ctx.result = {"target": "https://example.com"}
        stage_graphql(ctx)
        self.assertEqual(ctx.result["graphql"]["endpoints_tested"], 0)
        probe_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
