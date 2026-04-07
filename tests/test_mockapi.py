"""Tests for the mockapi module."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from rekit.mockapi.server import (
    MockEndpoint,
    MockResponse,
    MockServer,
    build_from_har,
    _pattern_to_regex,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "startedDateTime": "2024-01-01T00:00:00Z",
                "time": 150,
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/api/items",
                    "headers": [
                        {"name": "Accept", "value": "application/json"},
                    ],
                    "queryString": [],
                },
                "response": {
                    "status": 200,
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "X-Custom", "value": "test"},
                    ],
                    "content": {
                        "mimeType": "application/json",
                        "text": '["item1", "item2"]',
                    },
                },
            },
            {
                "startedDateTime": "2024-01-01T00:00:01Z",
                "time": 200,
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/api/items",
                    "headers": [],
                    "queryString": [],
                },
                "response": {
                    "status": 200,
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "content": {
                        "mimeType": "application/json",
                        "text": '["item3", "item4"]',
                    },
                },
            },
            {
                "startedDateTime": "2024-01-01T00:00:02Z",
                "time": 50,
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/api/items/123",
                    "headers": [],
                    "queryString": [],
                },
                "response": {
                    "status": 200,
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "content": {
                        "mimeType": "application/json",
                        "text": '{"id": 123, "name": "widget"}',
                    },
                },
            },
            {
                "startedDateTime": "2024-01-01T00:00:03Z",
                "time": 100,
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/api/items",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "postData": {
                        "mimeType": "application/json",
                        "text": '{"name": "new item"}',
                    },
                },
                "response": {
                    "status": 201,
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "content": {
                        "mimeType": "application/json",
                        "text": '{"id": 456, "name": "new item"}',
                    },
                },
            },
        ],
    }
}


def _write_har(tmp_path: Path, data: dict | None = None) -> Path:
    """Write sample HAR data to a temp file and return the path."""
    har_path = tmp_path / "test.har"
    har_path.write_text(json.dumps(data or SAMPLE_HAR), encoding="utf-8")
    return har_path


def _free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Unit tests — MockServer.load_har
# ---------------------------------------------------------------------------


class TestLoadHar:
    """Tests for loading HAR data into a MockServer."""

    def test_load_har_creates_endpoints(self, tmp_path: Path) -> None:
        """load_har should create endpoints from HAR entries."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        methods = {ep.method for ep in server.endpoints}
        assert "GET" in methods
        assert "POST" in methods

    def test_load_har_groups_same_endpoint(self, tmp_path: Path) -> None:
        """Multiple requests to the same normalized path should group together."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        get_items = [
            ep
            for ep in server.endpoints
            if ep.method == "GET" and ep.path_pattern == "/api/items"
        ]
        assert len(get_items) == 1
        # Should have 2 responses grouped
        assert len(get_items[0].responses) == 2

    def test_load_har_path_params_normalized(self, tmp_path: Path) -> None:
        """Numeric path segments should be normalized as path params."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        param_endpoints = [ep for ep in server.endpoints if "{" in ep.path_pattern]
        assert len(param_endpoints) >= 1
        ep = param_endpoints[0]
        assert ep.path_regex is not None

    def test_load_har_captures_latency(self, tmp_path: Path) -> None:
        """Latency from HAR time field should be stored in responses."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        get_items = [
            ep
            for ep in server.endpoints
            if ep.method == "GET" and ep.path_pattern == "/api/items"
        ]
        assert get_items
        latencies = [r.latency_ms for r in get_items[0].responses]
        assert 150.0 in latencies
        assert 200.0 in latencies


# ---------------------------------------------------------------------------
# Unit tests — endpoint matching
# ---------------------------------------------------------------------------


class TestEndpointMatching:
    """Tests for matching incoming requests to stored endpoints."""

    def test_exact_path_match(self, tmp_path: Path) -> None:
        """Exact path should match the correct endpoint."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        ep = server._match_request("GET", "/api/items")
        assert ep is not None
        assert ep.method == "GET"

    def test_path_param_match(self, tmp_path: Path) -> None:
        """Path with parameter should match parameterized endpoint."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        ep = server._match_request("GET", "/api/items/999")
        assert ep is not None
        assert "{" in ep.path_pattern

    def test_no_match_returns_none(self, tmp_path: Path) -> None:
        """Non-existent path should return None."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        ep = server._match_request("GET", "/not/a/real/path")
        assert ep is None

    def test_method_mismatch_returns_none(self, tmp_path: Path) -> None:
        """Wrong method should not match."""
        har_path = _write_har(tmp_path)
        server = MockServer()
        server.load_har(har_path)

        ep = server._match_request("DELETE", "/api/items")
        assert ep is None


# ---------------------------------------------------------------------------
# Unit tests — response selection
# ---------------------------------------------------------------------------


class TestResponseSelection:
    """Tests for selecting responses from endpoints."""

    def test_sequential_round_robin(self) -> None:
        """Sequential mode should cycle through responses."""
        ep = MockEndpoint(
            method="GET",
            path_pattern="/test",
            path_regex=_pattern_to_regex("/test"),
            responses=[
                MockResponse(status_code=200, body="first"),
                MockResponse(status_code=200, body="second"),
            ],
        )
        assert ep.next_response("sequential").body == "first"
        assert ep.next_response("sequential").body == "second"
        assert ep.next_response("sequential").body == "first"

    def test_random_selection(self) -> None:
        """Random mode should return one of the available responses."""
        ep = MockEndpoint(
            method="GET",
            path_pattern="/test",
            path_regex=_pattern_to_regex("/test"),
            responses=[
                MockResponse(status_code=200, body="a"),
                MockResponse(status_code=200, body="b"),
            ],
        )
        results = {ep.next_response("random").body for _ in range(50)}
        # With 50 attempts and 2 choices, both should appear
        assert "a" in results
        assert "b" in results


# ---------------------------------------------------------------------------
# Unit tests — error injection
# ---------------------------------------------------------------------------


class TestErrorInjection:
    """Tests for error injection behaviour."""

    def test_error_rate_one_always_errors(self, tmp_path: Path) -> None:
        """With error_rate=1.0, every request should return 500."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port, error_rate=1.0)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            req = Request(f"http://127.0.0.1:{port}/api/items")
            try:
                urlopen(req, timeout=5)
                pytest.fail("Expected HTTP 500")
            except HTTPError as e:
                assert e.code == 500
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Unit tests — stateful mode
# ---------------------------------------------------------------------------


class TestStatefulMode:
    """Tests for stateful request storage."""

    def test_post_stores_get_retrieves(self, tmp_path: Path) -> None:
        """POST should store data, GET should retrieve it."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.stateful = True
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            # POST data
            payload = json.dumps({"stored": True}).encode("utf-8")
            req = Request(
                f"http://127.0.0.1:{port}/api/items",
                data=payload,
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            resp = urlopen(req, timeout=5)
            assert resp.status == 201

            # GET should return stored data
            req2 = Request(f"http://127.0.0.1:{port}/api/items")
            resp2 = urlopen(req2, timeout=5)
            body = json.loads(resp2.read())
            assert body == {"stored": True}
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Unit tests — CORS headers
# ---------------------------------------------------------------------------


class TestCors:
    """Tests for CORS headers."""

    def test_cors_header_present(self, tmp_path: Path) -> None:
        """Responses should include CORS Allow-Origin header."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            req = Request(f"http://127.0.0.1:{port}/api/items")
            resp = urlopen(req, timeout=5)
            assert resp.headers.get("Access-Control-Allow-Origin") == "*"
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Integration test — full HTTP server
# ---------------------------------------------------------------------------


class TestHTTPServer:
    """Integration tests that start the server and make real HTTP requests."""

    def test_get_items(self, tmp_path: Path) -> None:
        """GET /api/items should return captured response."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            req = Request(f"http://127.0.0.1:{port}/api/items")
            resp = urlopen(req, timeout=5)
            assert resp.status == 200
            body = json.loads(resp.read())
            assert isinstance(body, list)
        finally:
            server.stop()

    def test_get_item_with_param(self, tmp_path: Path) -> None:
        """GET /api/items/{id} should match parameterized endpoint."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            req = Request(f"http://127.0.0.1:{port}/api/items/42")
            resp = urlopen(req, timeout=5)
            assert resp.status == 200
            body = json.loads(resp.read())
            assert "id" in body
        finally:
            server.stop()

    def test_post_items(self, tmp_path: Path) -> None:
        """POST /api/items should return 201."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            payload = json.dumps({"name": "test"}).encode("utf-8")
            req = Request(
                f"http://127.0.0.1:{port}/api/items",
                data=payload,
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            resp = urlopen(req, timeout=5)
            assert resp.status == 201
        finally:
            server.stop()

    def test_404_for_unknown_path(self, tmp_path: Path) -> None:
        """Request to unknown path should return 404."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            req = Request(f"http://127.0.0.1:{port}/nope")
            try:
                urlopen(req, timeout=5)
                pytest.fail("Expected HTTP 404")
            except HTTPError as e:
                assert e.code == 404
        finally:
            server.stop()

    def test_sequential_round_robin_over_http(self, tmp_path: Path) -> None:
        """Sequential mode should alternate responses across HTTP calls."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.mode = "sequential"
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            bodies = []
            for _ in range(3):
                req = Request(f"http://127.0.0.1:{port}/api/items")
                resp = urlopen(req, timeout=5)
                bodies.append(resp.read().decode("utf-8"))

            # First and third should be the same (round-robin with 2 responses)
            assert bodies[0] == bodies[2]
            assert bodies[0] != bodies[1]
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Hot reload test
# ---------------------------------------------------------------------------


class TestHotReload:
    """Tests for hot reload of HAR files."""

    def test_reload_on_file_change(self, tmp_path: Path) -> None:
        """Server should reload when HAR file is modified."""
        har_path = _write_har(tmp_path)
        port = _free_port()
        server = MockServer(port=port)
        server.simulate_latency = False
        server.watch = True
        server.load_har(har_path)
        server.start_background()
        time.sleep(0.3)

        try:
            # Verify initial response
            req = Request(f"http://127.0.0.1:{port}/api/items")
            resp = urlopen(req, timeout=5)
            body1 = resp.read().decode("utf-8")
            assert "item1" in body1

            # Modify HAR file with different data
            modified_har = {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "startedDateTime": "2024-01-01T00:00:00Z",
                            "time": 10,
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/api/items",
                                "headers": [],
                                "queryString": [],
                            },
                            "response": {
                                "status": 200,
                                "headers": [
                                    {
                                        "name": "Content-Type",
                                        "value": "application/json",
                                    },
                                ],
                                "content": {
                                    "mimeType": "application/json",
                                    "text": '["reloaded"]',
                                },
                            },
                        }
                    ],
                }
            }
            # Ensure mtime changes
            time.sleep(0.1)
            har_path.write_text(json.dumps(modified_har), encoding="utf-8")

            # Next request triggers reload
            req2 = Request(f"http://127.0.0.1:{port}/api/items")
            resp2 = urlopen(req2, timeout=5)
            body2 = resp2.read().decode("utf-8")
            assert "reloaded" in body2
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# build_from_har convenience function
# ---------------------------------------------------------------------------


class TestBuildFromHar:
    """Tests for the build_from_har convenience function."""

    def test_build_from_har(self, tmp_path: Path) -> None:
        """build_from_har should return a configured MockServer."""
        har_path = _write_har(tmp_path)
        server = build_from_har(har_path, port=9999)
        assert server.port == 9999
        assert len(server.endpoints) > 0


# ---------------------------------------------------------------------------
# Pattern-to-regex
# ---------------------------------------------------------------------------


class TestPatternToRegex:
    """Tests for the _pattern_to_regex helper."""

    def test_static_path(self) -> None:
        """Static path should match exactly."""
        regex = _pattern_to_regex("/api/items")
        assert regex.match("/api/items")
        assert not regex.match("/api/items/123")

    def test_param_path(self) -> None:
        """Parameterized path should match variable segments."""
        regex = _pattern_to_regex("/api/items/{id}")
        assert regex.match("/api/items/123")
        assert regex.match("/api/items/abc")
        assert not regex.match("/api/items/123/sub")

    def test_multiple_params(self) -> None:
        """Multiple params should each match a segment."""
        regex = _pattern_to_regex("/api/{org}/repos/{repo_id}")
        assert regex.match("/api/myorg/repos/42")
        assert not regex.match("/api/myorg/repos")
