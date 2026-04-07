"""mockapi.server — Generate and run a mock HTTP server from captured traffic."""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, unquote

from rekit.hargen.analyzer import _normalize_path
from rekit.hargen.parser import HttpExchange, parse_har

logger = logging.getLogger(__name__)


@dataclass
class MockResponse:
    """A stored HTTP response to replay."""

    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: Union[str, bytes, None] = None
    content_type: str = ""
    latency_ms: float = 0.0


@dataclass
class MockEndpoint:
    """A mock endpoint backed by one or more captured responses."""

    method: str
    path_pattern: str
    path_regex: re.Pattern[str] = field(default=None)  # type: ignore[assignment]
    responses: List[MockResponse] = field(default_factory=list)
    request_matchers: Dict[str, Any] = field(default_factory=dict)
    _counter: int = field(default=0, repr=False)

    def next_response(self, mode: str = "sequential") -> MockResponse:
        """Select the next response based on the selection mode."""
        if not self.responses:
            return MockResponse(status_code=404, body="No responses stored")
        if mode == "random":
            return random.choice(self.responses)
        # sequential round-robin
        idx = self._counter % len(self.responses)
        self._counter += 1
        return self.responses[idx]


def _pattern_to_regex(path_pattern: str) -> re.Pattern[str]:
    """Convert a path pattern like /api/{id}/items to a regex."""
    parts = path_pattern.strip("/").split("/")
    regex_parts: List[str] = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            regex_parts.append("([^/]+)")
        else:
            regex_parts.append(re.escape(part))
    pattern = "^/" + "/".join(regex_parts) + "$"
    return re.compile(pattern)


class MockServer:
    """A mock HTTP server that replays captured HAR traffic."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        error_rate: float = 0.0,
        latency_jitter: float = 0.0,
    ) -> None:
        self.host = host
        self.port = port
        self.error_rate = error_rate
        self.latency_jitter = latency_jitter
        self.endpoints: List[MockEndpoint] = []
        self.mode: str = "sequential"
        self.simulate_latency: bool = True
        self.cors: bool = True
        self.stateful: bool = False
        self.watch: bool = False
        self._har_path: Optional[Path] = None
        self._har_mtime: float = 0.0
        self._state_store: Dict[str, Union[str, bytes]] = {}
        self._server: Optional[HTTPServer] = None

    def load_har(self, path: Union[str, Path]) -> None:
        """Parse a HAR file and populate endpoints from the captured traffic.

        Args:
            path: Path to the HAR file.
        """
        path = Path(path)
        self._har_path = path
        self._har_mtime = path.stat().st_mtime

        exchanges = parse_har(path)

        # Also read raw HAR for timing data
        with open(path, "r", encoding="utf-8") as f:
            raw_har = json.load(f)
        entries = raw_har.get("log", {}).get("entries", [])
        timing_map: Dict[int, float] = {}
        for i, entry in enumerate(entries):
            total_time = entry.get("time", 0)
            timing_map[i] = float(total_time)

        # Group by (method, normalized_path)
        groups: Dict[Tuple[str, str], List[Tuple[HttpExchange, float]]] = {}
        for i, ex in enumerate(exchanges):
            parsed = urlparse(ex.url)
            path_str = parsed.path or "/"
            pattern, _params = _normalize_path(path_str)
            key = (ex.method.upper(), pattern)
            if key not in groups:
                groups[key] = []
            groups[key].append((ex, timing_map.get(i, 0.0)))

        self.endpoints = []
        for (method, pattern), items in groups.items():
            endpoint = MockEndpoint(
                method=method,
                path_pattern=pattern,
                path_regex=_pattern_to_regex(pattern),
            )
            for ex, latency in items:
                body = ex.response_body
                endpoint.responses.append(
                    MockResponse(
                        status_code=ex.status_code or 200,
                        headers=dict(ex.response_headers),
                        body=body,
                        content_type=ex.content_type,
                        latency_ms=latency,
                    )
                )
            self.endpoints.append(endpoint)

    def _check_reload(self) -> None:
        """Check if the HAR file has been modified and reload if so."""
        if not self.watch or not self._har_path:
            return
        try:
            mtime = self._har_path.stat().st_mtime
            if mtime > self._har_mtime:
                logger.info("HAR file changed, reloading: %s", self._har_path)
                self.load_har(self._har_path)
        except OSError:
            pass

    def _match_request(self, method: str, path: str) -> Optional[MockEndpoint]:
        """Match an incoming request against stored endpoints.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: Request path.

        Returns:
            The matching MockEndpoint, or None.
        """
        for ep in self.endpoints:
            if ep.method != method.upper():
                continue
            if ep.path_regex and ep.path_regex.match(path):
                return ep
        return None

    def _select_response(self, endpoint: MockEndpoint) -> MockResponse:
        """Select a response from an endpoint using the configured mode.

        Args:
            endpoint: The matched endpoint.

        Returns:
            The selected MockResponse.
        """
        return endpoint.next_response(self.mode)

    def _build_handler(self) -> type:
        """Build an HTTP request handler class bound to this server instance."""
        server_ref = self

        class MockHandler(BaseHTTPRequestHandler):
            """HTTP handler that replays stored responses."""

            def _handle(self) -> None:
                server_ref._check_reload()

                method = self.command.upper()
                path = unquote(self.path.split("?")[0])

                # Read request body
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else b""

                # Stateful: store body for POST/PUT
                if server_ref.stateful and method in ("POST", "PUT", "PATCH"):
                    server_ref._state_store[path] = body

                # Stateful: return stored body for GET if available
                if (
                    server_ref.stateful
                    and method == "GET"
                    and path in server_ref._state_store
                ):
                    stored = server_ref._state_store[path]
                    self.send_response(200)
                    if server_ref.cors:
                        self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    if isinstance(stored, str):
                        self.wfile.write(stored.encode("utf-8"))
                    else:
                        self.wfile.write(stored)
                    return

                # CORS preflight
                if method == "OPTIONS" and server_ref.cors:
                    self.send_response(204)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header(
                        "Access-Control-Allow-Methods",
                        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                    )
                    self.send_header("Access-Control-Allow-Headers", "*")
                    self.end_headers()
                    return

                endpoint = server_ref._match_request(method, path)
                if not endpoint:
                    self.send_response(404)
                    if server_ref.cors:
                        self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "No matching endpoint"}).encode("utf-8")
                    )
                    return

                # Error injection
                if (
                    server_ref.error_rate > 0
                    and random.random() < server_ref.error_rate
                ):
                    self.send_response(500)
                    if server_ref.cors:
                        self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "Injected error"}).encode("utf-8")
                    )
                    return

                resp = server_ref._select_response(endpoint)

                # Latency simulation
                if server_ref.simulate_latency and resp.latency_ms > 0:
                    delay = resp.latency_ms / 1000.0
                    if server_ref.latency_jitter > 0:
                        jitter = delay * server_ref.latency_jitter
                        delay += random.uniform(-jitter, jitter)
                    if delay > 0:
                        time.sleep(delay)

                self.send_response(resp.status_code)

                # Send headers (skip hop-by-hop)
                skip = {
                    "transfer-encoding",
                    "connection",
                    "keep-alive",
                    "content-length",
                    "content-encoding",
                }
                for name, value in resp.headers.items():
                    if name.lower() not in skip:
                        self.send_header(name, value)

                if server_ref.cors:
                    self.send_header("Access-Control-Allow-Origin", "*")

                self.end_headers()

                # Write body
                if resp.body is not None:
                    if isinstance(resp.body, str):
                        self.wfile.write(resp.body.encode("utf-8"))
                    else:
                        self.wfile.write(resp.body)

            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def do_PUT(self) -> None:
                self._handle()

            def do_PATCH(self) -> None:
                self._handle()

            def do_DELETE(self) -> None:
                self._handle()

            def do_OPTIONS(self) -> None:
                self._handle()

            def log_message(self, format: str, *args: Any) -> None:
                """Log requests using the logging module."""
                try:
                    from rich.console import Console

                    console = Console(stderr=True)
                    msg = format % args
                    console.print(f"  [dim]{msg}[/dim]")
                except ImportError:
                    logger.info(format, *args)

        return MockHandler

    def run(self) -> None:
        """Start the mock HTTP server (blocking)."""
        handler_cls = self._build_handler()
        self._server = HTTPServer((self.host, self.port), handler_cls)
        logger.info("Mock server running on http://%s:%d", self.host, self.port)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._server.server_close()

    def start_background(self) -> threading.Thread:
        """Start the mock server in a background thread.

        Returns:
            The running thread.
        """
        handler_cls = self._build_handler()
        self._server = HTTPServer((self.host, self.port), handler_cls)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Stop the running server."""
        if self._server:
            self._server.shutdown()


def build_from_har(path: Union[str, Path], **kwargs: Any) -> MockServer:
    """Convenience function to build a MockServer from a HAR file.

    Args:
        path: Path to the HAR file.
        **kwargs: Extra keyword arguments passed to MockServer().

    Returns:
        A MockServer with endpoints loaded from the HAR file.
    """
    server = MockServer(**kwargs)
    server.load_har(path)
    return server
