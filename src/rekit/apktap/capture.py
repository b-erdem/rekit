"""
capture.py — Main capture orchestration for apktap.

Manages Frida sessions, injects hook scripts, correlates request/response
pairs, and exports captured traffic as HAR 1.2 files.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table

from rekit.apktap.utils import (
    check_frida_server,
    detect_http_libraries,
    format_exchange,
    get_hooks_for_libraries,
)

console = Console(stderr=True)

HOOKS_DIR = Path(__file__).parent / "hooks"


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------


@dataclass
class HttpRequest:
    """Captured HTTP request."""

    url: str = ""
    method: str = "GET"
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    timestamp: float = 0.0


@dataclass
class HttpResponse:
    """Captured HTTP response."""

    status_code: int = 0
    status_text: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    timestamp: float = 0.0
    timing: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class Exchange:
    """A matched request/response pair."""

    id: str
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None
    source: str = ""


class ExchangeBuffer:
    """Thread-safe buffer that holds and correlates request/response pairs.

    Requests and responses are matched by their correlation ID, which is
    assigned by the Frida hook scripts.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._exchanges: Dict[str, Exchange] = {}
        self._order: List[str] = []

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._exchanges)

    @property
    def complete_count(self) -> int:
        with self._lock:
            return sum(
                1
                for ex in self._exchanges.values()
                if ex.request is not None and ex.response is not None
            )

    def add_request(self, id: str, request: HttpRequest, source: str = "") -> None:
        with self._lock:
            if id not in self._exchanges:
                self._exchanges[id] = Exchange(id=id, source=source)
                self._order.append(id)
            self._exchanges[id].request = request

    def add_response(self, id: str, response: HttpResponse) -> None:
        with self._lock:
            if id not in self._exchanges:
                self._exchanges[id] = Exchange(id=id)
                self._order.append(id)
            self._exchanges[id].response = response

    def get_exchange(self, id: str) -> Optional[Exchange]:
        with self._lock:
            return self._exchanges.get(id)

    def all_exchanges(self) -> List[Exchange]:
        """Return all exchanges in order of first appearance."""
        with self._lock:
            return [
                self._exchanges[eid] for eid in self._order if eid in self._exchanges
            ]

    def latest(self, n: int = 1) -> List[Exchange]:
        with self._lock:
            ids = self._order[-n:]
            return [self._exchanges[eid] for eid in ids if eid in self._exchanges]


# ---------------------------------------------------------------------------
#  HAR export
# ---------------------------------------------------------------------------


def _make_har_headers(headers: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert a headers dict to HAR headers list format."""
    result = []
    for key, value in headers.items():
        if key.startswith("_"):
            continue
        if isinstance(value, list):
            for v in value:
                result.append({"name": key, "value": str(v)})
        else:
            result.append({"name": key, "value": str(value)})
    return result


def _make_har_body(body: Any, is_request: bool = True) -> Dict[str, Any]:
    """Convert a body value to HAR format."""
    if body is None:
        if is_request:
            return {"mimeType": "", "text": ""}
        return {"size": 0, "mimeType": "", "text": ""}

    if isinstance(body, str):
        result = {"mimeType": "text/plain", "text": body}
        if not is_request:
            result["size"] = len(body.encode("utf-8", errors="replace"))
        return result

    if isinstance(body, dict):
        if body.get("_base64"):
            data = body.get("data", "")
            result = {
                "mimeType": "application/octet-stream",
                "text": data,
                "encoding": "base64",
            }
            if not is_request:
                result["size"] = body.get("size", len(data))
            return result

        if body.get("_truncated"):
            result = {
                "mimeType": "application/octet-stream",
                "text": "",
                "comment": f"Body truncated, original size: {body.get('size', 'unknown')} bytes",
            }
            if not is_request:
                result["size"] = body.get("size", 0)
            return result

        if body.get("_multipart"):
            text = f"[Multipart body with {len(body.get('parts', []))} parts]"
            result = {"mimeType": "multipart/form-data", "text": text}
            if not is_request:
                result["size"] = len(text)
            return result

        if body.get("_error"):
            result = {
                "mimeType": "",
                "text": "",
                "comment": body["_error"],
            }
            if not is_request:
                result["size"] = 0
            return result

    # Fallback: JSON-encode the body
    text = json.dumps(body, ensure_ascii=False)
    result = {"mimeType": "application/json", "text": text}
    if not is_request:
        result["size"] = len(text.encode("utf-8", errors="replace"))
    return result


def _parse_url(url: str) -> Dict[str, Any]:
    """Parse URL into components for HAR queryString."""
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(url)
    query_params = []
    if parsed.query:
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            for v in values:
                query_params.append({"name": key, "value": v})
    return {"queryString": query_params}


def save_har(exchanges: List[Exchange], output_path: Path) -> None:
    """Save captured exchanges as a HAR 1.2 file.

    Produces a JSON file compatible with Chrome DevTools, hargen, and
    other HAR-consuming tools.
    """
    entries = []
    for ex in exchanges:
        if ex.request is None:
            continue

        req = ex.request
        resp = ex.response

        # Build request entry
        url_info = _parse_url(req.url)
        har_request = {
            "method": req.method,
            "url": req.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _make_har_headers(req.headers),
            "queryString": url_info["queryString"],
            "postData": _make_har_body(req.body, is_request=True) if req.body else None,
            "headersSize": -1,
            "bodySize": -1,
        }
        if har_request["postData"] is None:
            del har_request["postData"]

        # Build response entry
        if resp and not resp.error:
            response_body = _make_har_body(resp.body, is_request=False)
            har_response = {
                "status": resp.status_code,
                "statusText": resp.status_text or "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": _make_har_headers(resp.headers),
                "content": {
                    "size": response_body.get("size", 0),
                    "mimeType": resp.headers.get(
                        "Content-Type", response_body.get("mimeType", "")
                    ),
                    "text": response_body.get("text", ""),
                },
                "redirectURL": resp.headers.get("Location", ""),
                "headersSize": -1,
                "bodySize": -1,
            }
            if response_body.get("encoding"):
                har_response["content"]["encoding"] = response_body["encoding"]
        elif resp and resp.error:
            har_response = {
                "status": 0,
                "statusText": resp.error,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
                "_error": {"message": resp.error},
            }
        else:
            # No response received
            har_response = {
                "status": 0,
                "statusText": "(no response captured)",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            }

        # Timing
        timing_ms = 0
        if resp and resp.timing:
            timing_ms = resp.timing.get("durationMs", 0)

        started = datetime.fromtimestamp(
            req.timestamp / 1000.0 if req.timestamp > 1e12 else req.timestamp,
            tz=timezone.utc,
        ).isoformat()

        entry = {
            "startedDateTime": started,
            "time": timing_ms,
            "request": har_request,
            "response": har_response,
            "cache": {},
            "timings": {
                "send": 0,
                "wait": timing_ms,
                "receive": 0,
            },
            "comment": f"Captured by apktap from {ex.source}" if ex.source else "",
        }
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "rekit-apktap",
                "version": "0.1.0",
            },
            "entries": entries,
        }
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(har, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
#  Capture session
# ---------------------------------------------------------------------------


class CaptureSession:
    """Manages a Frida capture session against an Android app.

    Handles device connection, app spawn/attach, hook injection,
    message handling, and graceful shutdown.
    """

    def __init__(
        self,
        package_name: str,
        device_id: Optional[str] = None,
        spawn: bool = True,
        filter_host: Optional[str] = None,
        verbose: bool = False,
    ):
        self.package_name = package_name
        self.device_id = device_id
        self.spawn = spawn
        self.filter_host = filter_host
        self.verbose = verbose

        self.buffer = ExchangeBuffer()
        self._device = None
        self._session = None
        self._scripts: List[Any] = []
        self._pid: Optional[int] = None
        self._running = False
        self._status_messages: List[str] = []

    def _connect_device(self):
        """Connect to the target Frida device."""
        import frida

        try:
            if self.device_id:
                self._device = frida.get_device(self.device_id, timeout=5)
            else:
                self._device = frida.get_usb_device(timeout=5)
        except frida.TimedOutError:
            console.print(
                "[bold red]Error:[/] Could not connect to device (timed out).\n\n"
                "[dim]Make sure:\n"
                "  1. USB debugging is enabled on the device\n"
                "  2. The device is connected via USB\n"
                "  3. `adb devices` shows the device\n"
                "  4. You authorized the USB debugging prompt on the device[/]"
            )
            sys.exit(1)
        except frida.InvalidArgumentError:
            console.print(
                f"[bold red]Error:[/] Device '{self.device_id}' not found.\n"
                "Run `adb devices` to see available devices."
            )
            sys.exit(1)
        except Exception as exc:
            console.print(f"[bold red]Error:[/] {exc}")
            sys.exit(1)

        if not check_frida_server(self._device):
            sys.exit(1)

        console.print(f"[green]Connected to device:[/] {self._device.name}")

    def _spawn_or_attach(self):
        """Spawn the app or attach to a running process."""
        import frida

        if self.spawn:
            console.print(f"[dim]Spawning {self.package_name}...[/]")
            try:
                self._pid = self._device.spawn([self.package_name])
                self._session = self._device.attach(self._pid)
                console.print(f"[green]Spawned and attached:[/] PID {self._pid}")
            except frida.ProcessNotFoundError:
                console.print(
                    f"[bold red]Error:[/] Package '{self.package_name}' not found on device.\n"
                    "Run [bold]rekit apktap list-apps[/] to see installed packages."
                )
                sys.exit(1)
            except Exception as exc:
                console.print(f"[bold red]Error spawning app:[/] {exc}")
                sys.exit(1)
        else:
            console.print(f"[dim]Attaching to {self.package_name}...[/]")
            try:
                self._session = self._device.attach(self.package_name)
                self._pid = self._session.pid
                console.print(f"[green]Attached:[/] PID {self._pid}")
            except frida.ProcessNotFoundError:
                console.print(
                    f"[bold red]Error:[/] Process '{self.package_name}' is not running.\n"
                    "Start the app first, or use [bold]--spawn[/] to launch it."
                )
                sys.exit(1)
            except Exception as exc:
                console.print(f"[bold red]Error attaching:[/] {exc}")
                sys.exit(1)

        # Monitor for unexpected detach
        self._session.on("detached", self._on_detached)

    def _on_detached(self, reason, crash):
        """Handle unexpected session detachment."""
        self._running = False
        if reason == "application-requested":
            console.print("\n[yellow]App closed normally.[/]")
        elif crash:
            console.print(f"\n[bold red]App crashed:[/] {crash}")
            console.print("[dim]Saving captured data...[/]")
        else:
            console.print(f"\n[yellow]Detached:[/] {reason}")

    def _inject_hooks(self):
        """Detect HTTP libraries and inject appropriate hook scripts."""
        # Detect libraries if possible
        detected = []
        if self._pid:
            try:
                detected = detect_http_libraries(self._device, self._pid)
                if detected:
                    console.print(
                        f"[dim]Detected HTTP libraries:[/] {', '.join(detected)}"
                    )
            except Exception:
                pass

        # Get hook scripts to inject
        hook_scripts = get_hooks_for_libraries(detected)

        if not hook_scripts:
            # Default: inject OkHttp (most common) + URLConnection (fallback)
            hook_scripts = ["okhttp.js", "urlconnection.js"]
            console.print(
                "[dim]No libraries detected yet (app may not have loaded them). "
                "Injecting default hooks: OkHttp + URLConnection[/]"
            )

        for hook_file in hook_scripts:
            hook_path = HOOKS_DIR / hook_file
            if not hook_path.exists():
                console.print(f"[yellow]Warning:[/] Hook script not found: {hook_file}")
                continue

            try:
                source = hook_path.read_text(encoding="utf-8")
                script = self._session.create_script(source)
                script.on("message", self.on_message)
                script.load()
                self._scripts.append(script)
                console.print(f"[green]Loaded hook:[/] {hook_file}")
            except Exception as exc:
                console.print(f"[yellow]Warning:[/] Failed to load {hook_file}: {exc}")

        # Resume the app if we spawned it
        if self.spawn and self._pid:
            self._device.resume(self._pid)
            console.print("[green]App resumed[/]")

    def on_message(self, message: Dict[str, Any], data: Any) -> None:
        """Handle messages from Frida hook scripts.

        Messages are JSON objects with a 'type' field:
          - "request"  — captured HTTP request
          - "response" — captured HTTP response
          - "status"   — hook status/diagnostic message
          - "error"    — hook error
        """
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if not isinstance(payload, dict):
                return

            msg_type = payload.get("type", "")

            if msg_type == "request":
                self._handle_request(payload)
            elif msg_type == "response":
                self._handle_response(payload)
            elif msg_type == "status":
                status_msg = payload.get("message", "")
                self._status_messages.append(status_msg)
                if self.verbose:
                    console.print(f"[dim]  hook: {status_msg}[/]")
            elif msg_type == "error":
                if self.verbose:
                    console.print(
                        f"[yellow]  hook error ({payload.get('id', '?')}):[/] "
                        f"{payload.get('message', '?')}"
                    )
        elif message.get("type") == "error":
            desc = message.get("description", "Unknown error")
            stack = message.get("stack", "")
            if self.verbose:
                console.print(f"[red]Script error:[/] {desc}")
                if stack:
                    console.print(f"[dim]{stack}[/]")

    def _handle_request(self, payload: Dict[str, Any]) -> None:
        """Process a captured request message."""
        url = payload.get("url", "")

        # Apply host filter
        if self.filter_host:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            if self.filter_host not in (parsed.hostname or ""):
                return

        req = HttpRequest(
            url=url,
            method=payload.get("method", "GET"),
            headers=payload.get("headers", {}),
            body=payload.get("body"),
            timestamp=payload.get("timestamp", time.time() * 1000),
        )

        source = payload.get("_source", "")
        self.buffer.add_request(payload["id"], req, source=source)

        if self.verbose:
            console.print(f"  [cyan]{req.method}[/] {_truncate(req.url, 100)}")

    def _handle_response(self, payload: Dict[str, Any]) -> None:
        """Process a captured response message."""
        # Check if the corresponding request was filtered out
        exchange = self.buffer.get_exchange(payload.get("id", ""))
        if exchange is None and self.filter_host:
            # Request was filtered — skip response too
            return

        resp = HttpResponse(
            status_code=payload.get("statusCode", 0),
            status_text=payload.get("statusText", ""),
            headers=payload.get("headers", {}),
            body=payload.get("body"),
            timestamp=payload.get("timestamp", time.time() * 1000),
            timing=payload.get("timing", {}),
            error=payload.get("error"),
        )

        self.buffer.add_response(payload["id"], resp)

        if self.verbose:
            code = resp.status_code
            style = (
                "green"
                if 200 <= code < 300
                else "yellow"
                if 300 <= code < 400
                else "red"
            )
            console.print(f"  [{style}]{code}[/{style}] ← {payload.get('id', '?')}")

    def start(self, timeout: int = 0, output_path: Optional[Path] = None) -> None:
        """Start the capture session.

        Args:
            timeout: Seconds to capture. 0 means run until Ctrl+C.
            output_path: Where to save the HAR file (used in status display).
        """
        self._connect_device()
        self._spawn_or_attach()
        self._inject_hooks()

        self._running = True

        console.print(f"\n[bold green]Capturing traffic from {self.package_name}[/]")
        if self.filter_host:
            console.print(f"[dim]Filtering: only requests to {self.filter_host}[/]")
        console.print("[dim]Press Ctrl+C to stop and save.[/]\n")

        # Set up signal handler for graceful shutdown
        original_sigint = signal.getsignal(signal.SIGINT)

        def _signal_handler(sig, frame):
            self._running = False
            signal.signal(signal.SIGINT, original_sigint)

        signal.signal(signal.SIGINT, _signal_handler)

        # Run the capture loop with live progress display
        try:
            if self.verbose:
                # In verbose mode, just wait — messages are printed as they arrive
                self._wait_loop(timeout)
            else:
                # Show a live counter
                self._live_progress_loop(timeout, output_path)
        except KeyboardInterrupt:
            self._running = False

    def _wait_loop(self, timeout: int) -> None:
        """Simple wait loop for verbose mode."""
        start_time = time.time()
        while self._running:
            time.sleep(0.2)
            if timeout > 0 and (time.time() - start_time) >= timeout:
                break

    def _live_progress_loop(self, timeout: int, output_path: Optional[Path]) -> None:
        """Wait loop with a Rich Live progress display."""
        start_time = time.time()

        with Live(console=console, refresh_per_second=4) as live:
            while self._running:
                elapsed = int(time.time() - start_time)
                total = self.buffer.count
                complete = self.buffer.complete_count

                # Build status table
                table = Table(show_header=False, box=None, padding=(0, 2))
                table.add_column(style="bold")
                table.add_column()

                table.add_row("Requests captured:", f"[cyan]{total}[/]")
                table.add_row("Complete pairs:", f"[green]{complete}[/]")
                table.add_row("Elapsed:", f"[dim]{elapsed}s[/]")
                if timeout > 0:
                    remaining = max(0, timeout - elapsed)
                    table.add_row("Remaining:", f"[dim]{remaining}s[/]")
                if output_path:
                    table.add_row("Output:", f"[dim]{output_path}[/]")

                # Show last few exchanges
                latest = self.buffer.latest(3)
                if latest:
                    table.add_row("", "")
                    table.add_row("[dim]Recent:", "")
                    for ex in latest:
                        if ex.request:
                            status = ""
                            if ex.response:
                                code = ex.response.status_code
                                style = (
                                    "green"
                                    if 200 <= code < 300
                                    else "yellow"
                                    if 300 <= code < 400
                                    else "red"
                                )
                                status = f" [{style}]{code}[/{style}]"
                            table.add_row(
                                "",
                                f"[cyan]{ex.request.method}[/] "
                                f"{_truncate(ex.request.url, 70)}{status}",
                            )

                live.update(table)

                time.sleep(0.25)
                if timeout > 0 and elapsed >= timeout:
                    break

    def stop(self, output_path: Optional[Path] = None) -> None:
        """Stop the capture session, detach, and save collected data."""
        self._running = False

        # Unload scripts
        for script in self._scripts:
            try:
                script.unload()
            except Exception:
                pass
        self._scripts.clear()

        # Detach session
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

        # Save results
        exchanges = self.buffer.all_exchanges()

        if not exchanges:
            console.print("\n[yellow]No HTTP traffic captured.[/]")
            return

        console.print(
            f"\n[bold]Captured {len(exchanges)} exchanges[/] "
            f"({self.buffer.complete_count} complete pairs)"
        )

        if output_path:
            try:
                save_har(exchanges, output_path)
                console.print(f"[green]Saved to:[/] {output_path}")
            except Exception as exc:
                console.print(f"[bold red]Error saving HAR:[/] {exc}")
                # Try emergency save
                emergency_path = Path(f"apktap_emergency_{int(time.time())}.har")
                try:
                    save_har(exchanges, emergency_path)
                    console.print(f"[yellow]Emergency save:[/] {emergency_path}")
                except Exception:
                    console.print("[bold red]Could not save captured data.[/]")

        if self.verbose:
            console.print("\n[dim]Exchange summary:[/]")
            for ex in exchanges[:20]:
                console.print(format_exchange(ex))
            if len(exchanges) > 20:
                console.print(f"[dim]  ... and {len(exchanges) - 20} more[/]")


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string with ellipsis if too long."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."
