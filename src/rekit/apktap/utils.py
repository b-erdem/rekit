"""
utils.py — Shared utilities for apktap.

Device detection, library detection, hook selection, and formatting helpers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from rekit.apktap.capture import Exchange

console = Console(stderr=True)

HOOKS_DIR = Path(__file__).parent / "hooks"

# Mapping from detected class/library names to hook script filenames
LIBRARY_HOOK_MAP = {
    "okhttp3": "okhttp.js",
    "okhttp": "okhttp.js",
    "com.squareup.okhttp": "okhttp.js",
    "retrofit2": "okhttp.js",  # Retrofit uses OkHttp under the hood
    "java.net.HttpURLConnection": "urlconnection.js",
    "javax.net.ssl.HttpsURLConnection": "urlconnection.js",
    "android.webkit.WebView": "webview.js",
    "android.webkit.WebViewClient": "webview.js",
    "libflutter.so": "dio.js",
    "io.flutter": "dio.js",
    "dart": "dio.js",
}


def detect_http_libraries(device: Any, pid: int) -> List[str]:
    """Detect which HTTP libraries an Android app has loaded.

    Uses Frida to enumerate loaded classes and modules, then checks
    for known HTTP library signatures.

    Args:
        device: A connected Frida device object.
        pid: Process ID of the target app.

    Returns:
        List of detected library identifiers (e.g., ["okhttp3", "android.webkit.WebView"]).
    """
    detected = []

    try:
        session = device.attach(pid)
        script = session.create_script(
            """
            (function() {
                var found = [];

                // Check Java classes
                Java.perform(function() {
                    var classChecks = [
                        "okhttp3.OkHttpClient",
                        "okhttp3.Request",
                        "com.squareup.okhttp.OkHttpClient",
                        "retrofit2.Retrofit",
                        "java.net.HttpURLConnection",
                        "android.webkit.WebView",
                        "android.webkit.WebViewClient",
                    ];

                    for (var i = 0; i < classChecks.length; i++) {
                        try {
                            Java.use(classChecks[i]);
                            found.push(classChecks[i]);
                        } catch (e) {
                            // Class not loaded
                        }
                    }
                });

                // Check native modules for Flutter
                var modules = Process.enumerateModules();
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].name === "libflutter.so") {
                        found.push("libflutter.so");
                        break;
                    }
                }

                send(found);
            })();
            """
        )

        result = []
        event = __import__("threading").Event()

        def on_message(message, data):
            if message.get("type") == "send":
                result.extend(message.get("payload", []))
            event.set()

        script.on("message", on_message)
        script.load()
        event.wait(timeout=5)
        script.unload()
        session.detach()

        # Normalize: map full class names to library identifiers
        seen = set()
        for cls in result:
            if "okhttp3" in cls or "okhttp" in cls.lower():
                if "okhttp3" not in seen:
                    detected.append("okhttp3")
                    seen.add("okhttp3")
            elif "retrofit2" in cls:
                if "okhttp3" not in seen:
                    detected.append("okhttp3")
                    seen.add("okhttp3")
            elif "HttpURLConnection" in cls:
                if "java.net.HttpURLConnection" not in seen:
                    detected.append("java.net.HttpURLConnection")
                    seen.add("java.net.HttpURLConnection")
            elif "WebView" in cls:
                if "android.webkit.WebView" not in seen:
                    detected.append("android.webkit.WebView")
                    seen.add("android.webkit.WebView")
            elif "libflutter" in cls:
                if "libflutter.so" not in seen:
                    detected.append("libflutter.so")
                    seen.add("libflutter.so")

    except Exception as exc:
        console.print(f"[dim]Library detection failed: {exc}[/]")

    return detected


def get_hooks_for_libraries(libraries: List[str]) -> List[str]:
    """Return the appropriate hook script filenames for detected libraries.

    Args:
        libraries: List of library identifiers from detect_http_libraries().

    Returns:
        Deduplicated list of hook script filenames to inject.
    """
    hooks = []
    seen = set()

    for lib in libraries:
        # Try exact match first, then prefix match
        hook = LIBRARY_HOOK_MAP.get(lib)
        if not hook:
            for key, val in LIBRARY_HOOK_MAP.items():
                if key in lib or lib in key:
                    hook = val
                    break

        if hook and hook not in seen:
            hooks.append(hook)
            seen.add(hook)

    return hooks


def check_frida_server(device: Any) -> bool:
    """Verify that frida-server is running on the device.

    Attempts to enumerate processes as a connectivity check.
    If it fails, prints a helpful error message with fix instructions.

    Args:
        device: A connected Frida device object.

    Returns:
        True if frida-server is reachable, False otherwise.
    """
    try:
        # Enumerating processes requires frida-server to be running
        processes = device.enumerate_processes()
        if not processes:
            raise RuntimeError("No processes found")
        return True
    except Exception as exc:
        error_str = str(exc).lower()

        if "unable to connect" in error_str or "closed" in error_str:
            console.print(
                "[bold red]Error:[/] Cannot connect to frida-server on device.\n\n"
                "[bold]To fix:[/]\n"
                "  1. Download the correct frida-server for your device architecture:\n"
                "     [cyan]https://github.com/frida/frida/releases[/]\n\n"
                "  2. Push it to the device:\n"
                "     [dim]adb push frida-server /data/local/tmp/[/]\n"
                "     [dim]adb shell chmod 755 /data/local/tmp/frida-server[/]\n\n"
                "  3. Start it (as root):\n"
                "     [dim]adb shell su -c /data/local/tmp/frida-server &[/]\n\n"
                "  [dim]Or use Magisk frida-server module for persistent setup.[/]"
            )
        else:
            console.print(
                f"[bold red]Error:[/] Frida server check failed: {exc}\n\n"
                "Make sure frida-server is running on the device:\n"
                "  [dim]adb shell su -c /data/local/tmp/frida-server &[/]"
            )

        return False


def format_exchange(exchange: "Exchange") -> str:
    """Pretty-print a single exchange for verbose/summary output.

    Args:
        exchange: An Exchange object with optional request and response.

    Returns:
        A formatted string suitable for console output.
    """
    parts = []

    if exchange.request:
        req = exchange.request
        url = req.url
        if len(url) > 80:
            url = url[:77] + "..."
        parts.append(f"  [cyan]{req.method:<7}[/] {url}")

        # Show content-type if present
        ct = req.headers.get("Content-Type", req.headers.get("content-type", ""))
        if ct:
            parts[-1] += f"  [dim]({ct})[/]"
    else:
        parts.append("  [dim](no request)[/]")

    if exchange.response:
        resp = exchange.response
        code = resp.status_code
        if 200 <= code < 300:
            style = "green"
        elif 300 <= code < 400:
            style = "yellow"
        elif code >= 400:
            style = "red"
        else:
            style = "dim"

        size_str = ""
        if resp.body:
            if isinstance(resp.body, str):
                size_str = f" ({len(resp.body)} chars)"
            elif isinstance(resp.body, dict) and resp.body.get("size"):
                size_str = f" ({resp.body['size']} bytes)"

        timing_str = ""
        if resp.timing and resp.timing.get("durationMs"):
            timing_str = f" [{resp.timing['durationMs']}ms]"

        parts.append(
            f"          [{style}]{code} {resp.status_text}[/{style}]{size_str}{timing_str}"
        )

        if resp.error:
            parts.append(f"          [red]Error: {resp.error}[/]")
    else:
        parts.append("          [dim](no response)[/]")

    return "\n".join(parts)
