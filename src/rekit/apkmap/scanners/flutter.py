"""
Flutter / Dart HTTP scanner.

Dart code in APKs is usually compiled to native, so full Dart source is rarely
available.  However:
  - Some Flutter apps bundle Dart source or kernel snapshots in assets.
  - jadx can extract string constants that contain URLs from ``libapp.so``.
  - Resource/asset files may contain configuration with base URLs.

This scanner searches for:
  - ``http.get()``, ``http.post()``, ``Dio()`` patterns
  - ``Uri.parse()``, ``HttpClient()`` usage
  - Interceptor wrappers (``InterceptorsWrapper``, ``onRequest``, ``onResponse``)
  - Base URL configurations and string constants matching URL patterns
  - Header configurations in Dart source or extracted strings
"""

from __future__ import annotations

import re
from pathlib import Path

from rekit.apkmap.scanners.base import (
    AuthPattern,
    EndpointInfo,
    InterceptorInfo,
    Scanner,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Dart http calls: http.get(...), http.post(...), etc.
_DART_HTTP_RE = re.compile(
    r"(?:http|client|_client)\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*"
    r"(?:Uri\.parse\s*\(\s*)?"
    r"['\"]?(https?://[^'\")\s]+)['\"]?",
    re.IGNORECASE,
)

# Dio().get("/path"), dio.post("/path"), etc.
_DIO_CALL_RE = re.compile(
    r"(?:dio|_dio|Dio\(\))\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*"
    r"['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# Dio base URL: BaseOptions(baseUrl: "https://...")
_DIO_BASE_OPTIONS_RE = re.compile(
    r'BaseOptions\s*\([^)]*baseUrl\s*:\s*["\']([^"\']+)["\']',
    re.DOTALL,
)

# Uri.parse("https://...")
_URI_PARSE_RE = re.compile(
    r'Uri\.parse\s*\(\s*["\']?(https?://[^"\')\s]+)["\']?',
)

# HttpClient() direct usage
_HTTP_CLIENT_RE = re.compile(
    r'HttpClient\(\)\s*(?:.*?\.)*(openUrl|getUrl|postUrl)\s*\(\s*["\']?(https?://[^"\')\s]+)',
    re.DOTALL,
)

# InterceptorsWrapper / interceptor configuration
_INTERCEPTOR_WRAPPER_RE = re.compile(
    r"InterceptorsWrapper\s*\(",
    re.MULTILINE,
)

# onRequest / onResponse / onError handlers
_INTERCEPTOR_HANDLER_RE = re.compile(
    r"(onRequest|onResponse|onError)\s*:\s*\(",
)

# Dio interceptor add: dio.interceptors.add(...)
_DIO_INTERCEPTOR_ADD_RE = re.compile(
    r"(?:dio|_dio)\.interceptors\.add\s*\(\s*(?:new\s+)?(\w+)",
)

# Header map patterns in Dart: {"Authorization": "Bearer ...", ...}
_DART_HEADER_MAP_RE = re.compile(
    r'["\']?(Authorization|X-Api-Key|x-api-key|Content-Type|Accept|User-Agent)["\']?\s*:\s*["\']([^"\']+)["\']',
)

# headers: {"Key": "Value"} in Dio Options
_DIO_HEADERS_RE = re.compile(
    r"headers\s*:\s*\{([^}]+)\}",
)

# String constants that look like API URLs (in extracted strings or Dart source)
_URL_CONSTANT_RE = re.compile(
    r"(?:https?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d+)?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*))",
)

# API path segments in URLs
_API_PATH_RE = re.compile(
    r"(?:https?://[^/]+)?(/(?:api|v[0-9]+|graphql|rest|mobile|app)/[a-zA-Z0-9._/-]*)",
)


class FlutterScanner(Scanner):
    """Scan for Flutter/Dart HTTP patterns in decompiled source and assets."""

    name = "flutter"

    def scan(self, source_dir: Path) -> ScanResult:
        result = ScanResult()

        # Scan Dart source files (if any exist)
        dart_files = list(source_dir.rglob("*.dart"))
        for fpath in dart_files:
            self._scan_dart_file(fpath, source_dir, result)

        # Scan extracted strings from native libs and assets
        # jadx sometimes puts string resources in res/ and smali/
        asset_dirs = [
            source_dir / "assets",
            source_dir / "res",
        ]
        for adir in asset_dirs:
            if adir.is_dir():
                for fpath in adir.rglob("*"):
                    if fpath.is_file() and fpath.stat().st_size < 5_000_000:
                        self._scan_text_file(fpath, source_dir, result)

        # Also scan smali files for string constants with URLs
        for fpath in source_dir.rglob("*.smali"):
            self._scan_smali_for_urls(fpath, source_dir, result)

        # Scan Java/Kotlin files that might be Flutter plugin bridges
        for pattern in ("**/flutter/**/*.java", "**/flutter/**/*.kt"):
            for fpath in source_dir.glob(pattern):
                self._scan_dart_file(fpath, source_dir, result)

        return result

    def _scan_dart_file(
        self, fpath: Path, source_dir: Path, result: ScanResult
    ) -> None:
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            return

        rel = str(fpath.relative_to(source_dir))

        # HTTP calls
        for m in _DART_HTTP_RE.finditer(text):
            method = m.group(1).upper()
            url = m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=url,
                    annotation_source=f"{rel}:{line_no}",
                )
            )

        # Dio calls
        for m in _DIO_CALL_RE.finditer(text):
            method = m.group(1).upper()
            path = m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=path,
                    annotation_source=f"{rel}:{line_no}",
                )
            )

        # Base URLs
        for m in _DIO_BASE_OPTIONS_RE.finditer(text):
            url = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            result.base_urls.append({"url": url, "source": f"{rel}:{line_no}"})

        for m in _URI_PARSE_RE.finditer(text):
            url = m.group(1)
            if _is_api_url(url):
                line_no = text[: m.start()].count("\n") + 1
                result.base_urls.append({"url": url, "source": f"{rel}:{line_no}"})

        # Interceptors
        for m in _INTERCEPTOR_WRAPPER_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            chunk = text[m.start() : m.start() + 1500]
            snippet = "\n".join(chunk.split("\n")[:10])
            result.interceptors.append(
                InterceptorInfo(
                    name="InterceptorsWrapper",
                    type="custom",
                    source_file=f"{rel}:{line_no}",
                    code_snippet=snippet,
                )
            )

        for m in _DIO_INTERCEPTOR_ADD_RE.finditer(text):
            name = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            result.interceptors.append(
                InterceptorInfo(
                    name=name,
                    type="custom",
                    source_file=f"{rel}:{line_no}",
                )
            )

        # Auth patterns in headers
        for m in _DART_HEADER_MAP_RE.finditer(text):
            header_name = m.group(1)
            header_value = m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            if header_name.lower() == "authorization":
                if "bearer" in header_value.lower():
                    result.auth_patterns.append(
                        AuthPattern(
                            type="bearer",
                            header_name="Authorization",
                            source_description="Bearer token in Dart source",
                            code_snippet=text[m.start() : m.end()],
                            source_file=f"{rel}:{line_no}",
                        )
                    )
                elif "basic" in header_value.lower():
                    result.auth_patterns.append(
                        AuthPattern(
                            type="basic",
                            header_name="Authorization",
                            source_description="Basic auth in Dart source",
                            code_snippet=text[m.start() : m.end()],
                            source_file=f"{rel}:{line_no}",
                        )
                    )
            elif header_name.lower() in ("x-api-key",):
                result.auth_patterns.append(
                    AuthPattern(
                        type="api_key",
                        header_name=header_name,
                        source_description="API key header in Dart source",
                        code_snippet=text[m.start() : m.end()],
                        source_file=f"{rel}:{line_no}",
                    )
                )

    def _scan_text_file(
        self, fpath: Path, source_dir: Path, result: ScanResult
    ) -> None:
        """Scan asset/resource text files for URL patterns."""
        try:
            text = fpath.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return

        rel = str(fpath.relative_to(source_dir))

        for m in _URL_CONSTANT_RE.finditer(text):
            url = m.group(0)
            if _is_api_url(url):
                line_no = text[: m.start()].count("\n") + 1
                result.base_urls.append({"url": url, "source": f"{rel}:{line_no}"})

    def _scan_smali_for_urls(
        self, fpath: Path, source_dir: Path, result: ScanResult
    ) -> None:
        """Extract URL string constants from smali files."""
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            return

        rel = str(fpath.relative_to(source_dir))

        for m in _URL_CONSTANT_RE.finditer(text):
            url = m.group(0)
            if _is_api_url(url):
                line_no = text[: m.start()].count("\n") + 1
                result.base_urls.append({"url": url, "source": f"{rel}:{line_no}"})


def _is_api_url(url: str) -> bool:
    """Heuristic: is this URL likely an API endpoint rather than a resource?"""
    lowered = url.lower()
    # Skip common non-API URLs
    skip_domains = (
        "schemas.android.com",
        "www.w3.org",
        "ns.adobe.com",
        "play.google.com",
        "developer.android.com",
        "fonts.googleapis.com",
        "schemas.microsoft.com",
        "xml.org",
        "xmlns.com",
        "github.com",
        "stackoverflow.com",
    )
    for d in skip_domains:
        if d in lowered:
            return False
    # Skip file extensions that indicate static resources
    skip_extensions = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".css",
        ".js",
        ".woff",
        ".ttf",
        ".eot",
    )
    for ext in skip_extensions:
        if lowered.endswith(ext):
            return False
    # Positive signals
    if _API_PATH_RE.search(url):
        return True
    if any(
        seg in lowered for seg in ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest")
    ):
        return True
    return True  # Default: include it, generic scanner will deduplicate
