"""
Analyze JavaScript bundles for API endpoints, secrets, and configuration.

Uses regex-based scanning (no AST parsing) to work with minified code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from rekit.apkmap.scanners.base import (
    AuthPattern,
    EndpointInfo,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class JSAnalysis:
    """Results from analyzing a JS bundle."""

    endpoints: List[EndpointInfo] = field(default_factory=list)
    api_base_urls: List[str] = field(default_factory=list)
    auth_patterns: List[AuthPattern] = field(default_factory=list)
    hardcoded_secrets: List[Dict] = field(default_factory=list)
    graphql_operations: List[Dict] = field(default_factory=list)
    env_configs: List[Dict] = field(default_factory=list)
    fetch_calls: List[Dict] = field(default_factory=list)
    navigation_api_map: List[Dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# URL patterns
_HTTP_URL_RE = re.compile(
    r"""https?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d{1,5})?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?""",
)

_API_URL_RE = re.compile(
    r"https?://(?:api|rest|backend|gateway)[-a-zA-Z0-9.]*(?::\d{1,5})?(?:/[^\s\"'`,;)}\]]*)?",
)

_WEBSOCKET_URL_RE = re.compile(
    r"wss?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d{1,5})?(?:/[^\s\"'`,;)}\]]*)?",
)

# fetch() calls
_FETCH_RE = re.compile(
    r"""fetch\s*\(\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*\{([^}]{0,500})\})?""",
)

# axios patterns
_AXIOS_METHOD_RE = re.compile(
    r"""axios\.(?:get|post|put|delete|patch|head|options|request)\s*\(\s*["']([^"']+)["']""",
)

_AXIOS_CREATE_RE = re.compile(
    r"""axios\.create\s*\(\s*\{[^}]*?baseURL\s*:\s*["']([^"']+)["']""",
    re.DOTALL,
)

# XMLHttpRequest
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']""",
)

# Method extraction from fetch options
_METHOD_RE = re.compile(
    r"""method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']""", re.IGNORECASE
)

# Headers in fetch options
_HEADERS_RE = re.compile(r"""headers\s*:\s*\{([^}]*)\}""")
_HEADER_PAIR_RE = re.compile(r"""["']([^"']+)["']\s*:\s*["']([^"']+)["']""")

# API key / secret patterns
_API_KEY_PATTERNS = [
    # Generic key=value assignments
    re.compile(
        r"""(?:API_KEY|apiKey|api_key|SECRET_KEY|secretKey|secret_key|CLIENT_SECRET|clientSecret|client_secret|CLIENT_ID|clientId|client_id|APP_KEY|appKey|app_key|APP_SECRET|appSecret|app_secret)\s*[:=]\s*["']([^"']{8,})["']""",
    ),
    # AWS access keys
    re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""),
    # Google Maps API keys
    re.compile(r"""["'](AIza[0-9A-Za-z_-]{35})["']"""),
    # Stripe keys
    re.compile(r"""["'](sk_(?:live|test|fake)_[0-9a-zA-Z]{10,})["']"""),
    re.compile(r"""["'](pk_(?:live|test|fake)_[0-9a-zA-Z]{10,})["']"""),
    # Firebase config
    re.compile(
        r"""(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*:\s*["']([^"']{8,})["']""",
    ),
    # JWT tokens (embedded defaults)
    re.compile(
        r"""["'](eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)["']"""
    ),
    # Generic: KEY/SECRET/TOKEN/PASSWORD/CREDENTIAL with long string value
    re.compile(
        r"""(?:[\w]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[\w]*)\s*[:=]\s*["']([^"']{16,})["']""",
        re.IGNORECASE,
    ),
]

# Bearer token in headers
_BEARER_HEADER_RE = re.compile(
    r"""["']Authorization["']\s*:\s*["']Bearer\s+""",
    re.IGNORECASE,
)

_AUTH_HEADER_RE = re.compile(
    r"""["'](?:Authorization|X-Api-Key|X-API-KEY|x-api-key|X-Auth-Token|x-auth-token)["']\s*:""",
    re.IGNORECASE,
)

# GraphQL patterns
_GQL_TEMPLATE_RE = re.compile(
    r"""(?:graphql|gql)\s*`\s*((?:query|mutation|subscription)\s+(\w+)[^`]*)`""",
    re.DOTALL,
)

_GQL_STRING_RE = re.compile(
    r"""["']((?:query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*\{[^"']{10,})["']""",
)

# Environment config
_ENV_VAR_RE = re.compile(
    r"""process\.env\.(\w+)""",
)

_EXPO_CONFIG_RE = re.compile(
    r"""Constants\.expoConfig""",
)

_CONFIG_OBJECT_RE = re.compile(
    r"""(?:apiUrl|apiBaseUrl|API_URL|API_BASE_URL|baseUrl|BASE_URL|environment|ENVIRONMENT)\s*:\s*["']([^"']+)["']""",
)

# React Navigation screen names near API calls
_SCREEN_RE = re.compile(
    r"""(?:Screen|screen)\s*(?:name|:)\s*["'](\w+)["']""",
)

# Domains to skip (SDKs, well-known)
_SKIP_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "reactnative.dev",
    "facebook.com",
    "github.com",
    "npmjs.com",
    "googleapis.com/auth",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
}

_SKIP_EXTENSIONS = frozenset(
    (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ttf", ".map")
)


def _should_skip_url(url: str) -> bool:
    lowered = url.lower()
    for d in _SKIP_DOMAINS:
        if d in lowered:
            return True
    for ext in _SKIP_EXTENSIONS:
        if lowered.rstrip("/").endswith(ext):
            return True
    if len(url) < 12:
        return True
    return False


def _approx_line(content: str, pos: int) -> int:
    """Approximate line number for a position in content."""
    return content[:pos].count("\n") + 1


def _snippet(content: str, pos: int, length: int = 120) -> str:
    """Extract a short snippet around a position."""
    start = max(0, pos - 40)
    end = min(len(content), pos + length)
    return content[start:end].replace("\n", " ").strip()


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_bundle(content: str) -> JSAnalysis:
    """Analyze JavaScript bundle content for API patterns, secrets, and config."""
    result = JSAnalysis()

    _find_fetch_calls(content, result)
    _find_axios_calls(content, result)
    _find_xhr_calls(content, result)
    _find_api_urls(content, result)
    _find_websocket_urls(content, result)
    _find_auth_patterns(content, result)
    _find_secrets(content, result)
    _find_graphql(content, result)
    _find_env_config(content, result)
    _find_navigation_api_map(content, result)

    # Deduplicate base URLs
    result.api_base_urls = list(dict.fromkeys(result.api_base_urls))

    return result


def _find_fetch_calls(content: str, result: JSAnalysis) -> None:
    for m in _FETCH_RE.finditer(content):
        url = m.group(1)
        options = m.group(2) or ""

        method = "GET"
        method_match = _METHOD_RE.search(options)
        if method_match:
            method = method_match.group(1).upper()

        headers: Dict[str, str] = {}
        headers_match = _HEADERS_RE.search(options)
        if headers_match:
            for hm in _HEADER_PAIR_RE.finditer(headers_match.group(1)):
                headers[hm.group(1)] = hm.group(2)

        line = _approx_line(content, m.start())
        result.fetch_calls.append(
            {"url": url, "method": method, "headers": headers, "line_approx": line}
        )

        if not _should_skip_url(url):
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=url,
                    annotation_source=f"jsbundle:{line}",
                    headers=[{"name": k, "value": v} for k, v in headers.items()],
                )
            )


def _find_axios_calls(content: str, result: JSAnalysis) -> None:
    # axios.method() calls
    for m in _AXIOS_METHOD_RE.finditer(content):
        url = m.group(1)
        # Extract method from the matched text
        method_text = re.search(r"axios\.(\w+)", m.group(0))
        method = method_text.group(1).upper() if method_text else "GET"
        if method == "REQUEST":
            method = "GET"

        line = _approx_line(content, m.start())
        if not _should_skip_url(url):
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=url,
                    annotation_source=f"jsbundle:{line}",
                )
            )

    # axios.create({baseURL: "..."})
    for m in _AXIOS_CREATE_RE.finditer(content):
        base_url = m.group(1)
        if not _should_skip_url(base_url):
            result.api_base_urls.append(base_url)


def _find_xhr_calls(content: str, result: JSAnalysis) -> None:
    for m in _XHR_OPEN_RE.finditer(content):
        method = m.group(1).upper()
        url = m.group(2)
        line = _approx_line(content, m.start())
        if not _should_skip_url(url):
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=url,
                    annotation_source=f"jsbundle:{line}",
                )
            )


def _find_api_urls(content: str, result: JSAnalysis) -> None:
    """Find API-like URLs not already captured by fetch/axios scanning."""
    existing_urls = {ep.path for ep in result.endpoints}
    existing_urls.update(result.api_base_urls)

    for m in _API_URL_RE.finditer(content):
        url = m.group(0).rstrip(".,;:)\"'`")
        if url in existing_urls or _should_skip_url(url):
            continue
        existing_urls.add(url)
        result.api_base_urls.append(url)

    # Also find general HTTP URLs that look like APIs (have path segments)
    for m in _HTTP_URL_RE.finditer(content):
        url = m.group(0).rstrip(".,;:)\"'`")
        if url in existing_urls or _should_skip_url(url):
            continue
        # Only include if it has path segments suggesting an API
        if re.search(
            r"/(?:api|v\d+|graphql|rest|mobile|app|service|backend|rpc)/", url
        ):
            existing_urls.add(url)
            line = _approx_line(content, m.start())
            result.endpoints.append(
                EndpointInfo(
                    method="UNKNOWN",
                    path=url,
                    annotation_source=f"jsbundle:{line}",
                )
            )


def _find_websocket_urls(content: str, result: JSAnalysis) -> None:
    for m in _WEBSOCKET_URL_RE.finditer(content):
        url = m.group(0).rstrip(".,;:)\"'`")
        if _should_skip_url(url):
            continue
        line = _approx_line(content, m.start())
        result.endpoints.append(
            EndpointInfo(
                method="WS",
                path=url,
                annotation_source=f"jsbundle:{line}",
            )
        )


def _find_auth_patterns(content: str, result: JSAnalysis) -> None:
    for m in _BEARER_HEADER_RE.finditer(content):
        line = _approx_line(content, m.start())
        snip = _snippet(content, m.start())
        result.auth_patterns.append(
            AuthPattern(
                type="bearer",
                header_name="Authorization",
                source_description="Bearer token in headers",
                code_snippet=snip,
                source_file=f"jsbundle:{line}",
            )
        )

    for m in _AUTH_HEADER_RE.finditer(content):
        # Avoid double-counting Bearer patterns
        snip = _snippet(content, m.start())
        if "Bearer" in snip:
            continue
        header = m.group(0).strip("\"': ")
        line = _approx_line(content, m.start())
        auth_type = "api_key" if "key" in header.lower() else "custom"
        result.auth_patterns.append(
            AuthPattern(
                type=auth_type,
                header_name=header,
                source_description=f"Auth header {header}",
                code_snippet=snip,
                source_file=f"jsbundle:{line}",
            )
        )


def _find_secrets(content: str, result: JSAnalysis) -> None:
    seen_values: set[str] = set()

    for pattern in _API_KEY_PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(1)
            if value in seen_values:
                continue
            seen_values.add(value)

            # Find the key name from context
            ctx_start = max(0, m.start() - 60)
            context = content[ctx_start : m.end()]
            key_match = re.search(
                r"(\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|apiKey|api_key|"
                r"clientSecret|client_secret|CLIENT_ID|clientId|appId|"
                r"authDomain|databaseURL|projectId|storageBucket|"
                r"messagingSenderId|measurementId)\w*)",
                context,
                re.IGNORECASE,
            )
            key = key_match.group(1) if key_match else "UNKNOWN_KEY"
            line = _approx_line(content, m.start())

            result.hardcoded_secrets.append(
                {
                    "key": key,
                    "value": value,
                    "context": _snippet(content, m.start()),
                    "line_approx": line,
                }
            )


def _find_graphql(content: str, result: JSAnalysis) -> None:
    seen_names: set[str] = set()

    # Template literal GraphQL
    for m in _GQL_TEMPLATE_RE.finditer(content):
        body = m.group(1).strip()
        name = m.group(2)
        if name in seen_names:
            continue
        seen_names.add(name)

        # Determine type
        op_type = "query"
        if body.startswith("mutation"):
            op_type = "mutation"
        elif body.startswith("subscription"):
            op_type = "subscription"

        result.graphql_operations.append({"name": name, "type": op_type, "body": body})

    # String-based GraphQL
    for m in _GQL_STRING_RE.finditer(content):
        body = m.group(1).strip()
        name = m.group(2)
        if name in seen_names:
            continue
        seen_names.add(name)

        op_type = "query"
        if body.startswith("mutation"):
            op_type = "mutation"
        elif body.startswith("subscription"):
            op_type = "subscription"

        result.graphql_operations.append({"name": name, "type": op_type, "body": body})


def _find_env_config(content: str, result: JSAnalysis) -> None:
    seen_keys: set[str] = set()

    # process.env.*
    for m in _ENV_VAR_RE.finditer(content):
        key = m.group(1)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Try to find a default value nearby
        ctx = content[m.start() : min(len(content), m.end() + 100)]
        val_match = re.search(r"""\|\|\s*["']([^"']+)["']""", ctx)
        value = val_match.group(1) if val_match else ""
        result.env_configs.append({"key": key, "value": value})

    # Config object patterns
    for m in _CONFIG_OBJECT_RE.finditer(content):
        value = m.group(1)
        # Derive key from the match
        key_match = re.search(r"(\w+)\s*:", m.group(0))
        key = key_match.group(1) if key_match else "config"
        full_key = f"config.{key}"
        if full_key not in seen_keys:
            seen_keys.add(full_key)
            result.env_configs.append({"key": key, "value": value})


def _find_navigation_api_map(content: str, result: JSAnalysis) -> None:
    """Try to associate React Navigation screens with nearby API calls."""
    screens = list(_SCREEN_RE.finditer(content))
    if not screens:
        return

    endpoint_urls = [ep.path for ep in result.endpoints]
    if not endpoint_urls:
        return

    for sm in screens:
        screen_name = sm.group(1)
        # Look in a window around the screen definition for API URLs
        window_start = max(0, sm.start() - 500)
        window_end = min(len(content), sm.end() + 2000)
        window = content[window_start:window_end]

        nearby_endpoints: list[str] = []
        for url in endpoint_urls:
            if url in window:
                nearby_endpoints.append(url)

        if nearby_endpoints:
            result.navigation_api_map.append(
                {"screen": screen_name, "endpoints": nearby_endpoints}
            )


# ---------------------------------------------------------------------------
# File-level entry points
# ---------------------------------------------------------------------------


def analyze_bundle_file(path: Path) -> JSAnalysis:
    """Read a JS bundle file and analyze it."""
    content = path.read_text(errors="replace")
    return analyze_bundle(content)


def merge_with_apkmap(js_analysis: JSAnalysis, scan_result: ScanResult) -> ScanResult:
    """Merge JS analysis results into an apkmap ScanResult, deduplicating endpoints."""
    seen_keys = {e._key() for e in scan_result.endpoints}

    for ep in js_analysis.endpoints:
        if ep._key() not in seen_keys:
            scan_result.endpoints.append(ep)
            seen_keys.add(ep._key())

    seen_urls = {u.get("url") for u in scan_result.base_urls}
    for url in js_analysis.api_base_urls:
        if url not in seen_urls:
            scan_result.base_urls.append({"url": url, "source": "jsbundle"})
            seen_urls.add(url)

    seen_auth = {(a.type, a.header_name) for a in scan_result.auth_patterns}
    for auth in js_analysis.auth_patterns:
        key = (auth.type, auth.header_name)
        if key not in seen_auth:
            scan_result.auth_patterns.append(auth)
            seen_auth.add(key)

    return scan_result


def mask_secret(value: str) -> str:
    """Mask a secret value, showing only first 4 and last 4 characters."""
    if len(value) <= 10:
        return value[:2] + "*" * (len(value) - 2)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]
