"""
Generic catch-all scanner.

Sweeps decompiled source for:
  - URL-like strings
  - Common API path patterns (``/api/``, ``/v1/``, ``/graphql``)
  - JSON field-name patterns suggesting API models
  - Common auth patterns (``Bearer``, ``Basic``, ``x-api-key``, ``Authorization``)
  - ``SharedPreferences`` keys that may store tokens
  - Certificate pinning patterns
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from rekit.apkmap.scanners.base import (
    AuthPattern,
    EndpointInfo,
    ModelInfo,
    FieldInfo,
    Scanner,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Generic URL pattern
_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d{1,5})?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*)?",
)

# API path segments
_API_PATH_RE = re.compile(
    r'(?:https?://[^/\s"\']+)?(/(?:api|v[0-9]+|graphql|rest|mobile|app|service|services|backend|rpc)/[a-zA-Z0-9._/{}-]*)',
)

# Auth header patterns
_BEARER_RE = re.compile(r'["\']Bearer\s+', re.IGNORECASE)
_BASIC_AUTH_RE = re.compile(r'["\']Basic\s+', re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r'["\']?(Authorization|X-Api-Key|x-api-key|X-API-KEY|api[_-]?key|x-auth-token|X-Auth-Token)["\']?\s*[,:=]',
    re.IGNORECASE,
)

# SharedPreferences token keys
_SHARED_PREFS_RE = re.compile(
    r'(?:getString|putString|edit\(\)\.putString)\s*\(\s*["\']'
    r'((?:access_token|refresh_token|auth_token|api_key|session_id|jwt|token|bearer|id_token|secret_key)[^"\']*)'
    r'["\']',
    re.IGNORECASE,
)

# Certificate pinning patterns
_CERT_PIN_PATTERNS = [
    re.compile(r"CertificatePinner", re.IGNORECASE),
    re.compile(r"X509TrustManager"),
    re.compile(r"TrustManagerFactory"),
    re.compile(r"\.sslSocketFactory\s*\("),
    re.compile(r"network_security_config", re.IGNORECASE),
    re.compile(r"pin-set", re.IGNORECASE),
    re.compile(r"sha256/[A-Za-z0-9+/=]{20,}"),
]

# JSON model-like patterns: classes with @SerializedName, @Json, @JsonProperty
_SERIALIZED_NAME_RE = re.compile(
    r'@(?:SerializedName|Json(?:Property)?|JsonField|Expose)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
)

# Data class pattern (Kotlin): data class Foo(val bar: String, ...)
_DATA_CLASS_RE = re.compile(
    r"data\s+class\s+(\w+)\s*\(([^)]+)\)",
    re.MULTILINE,
)

# Kotlin field in data class: val fieldName: Type
_KOTLIN_FIELD_RE = re.compile(
    r"(?:val|var)\s+(\w+)\s*:\s*([\w<>,?\s]+)",
)

# Java POJO field with @SerializedName
_JAVA_FIELD_RE = re.compile(
    r'@SerializedName\s*\(\s*["\']([^"\']+)["\']\s*\)\s*'
    r"(?:private|public|protected)?\s*"
    r"([\w<>,?\s]+)\s+(\w+)\s*;",
    re.MULTILINE,
)

# GraphQL query/mutation patterns
_GRAPHQL_RE = re.compile(
    r"(?:query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*\{",
)

# Domains we skip (SDKs, Android system, etc.)
_SKIP_DOMAINS: Set[str] = {
    "schemas.android.com",
    "www.w3.org",
    "ns.adobe.com",
    "play.google.com",
    "developer.android.com",
    "schemas.microsoft.com",
    "xml.org",
    "xmlns.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "crashlytics.com",
    "firebase.google.com",
    "google.com/maps",
    "maps.googleapis.com",
    "facebook.com",
    "graph.facebook.com",
    "github.com",
    "raw.githubusercontent.com",
    "stackoverflow.com",
}

_SKIP_EXTENSIONS = frozenset(
    (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".css",
        ".js",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
    )
)

# Maximum file size we will read (5 MB)
_MAX_FILE_SIZE = 5 * 1024 * 1024


class GenericScanner(Scanner):
    """Catch-all scanner for URL strings, auth patterns, and model hints."""

    name = "generic"

    def scan(self, source_dir: Path) -> ScanResult:
        result = ScanResult()
        extensions = {
            ".java",
            ".kt",
            ".smali",
            ".xml",
            ".json",
            ".dart",
            ".properties",
            ".yaml",
            ".yml",
            ".cfg",
            ".txt",
        }

        for fpath in source_dir.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in extensions:
                continue
            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            if size > _MAX_FILE_SIZE or size == 0:
                continue

            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue

            rel = str(fpath.relative_to(source_dir))
            self._find_urls(text, rel, result)
            self._find_auth_patterns(text, rel, result)
            self._find_shared_prefs_tokens(text, rel, result)
            self._find_cert_pinning(text, rel, result)

            # Only scan Java/Kotlin for models and graphql
            if fpath.suffix in (".java", ".kt"):
                self._find_models(text, rel, result)
                self._find_graphql(text, rel, result)

        return result

    # ---- URL discovery ----

    def _find_urls(self, text: str, rel_path: str, result: ScanResult) -> None:
        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:)\"'")
            if _should_skip_url(url):
                continue
            line_no = text[: m.start()].count("\n") + 1

            # Determine if this looks like an endpoint vs a base URL
            api_match = _API_PATH_RE.search(url)
            if api_match:
                result.endpoints.append(
                    EndpointInfo(
                        method="UNKNOWN",
                        path=url,
                        annotation_source=f"{rel_path}:{line_no}",
                    )
                )
            else:
                result.base_urls.append({"url": url, "source": f"{rel_path}:{line_no}"})

    # ---- Auth patterns ----

    def _find_auth_patterns(self, text: str, rel_path: str, result: ScanResult) -> None:
        for m in _BEARER_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())
            result.auth_patterns.append(
                AuthPattern(
                    type="bearer",
                    header_name="Authorization",
                    source_description="Bearer token reference",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

        for m in _BASIC_AUTH_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())
            result.auth_patterns.append(
                AuthPattern(
                    type="basic",
                    header_name="Authorization",
                    source_description="Basic auth reference",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

        for m in _AUTH_HEADER_RE.finditer(text):
            header_name = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())
            auth_type = "api_key" if "key" in header_name.lower() else "custom"
            result.auth_patterns.append(
                AuthPattern(
                    type=auth_type,
                    header_name=header_name,
                    source_description=f"Auth header {header_name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

    # ---- SharedPreferences tokens ----

    def _find_shared_prefs_tokens(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        for m in _SHARED_PREFS_RE.finditer(text):
            key_name = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())
            result.auth_patterns.append(
                AuthPattern(
                    type="custom",
                    header_name=None,
                    source_description=f"Token stored in SharedPreferences key '{key_name}'",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

    # ---- Certificate pinning ----

    def _find_cert_pinning(self, text: str, rel_path: str, result: ScanResult) -> None:
        for pat in _CERT_PIN_PATTERNS:
            for m in pat.finditer(text):
                line_no = text[: m.start()].count("\n") + 1
                snippet = _snippet_around(text, m.start())
                result.auth_patterns.append(
                    AuthPattern(
                        type="certificate",
                        header_name=None,
                        source_description=f"Certificate pinning pattern: {m.group(0)[:80]}",
                        code_snippet=snippet,
                        source_file=f"{rel_path}:{line_no}",
                    )
                )
                break  # One match per pattern per file is enough

    # ---- Model discovery ----

    def _find_models(self, text: str, rel_path: str, result: ScanResult) -> None:
        # Kotlin data classes
        for m in _DATA_CLASS_RE.finditer(text):
            class_name = m.group(1)
            body = m.group(2)
            fields: List[FieldInfo] = []
            for fm in _KOTLIN_FIELD_RE.finditer(body):
                fname = fm.group(1)
                ftype = fm.group(2).strip()
                # Look for @SerializedName on the same field
                json_name = None
                field_ctx_start = max(0, fm.start() - 80)
                field_ctx = body[field_ctx_start : fm.start()]
                sn = _SERIALIZED_NAME_RE.search(field_ctx)
                if sn:
                    json_name = sn.group(1)
                fields.append(FieldInfo(name=fname, type=ftype, json_name=json_name))

            if fields:
                result.models.append(
                    ModelInfo(name=class_name, fields=fields, source_file=rel_path)
                )

        # Java POJOs with @SerializedName
        # Group fields by enclosing class
        class_re = re.compile(
            r"class\s+(\w+)\s*(?:extends\s+\w+\s*)?(?:implements\s+[\w,\s]*?)?\s*\{"
        )
        for cm in class_re.finditer(text):
            class_name = cm.group(1)
            # Find closing brace (simple heuristic: next 5000 chars)
            class_body = text[cm.start() : cm.start() + 5000]
            fields: List[FieldInfo] = []
            for fm in _JAVA_FIELD_RE.finditer(class_body):
                json_name = fm.group(1)
                ftype = fm.group(2).strip()
                fname = fm.group(3)
                fields.append(FieldInfo(name=fname, type=ftype, json_name=json_name))
            if fields:
                result.models.append(
                    ModelInfo(name=class_name, fields=fields, source_file=rel_path)
                )

    # ---- GraphQL ----

    def _find_graphql(self, text: str, rel_path: str, result: ScanResult) -> None:
        for m in _GRAPHQL_RE.finditer(text):
            op_name = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            method = "POST"  # GraphQL typically uses POST
            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=f"/graphql#{op_name}",
                    annotation_source=f"{rel_path}:{line_no}",
                )
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _should_skip_url(url: str) -> bool:
    """Return True if the URL is from a known non-API domain or is a static resource."""
    lowered = url.lower()
    for d in _SKIP_DOMAINS:
        if d in lowered:
            return True
    for ext in _SKIP_EXTENSIONS:
        if lowered.rstrip("/").endswith(ext):
            return True
    # Skip very short URLs (likely incomplete)
    if len(url) < 12:
        return True
    return False


def _snippet_around(text: str, pos: int, context_lines: int = 3) -> str:
    """Return a few lines of context around *pos*."""
    line_start = text.rfind("\n", 0, pos)
    if line_start == -1:
        line_start = 0
    # Go back a couple more lines
    for _ in range(context_lines - 1):
        prev = text.rfind("\n", 0, line_start)
        if prev == -1:
            break
        line_start = prev

    line_end = pos
    for _ in range(context_lines):
        nxt = text.find("\n", line_end + 1)
        if nxt == -1:
            line_end = len(text)
            break
        line_end = nxt

    return text[line_start:line_end].strip()
