"""
OkHttp direct-usage scanner.

Finds ``OkHttpClient.Builder()`` chains, ``Request.Builder()`` patterns,
``newCall()`` invocations, URL/header extraction from builder chains,
and classes implementing the ``Interceptor`` interface.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

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

# Request.Builder().url("...").method("POST", body).header("K", "V")
_REQUEST_BUILDER_RE = re.compile(
    r'(?:new\s+)?Request\.Builder\(\)',
    re.MULTILINE,
)

# .url("https://...") or .url(variable)
_URL_CALL_RE = re.compile(
    r'\.url\s*\(\s*"(https?://[^"]+)"\s*\)',
)

# .url(variable) — capture variable name
_URL_VAR_RE = re.compile(
    r'\.url\s*\(\s*(\w+)\s*\)',
)

# .header("Name", "Value") / .addHeader("Name", "Value")
_HEADER_CALL_RE = re.compile(
    r'\.\s*(?:addHeader|header)\s*\(\s*"([^"]*)"\s*,\s*([^)]+)\)',
)

# .method("POST", ...) or .post(body) / .get() / .put(body) / .delete(body)
_METHOD_CALL_RE = re.compile(
    r'\.(?:method\s*\(\s*"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"'
    r'|'
    r'(get|post|put|delete|patch|head)\s*\()',
    re.IGNORECASE,
)

# OkHttpClient.Builder() chain — look for addInterceptor / addNetworkInterceptor
_CLIENT_BUILDER_RE = re.compile(
    r'OkHttpClient\.Builder\(\)',
)

_ADD_INTERCEPTOR_RE = re.compile(
    r'\.add(?:Network)?Interceptor\s*\(\s*(?:new\s+)?(\w+)',
)

# newCall(request).execute() or enqueue()
_NEW_CALL_RE = re.compile(
    r'\.newCall\s*\(\s*(\w+)\s*\)\s*\.\s*(execute|enqueue)',
)

# Interceptor class declaration (Java)
_INTERCEPTOR_IMPL_RE = re.compile(
    r'class\s+(\w+)\s+implements\s+[\w,\s]*Interceptor',
)

# Interceptor class declaration (Kotlin)
_INTERCEPTOR_IMPL_KOTLIN_RE = re.compile(
    r'class\s+(\w+)\s*(?:\([^)]*\))?\s*:\s*[\w,\s]*Interceptor',
)

# CertificatePinner.Builder()
_CERT_PINNER_RE = re.compile(
    r'CertificatePinner\.Builder\(\)',
)

# .add("hostname", "sha256/...")
_CERT_PIN_ADD_RE = re.compile(
    r'\.add\s*\(\s*"([^"]*)"\s*,\s*"(sha256/[^"]*)"\s*\)',
)


class OkHttpScanner(Scanner):
    """Scan for direct OkHttp usage patterns in decompiled source."""

    name = "okhttp"

    def scan(self, source_dir: Path) -> ScanResult:
        result = ScanResult()

        for fpath in _java_kotlin_files(source_dir):
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue

            # Quick relevance check — skip files with no OkHttp references
            if "okhttp" not in text.lower() and "OkHttp" not in text and "Request.Builder" not in text:
                continue

            rel = str(fpath.relative_to(source_dir))
            self._scan_request_builders(text, rel, result)
            self._scan_client_builders(text, rel, result)
            self._scan_interceptor_classes(text, rel, result)
            self._scan_cert_pinning(text, rel, result)

        return result

    # ---- private helpers ----

    def _scan_request_builders(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        """Find Request.Builder() blocks and extract endpoints."""
        for m in _REQUEST_BUILDER_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            # Grab the builder chain (up to ~800 chars or closing semicolon)
            chain_end = min(m.start() + 800, len(text))
            semi = text.find(";", m.start(), chain_end)
            if semi != -1:
                chain_end = semi + 1
            chain = text[m.start():chain_end]

            url = self._extract_url(chain)
            method = self._extract_method(chain)
            headers = self._extract_headers(chain)

            if url or method:
                result.endpoints.append(
                    EndpointInfo(
                        method=method or "GET",
                        path=url or "<dynamic>",
                        annotation_source=f"{rel_path}:{line_no}",
                        headers=headers,
                    )
                )

    @staticmethod
    def _extract_url(chain: str) -> str:
        m = _URL_CALL_RE.search(chain)
        if m:
            return m.group(1)
        vm = _URL_VAR_RE.search(chain)
        if vm:
            return f"<{vm.group(1)}>"
        return ""

    @staticmethod
    def _extract_method(chain: str) -> str:
        m = _METHOD_CALL_RE.search(chain)
        if m:
            return (m.group(1) or m.group(2)).upper()
        return "GET"

    @staticmethod
    def _extract_headers(chain: str) -> List[Dict[str, str]]:
        headers: List[Dict[str, str]] = []
        for m in _HEADER_CALL_RE.finditer(chain):
            headers.append({"name": m.group(1), "value": m.group(2).strip().strip('"')})
        return headers

    def _scan_client_builders(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        """Find OkHttpClient.Builder() chains and registered interceptors."""
        for m in _CLIENT_BUILDER_RE.finditer(text):
            chain_end = min(m.start() + 1500, len(text))
            chain = text[m.start():chain_end]

            for im in _ADD_INTERCEPTOR_RE.finditer(chain):
                interceptor_name = im.group(1)
                line_no = text[: m.start() + im.start()].count("\n") + 1
                result.interceptors.append(
                    InterceptorInfo(
                        name=interceptor_name,
                        type="custom",
                        source_file=f"{rel_path}:{line_no}",
                        code_snippet=chain[im.start():im.start() + 120].strip(),
                    )
                )

    def _scan_interceptor_classes(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        """Find classes implementing Interceptor."""
        for pattern in (_INTERCEPTOR_IMPL_RE, _INTERCEPTOR_IMPL_KOTLIN_RE):
            for m in pattern.finditer(text):
                name = m.group(1)
                line_no = text[: m.start()].count("\n") + 1
                # Extract headers from intercept method body
                chunk = text[m.start(): m.start() + 3000]
                headers: List[Dict[str, str]] = []
                for hm in _HEADER_CALL_RE.finditer(chunk):
                    headers.append({"name": hm.group(1), "value_expr": hm.group(2).strip()})

                itype = _classify(name, chunk)
                snippet_lines = chunk.split("\n")[:12]

                result.interceptors.append(
                    InterceptorInfo(
                        name=name,
                        type=itype,
                        headers_added=headers,
                        source_file=f"{rel_path}:{line_no}",
                        code_snippet="\n".join(snippet_lines),
                    )
                )

                # Auth detection
                self._detect_auth(name, chunk, rel_path, line_no, result)

    @staticmethod
    def _detect_auth(
        name: str, context: str, rel_path: str, line_no: int, result: ScanResult
    ) -> None:
        ctx_lower = context.lower()
        snippet = "\n".join(context.split("\n")[:8])

        if "authorization" in ctx_lower and "bearer" in ctx_lower:
            result.auth_patterns.append(
                AuthPattern(
                    type="bearer",
                    header_name="Authorization",
                    source_description=f"Bearer token in OkHttp interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )
        if re.search(r'x-api-key|apikey|api[_-]key', ctx_lower):
            result.auth_patterns.append(
                AuthPattern(
                    type="api_key",
                    header_name="X-Api-Key",
                    source_description=f"API key in OkHttp interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

    def _scan_cert_pinning(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        """Find certificate pinning configurations."""
        for m in _CERT_PINNER_RE.finditer(text):
            chunk = text[m.start(): m.start() + 1000]
            for pm in _CERT_PIN_ADD_RE.finditer(chunk):
                line_no = text[: m.start() + pm.start()].count("\n") + 1
                result.auth_patterns.append(
                    AuthPattern(
                        type="certificate",
                        header_name=None,
                        source_description=f"Certificate pinning for {pm.group(1)} ({pm.group(2)})",
                        code_snippet=chunk[:200],
                        source_file=f"{rel_path}:{line_no}",
                    )
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _java_kotlin_files(source_dir: Path):
    """Yield .java and .kt files under *source_dir*."""
    yield from source_dir.rglob("*.java")
    yield from source_dir.rglob("*.kt")


def _classify(name: str, context: str) -> str:
    nl = name.lower()
    cl = context.lower()
    if any(k in nl for k in ("auth", "token", "bearer", "apikey")):
        return "auth"
    if any(k in nl for k in ("log", "debug")):
        return "logging"
    if "authorization" in cl or "bearer" in cl or "token" in cl:
        return "auth"
    if "retry" in nl:
        return "retry"
    if "header" in nl:
        return "header"
    return "custom"
