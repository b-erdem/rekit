"""
Retrofit / OkHttp annotation scanner.

Finds Retrofit-style ``@GET``, ``@POST``, etc. annotations, parameter
annotations (``@Query``, ``@Path``, ``@Body``, ``@Header``), class-level
``@Headers``, return types, and OkHttp ``Interceptor`` implementations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

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

# Retrofit HTTP method annotations: @GET("path"), @POST("/api/v1/users"), etc.
_HTTP_ANNOTATION_RE = re.compile(
    r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*"
    r"(?:value\s*=\s*)?"
    r'"([^"]*)"'
    r"\s*\)",
    re.MULTILINE,
)

# Method signature immediately following the annotation (Java/Kotlin)
# Captures return type and method name.  We look for it on the same or next
# few lines after the annotation.
_METHOD_SIG_RE = re.compile(
    r"(?:(?:public|private|protected|abstract|suspend)\s+)*"
    r"(?:fun\s+)?"  # Kotlin fun keyword
    r"(?:(@?\w[\w<>,\s\?]*?)\s+)?"  # return type (Java)
    r"(\w+)\s*\(",  # method name
    re.MULTILINE,
)

# Parameter annotations: @Query("key"), @Path("id"), @Body, @Header("X-Token"), etc.
_PARAM_ANNOTATION_RE = re.compile(
    r"@(Query|QueryMap|QueryName|Path|Body|Header|HeaderMap|Field|FieldMap|Part|PartMap|Url)\s*"
    r'(?:\(\s*(?:value\s*=\s*)?"([^"]*)"\s*\))?',
)

# Class-level @Headers({"Content-Type: application/json", ...})
_CLASS_HEADERS_RE = re.compile(
    r"@Headers\s*\(\s*\{?\s*"
    r'((?:"[^"]*"\s*,?\s*)+)'
    r"\}?\s*\)",
    re.MULTILINE,
)

# Single header string inside @Headers
_HEADER_VALUE_RE = re.compile(r'"([^"]+)"')

# Interceptor class declarations
_INTERCEPTOR_CLASS_RE = re.compile(
    r"class\s+(\w+)\s*"
    r"(?:extends\s+\w+\s*)?"
    r"(?:implements\s+[\w,\s]*?Interceptor)",
    re.MULTILINE,
)

# Kotlin-style interceptor
_INTERCEPTOR_CLASS_KOTLIN_RE = re.compile(
    r"class\s+(\w+)\s*(?:\([^)]*\))?\s*:\s*[\w,\s]*?Interceptor",
    re.MULTILINE,
)

# addHeader / header calls inside interceptors
_ADD_HEADER_RE = re.compile(
    r'\.\s*(addHeader|header)\s*\(\s*"([^"]*)"\s*,\s*([^)]+)\)',
)

# Base URL patterns
_BASE_URL_RE = re.compile(
    r'(?:baseUrl|BASE_URL|base_url|BaseUrl)\s*(?:\(|=)\s*"(https?://[^"]+)"',
)

# @BaseUrl annotation (less common)
_BASE_URL_ANNOTATION_RE = re.compile(
    r'@BaseUrl\s*\(\s*"(https?://[^"]+)"\s*\)',
)

# Retrofit.Builder().baseUrl("...")
_RETROFIT_BUILDER_URL_RE = re.compile(
    r'Retrofit\.Builder\(\)\s*(?:.*?\.)*\s*baseUrl\s*\(\s*"(https?://[^"]+)"\s*\)',
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class RetrofitScanner(Scanner):
    """Scan decompiled Java/Kotlin for Retrofit and OkHttp annotation patterns."""

    name = "retrofit"

    def scan(self, source_dir: Path) -> ScanResult:
        result = ScanResult()
        java_files = list(source_dir.rglob("*.java"))
        kotlin_files = list(source_dir.rglob("*.kt"))
        all_files = java_files + kotlin_files

        for fpath in all_files:
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue

            rel = str(fpath.relative_to(source_dir))

            self._extract_endpoints(text, rel, result)
            self._extract_interceptors(text, rel, result)
            self._extract_base_urls(text, rel, result)

        return result

    # ---- private helpers ----

    def _extract_endpoints(self, text: str, rel_path: str, result: ScanResult) -> None:
        lines = text.split("\n")

        for match in _HTTP_ANNOTATION_RE.finditer(text):
            method = match.group(1).upper()
            path = match.group(2)
            line_no = text[: match.start()].count("\n") + 1

            # Grab surrounding context for parameter / return-type extraction
            ctx_start = max(0, line_no - 2)
            ctx_end = min(len(lines), line_no + 15)
            context = "\n".join(lines[ctx_start:ctx_end])

            params = self._extract_params(context)
            headers = self._extract_inline_headers(context)
            return_type = self._extract_return_type(
                context, match.end() - text.rfind("\n", 0, match.start())
            )

            result.endpoints.append(
                EndpointInfo(
                    method=method,
                    path=path,
                    annotation_source=f"{rel_path}:{line_no}",
                    params=params,
                    return_type=return_type,
                    headers=headers,
                )
            )

    @staticmethod
    def _extract_params(context: str) -> List[Dict[str, str]]:
        params: List[Dict[str, str]] = []
        for m in _PARAM_ANNOTATION_RE.finditer(context):
            kind = m.group(1)
            name = m.group(2) or ""
            params.append({"kind": kind, "name": name})
        return params

    @staticmethod
    def _extract_inline_headers(context: str) -> List[Dict[str, str]]:
        headers: List[Dict[str, str]] = []
        hdr_match = _CLASS_HEADERS_RE.search(context)
        if hdr_match:
            raw = hdr_match.group(1)
            for h in _HEADER_VALUE_RE.findall(raw):
                if ":" in h:
                    key, _, value = h.partition(":")
                    headers.append({"name": key.strip(), "value": value.strip()})
        return headers

    @staticmethod
    def _extract_return_type(context: str, offset: int) -> Optional[str]:
        # Look for the method signature near the annotation
        sig = _METHOD_SIG_RE.search(context)
        if sig and sig.group(1):
            raw = sig.group(1).strip()
            # Strip access modifiers
            for kw in ("public", "private", "protected", "abstract", "suspend"):
                raw = raw.replace(kw, "").strip()
            if raw and raw not in ("void", "fun"):
                return raw
        return None

    def _extract_interceptors(
        self, text: str, rel_path: str, result: ScanResult
    ) -> None:
        for pattern in (_INTERCEPTOR_CLASS_RE, _INTERCEPTOR_CLASS_KOTLIN_RE):
            for m in pattern.finditer(text):
                name = m.group(1)
                line_no = text[: m.start()].count("\n") + 1
                headers_added = self._extract_interceptor_headers(text, m.start())
                itype = self._classify_interceptor(
                    name, text[m.start() : m.start() + 2000]
                )

                # Grab a compact code snippet (up to 12 lines from class start)
                snippet_lines = text[m.start() :].split("\n")[:12]
                snippet = "\n".join(snippet_lines)

                result.interceptors.append(
                    InterceptorInfo(
                        name=name,
                        type=itype,
                        headers_added=headers_added,
                        source_file=f"{rel_path}:{line_no}",
                        code_snippet=snippet,
                    )
                )

                # Check for auth patterns in interceptor
                self._check_auth_in_interceptor(
                    name, text[m.start() : m.start() + 3000], rel_path, line_no, result
                )

    @staticmethod
    def _extract_interceptor_headers(text: str, start: int) -> List[Dict[str, str]]:
        # Search within the next ~3000 chars for header additions
        chunk = text[start : start + 3000]
        headers: List[Dict[str, str]] = []
        for m in _ADD_HEADER_RE.finditer(chunk):
            headers.append({"name": m.group(2), "value_expr": m.group(3).strip()})
        return headers

    @staticmethod
    def _classify_interceptor(name: str, context: str) -> str:
        name_lower = name.lower()
        ctx_lower = context.lower()
        if any(
            kw in name_lower
            for kw in ("auth", "token", "credential", "bearer", "apikey")
        ):
            return "auth"
        if any(kw in name_lower for kw in ("log", "debug", "trace")):
            return "logging"
        if any(
            kw in ctx_lower for kw in ("authorization", "bearer ", "x-api-key", "token")
        ):
            return "auth"
        if "retry" in name_lower or "retry" in ctx_lower:
            return "retry"
        if "header" in name_lower:
            return "header"
        return "custom"

    @staticmethod
    def _check_auth_in_interceptor(
        name: str, context: str, rel_path: str, line_no: int, result: ScanResult
    ) -> None:
        ctx_lower = context.lower()
        snippet_lines = context.split("\n")[:8]
        snippet = "\n".join(snippet_lines)

        if "bearer" in ctx_lower:
            result.auth_patterns.append(
                AuthPattern(
                    type="bearer",
                    header_name="Authorization",
                    source_description=f"Bearer token in interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )
        if re.search(r"x-api-key|apikey|api_key", ctx_lower):
            # Try to find the actual header name
            hdr_match = re.search(
                r'"((?:x-api-key|X-Api-Key|X-API-KEY|api[_-]?key)[^"]*)"',
                context,
                re.IGNORECASE,
            )
            hdr_name = hdr_match.group(1) if hdr_match else "X-Api-Key"
            result.auth_patterns.append(
                AuthPattern(
                    type="api_key",
                    header_name=hdr_name,
                    source_description=f"API key header in interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )
        if "basic " in ctx_lower or "basic auth" in ctx_lower:
            result.auth_patterns.append(
                AuthPattern(
                    type="basic",
                    header_name="Authorization",
                    source_description=f"Basic auth in interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )
        if re.search(r"hmac|signature|signing", ctx_lower):
            result.auth_patterns.append(
                AuthPattern(
                    type="hmac",
                    header_name=None,
                    source_description=f"HMAC/signature auth in interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )
        if re.search(r"oauth|access_token|refresh_token", ctx_lower):
            result.auth_patterns.append(
                AuthPattern(
                    type="oauth",
                    header_name="Authorization",
                    source_description=f"OAuth pattern in interceptor {name}",
                    code_snippet=snippet,
                    source_file=f"{rel_path}:{line_no}",
                )
            )

    def _extract_base_urls(self, text: str, rel_path: str, result: ScanResult) -> None:
        for pattern in (
            _BASE_URL_RE,
            _BASE_URL_ANNOTATION_RE,
            _RETROFIT_BUILDER_URL_RE,
        ):
            for m in pattern.finditer(text):
                url = m.group(1)
                line_no = text[: m.start()].count("\n") + 1
                result.base_urls.append({"url": url, "source": f"{rel_path}:{line_no}"})
