"""
Base scanner interface and shared data models for apkmap.

All scanners inherit from ``Scanner`` and return a ``ScanResult`` containing
structured findings about API endpoints, models, interceptors, and auth
patterns discovered in decompiled Android source code.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldInfo:
    """A single field inside a request/response model."""

    name: str
    type: str = "unknown"
    annotation: Optional[str] = None  # e.g. @SerializedName("user_id")
    json_name: Optional[str] = None  # the actual JSON key if different


@dataclass(frozen=True)
class EndpointInfo:
    """An HTTP endpoint discovered in source code."""

    method: str  # GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
    path: str  # e.g. /api/v1/users/{id}
    annotation_source: str = ""  # file:line
    params: List[Dict[str, str]] = field(default_factory=list)
    return_type: Optional[str] = None
    headers: List[Dict[str, str]] = field(default_factory=list)
    body_type: Optional[str] = None

    def _key(self) -> tuple:
        return (self.method.upper(), self.path)


@dataclass(frozen=True)
class ModelInfo:
    """A request/response data model (typically a Gson/Moshi/serializable class)."""

    name: str
    fields: List[FieldInfo] = field(default_factory=list)
    source_file: str = ""


@dataclass(frozen=True)
class InterceptorInfo:
    """An OkHttp/Dio interceptor that modifies requests or responses."""

    name: str
    type: str = "unknown"  # header, auth, logging, retry, custom
    headers_added: List[Dict[str, str]] = field(default_factory=list)
    source_file: str = ""
    code_snippet: str = ""


@dataclass(frozen=True)
class AuthPattern:
    """An authentication mechanism discovered in source code."""

    type: str  # api_key, bearer, oauth, hmac, basic, certificate, custom
    header_name: Optional[str] = None
    source_description: str = ""
    code_snippet: str = ""
    source_file: str = ""


@dataclass
class ScanResult:
    """Aggregated scan results from one or more scanners."""

    endpoints: List[EndpointInfo] = field(default_factory=list)
    models: List[ModelInfo] = field(default_factory=list)
    interceptors: List[InterceptorInfo] = field(default_factory=list)
    base_urls: List[Dict[str, str]] = field(default_factory=list)
    auth_patterns: List[AuthPattern] = field(default_factory=list)

    # ----- merging & deduplication -----

    def merge(self, other: ScanResult) -> None:
        """Merge *other* into this result, deduplicating where possible."""
        seen_endpoints = {e._key() for e in self.endpoints}
        for ep in other.endpoints:
            if ep._key() not in seen_endpoints:
                self.endpoints.append(ep)
                seen_endpoints.add(ep._key())

        seen_models = {m.name for m in self.models}
        for m in other.models:
            if m.name not in seen_models:
                self.models.append(m)
                seen_models.add(m.name)

        seen_interceptors = {i.name for i in self.interceptors}
        for i in other.interceptors:
            if i.name not in seen_interceptors:
                self.interceptors.append(i)
                seen_interceptors.add(i.name)

        seen_urls = {u.get("url") for u in self.base_urls}
        for u in other.base_urls:
            if u.get("url") not in seen_urls:
                self.base_urls.append(u)
                seen_urls.add(u.get("url"))

        seen_auth = {(a.type, a.header_name) for a in self.auth_patterns}
        for a in other.auth_patterns:
            key = (a.type, a.header_name)
            if key not in seen_auth:
                self.auth_patterns.append(a)
                seen_auth.add(key)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict (JSON-friendly)."""
        return {
            "endpoints": [dataclasses.asdict(e) for e in self.endpoints],
            "models": [dataclasses.asdict(m) for m in self.models],
            "interceptors": [dataclasses.asdict(i) for i in self.interceptors],
            "base_urls": list(self.base_urls),
            "auth_patterns": [dataclasses.asdict(a) for a in self.auth_patterns],
            "summary": {
                "total_endpoints": len(self.endpoints),
                "total_models": len(self.models),
                "total_interceptors": len(self.interceptors),
                "total_base_urls": len(self.base_urls),
                "total_auth_patterns": len(self.auth_patterns),
            },
        }


# ---------------------------------------------------------------------------
# Abstract base scanner
# ---------------------------------------------------------------------------


class Scanner(ABC):
    """Base class that every apkmap scanner must implement."""

    name: str = "base"

    @abstractmethod
    def scan(self, source_dir: Path) -> ScanResult:
        """Scan *source_dir* and return structured findings."""
        ...
