"""
hargen.analyzer — Analyze captured HTTP traffic and extract API patterns.

Groups requests by host, detects path parameter patterns, infers JSON schemas,
classifies headers (static, dynamic, auth), and produces a structured ApiSpec.
"""

from __future__ import annotations

import re
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from rekit.hargen.parser import HttpExchange

logger = logging.getLogger(__name__)

# Patterns that identify path segments as likely variable parameters
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
NUMERIC_RE = re.compile(r"^\d+$")
HEX_ID_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
# Slug-like IDs (alphanumeric with dashes, but not common words)
SLUG_ID_RE = re.compile(r"^[a-z0-9]+-[a-z0-9-]+[a-z0-9]$", re.IGNORECASE)

# Header names commonly used for authentication
AUTH_HEADER_PATTERNS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "cookie",
    "x-session-id",
    "api-key",
    "apikey",
    "bearer",
    "token",
}

# Headers that are typically dynamic per-request (trace IDs, timestamps)
DYNAMIC_HEADER_PATTERNS = {
    "x-request-id",
    "x-trace-id",
    "x-correlation-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-amzn-trace-id",
    "date",
    "x-timestamp",
    "if-none-match",
    "if-modified-since",
}

# Headers to ignore entirely (browser/transport level)
SKIP_HEADERS = {
    "host",
    "connection",
    "accept-encoding",
    "content-length",
    "transfer-encoding",
    ":method",
    ":path",
    ":scheme",
    ":authority",
    ":status",
}


@dataclass
class FieldSchema:
    """Schema for a single field in a JSON object."""

    name: str
    type_str: str  # e.g., "str", "int", "List[Dict[str, Any]]"
    optional: bool = False
    example_value: Any = None
    nested: Optional[List[FieldSchema]] = None  # For nested objects

    def __repr__(self) -> str:
        opt = "?" if self.optional else ""
        return f"FieldSchema({self.name}: {self.type_str}{opt})"


@dataclass
class ParamInfo:
    """Information about a query or path parameter."""

    name: str
    type_str: str = "str"
    required: bool = True
    example_values: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class HeaderInfo:
    """Classified header information."""

    name: str
    classification: str  # "static", "dynamic", "auth"
    example_value: str = ""
    all_values: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    """A single API endpoint with its extracted patterns."""

    method: str
    path_pattern: str  # e.g., "/api/listings/{id}"
    path_params: List[ParamInfo] = field(default_factory=list)
    query_params: List[ParamInfo] = field(default_factory=list)
    request_schema: Optional[List[FieldSchema]] = None
    response_schema: Optional[List[FieldSchema]] = None
    headers: List[HeaderInfo] = field(default_factory=list)
    example_request: Optional[Dict[str, Any]] = None
    example_response: Optional[Dict[str, Any]] = None
    status_codes: List[int] = field(default_factory=list)
    request_count: int = 0

    @property
    def function_name(self) -> str:
        """Generate a Python function name for this endpoint."""
        # /api/v2/listings/{id}/photos -> get_listings_id_photos
        parts = self.path_pattern.strip("/").split("/")
        clean_parts = []
        for p in parts:
            if p.startswith("{") and p.endswith("}"):
                continue  # Skip path params in the name
            # Remove version prefixes like v1, v2, api
            if re.match(r"^(api|v\d+)$", p, re.IGNORECASE):
                continue
            clean_parts.append(re.sub(r"[^a-zA-Z0-9]", "_", p))

        method_prefix = self.method.lower()
        path_part = "_".join(clean_parts) if clean_parts else "root"
        name = f"{method_prefix}_{path_part}"
        # Deduplicate underscores
        name = re.sub(r"_+", "_", name).strip("_")
        return name

    @property
    def response_model_name(self) -> str:
        """Generate a model class name for the response."""
        parts = self.path_pattern.strip("/").split("/")
        clean_parts = []
        for p in parts:
            if p.startswith("{"):
                continue
            if re.match(r"^(api|v\d+)$", p, re.IGNORECASE):
                continue
            clean_parts.append(p.capitalize())
        suffix = "".join(clean_parts) or "Root"
        return f"{suffix}Response"

    @property
    def request_model_name(self) -> str:
        """Generate a model class name for the request body."""
        parts = self.path_pattern.strip("/").split("/")
        clean_parts = []
        for p in parts:
            if p.startswith("{"):
                continue
            if re.match(r"^(api|v\d+)$", p, re.IGNORECASE):
                continue
            clean_parts.append(p.capitalize())
        suffix = "".join(clean_parts) or "Root"
        return f"{suffix}Request"


@dataclass
class ApiSpec:
    """Full API specification extracted from traffic analysis."""

    base_url: str
    endpoints: List[Endpoint] = field(default_factory=list)
    common_headers: List[HeaderInfo] = field(default_factory=list)
    auth_headers: List[HeaderInfo] = field(default_factory=list)


def analyze(
    exchanges: List[HttpExchange],
    base_url_filter: Optional[str] = None,
) -> ApiSpec:
    """
    Analyze a list of HTTP exchanges and extract a structured API specification.

    Args:
        exchanges: List of HttpExchange objects from parsing traffic.
        base_url_filter: If provided, only include exchanges whose URL starts
                         with this string (e.g., "https://api.example.com").

    Returns:
        An ApiSpec object describing the discovered API.
    """
    if not exchanges:
        return ApiSpec(base_url="")

    # Filter by base URL if specified
    if base_url_filter:
        filtered = base_url_filter.rstrip("/")
        exchanges = [e for e in exchanges if e.url.startswith(filtered)]
        if not exchanges:
            logger.warning("No exchanges match base_url_filter=%r", base_url_filter)
            return ApiSpec(base_url=filtered)

    # Determine the most common base URL (scheme + host)
    base_url = _detect_base_url(exchanges, base_url_filter)

    # Classify headers across all exchanges
    all_headers_by_name: Dict[str, List[str]] = defaultdict(list)
    for ex in exchanges:
        if not ex.url.startswith(base_url):
            continue
        for name, value in ex.request_headers.items():
            if name.lower() not in SKIP_HEADERS:
                all_headers_by_name[name.lower()].append(value)

    common_headers, auth_headers = _classify_headers(
        all_headers_by_name, len(exchanges)
    )

    # Group exchanges by (method, path_pattern)
    endpoint_groups = _group_into_endpoints(exchanges, base_url)

    # Build endpoint specs
    endpoints: List[Endpoint] = []
    for (method, pattern, path_params), group_exchanges in endpoint_groups.items():
        endpoint = _build_endpoint(
            method, pattern, path_params, group_exchanges, base_url
        )
        endpoints.append(endpoint)

    # Sort endpoints by path for stable output
    endpoints.sort(key=lambda e: (e.path_pattern, e.method))

    return ApiSpec(
        base_url=base_url,
        endpoints=endpoints,
        common_headers=common_headers,
        auth_headers=auth_headers,
    )


def _detect_base_url(
    exchanges: List[HttpExchange], explicit: Optional[str] = None
) -> str:
    """Determine the most common base URL from exchanges."""
    if explicit:
        return explicit.rstrip("/")

    host_counts: Dict[str, int] = defaultdict(int)
    for ex in exchanges:
        parsed = urlparse(ex.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host_counts[base] += 1

    if not host_counts:
        return ""

    # Return the most common host
    return max(host_counts, key=host_counts.get)  # type: ignore[arg-type]


def _classify_headers(
    headers_by_name: Dict[str, List[str]], total_count: int
) -> Tuple[List[HeaderInfo], List[HeaderInfo]]:
    """Classify headers into common (static/dynamic) and auth categories."""
    common: List[HeaderInfo] = []
    auth: List[HeaderInfo] = []

    for name, values in headers_by_name.items():
        if name in SKIP_HEADERS:
            continue

        unique_values = set(values)
        example = values[0] if values else ""

        # Classify as auth
        if _is_auth_header(name):
            auth.append(
                HeaderInfo(
                    name=name,
                    classification="auth",
                    example_value=_mask_value(example),
                    all_values=[],  # Don't store auth values
                )
            )
            continue

        # Present in most requests?
        presence_ratio = len(values) / max(total_count, 1)
        if presence_ratio < 0.5:
            continue  # Skip infrequent headers

        if _is_dynamic_header(name) or len(unique_values) > max(3, len(values) * 0.5):
            classification = "dynamic"
        elif len(unique_values) == 1:
            classification = "static"
        else:
            classification = "static"  # Mostly static, use first value

        common.append(
            HeaderInfo(
                name=name,
                classification=classification,
                example_value=example,
                all_values=list(unique_values)[:5],
            )
        )

    return common, auth


def _is_auth_header(name: str) -> bool:
    """Check if a header name matches authentication patterns."""
    lower = name.lower()
    return lower in AUTH_HEADER_PATTERNS or any(
        pat in lower for pat in ("auth", "token", "api-key", "apikey", "session")
    )


def _is_dynamic_header(name: str) -> bool:
    """Check if a header name matches dynamic/per-request patterns."""
    lower = name.lower()
    return lower in DYNAMIC_HEADER_PATTERNS or any(
        pat in lower for pat in ("trace", "request-id", "correlation", "nonce")
    )


def _mask_value(value: str) -> str:
    """Mask a potentially sensitive header value for display."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


def _is_path_param_segment(segment: str) -> bool:
    """Check if a URL path segment looks like a variable parameter."""
    if UUID_RE.match(segment):
        return True
    if NUMERIC_RE.match(segment):
        return True
    if HEX_ID_RE.match(segment):
        return True
    return False


def _normalize_path(path: str) -> Tuple[str, List[str]]:
    """
    Normalize a URL path, replacing variable segments with parameter placeholders.

    Returns (pattern, list_of_param_names).
    """
    segments = path.strip("/").split("/")
    pattern_parts = []
    params = []
    param_counter: Dict[str, int] = defaultdict(int)

    for seg in segments:
        if _is_path_param_segment(seg):
            # Determine param name from context
            # Use the previous segment name as hint
            if pattern_parts:
                prev = pattern_parts[-1].strip("{}")
                # Singularize naive: remove trailing 's'
                if prev.endswith("s") and len(prev) > 2:
                    param_name = f"{prev[:-1]}_id"
                else:
                    param_name = f"{prev}_id"
            else:
                param_name = "id"

            # Handle duplicates
            param_counter[param_name] += 1
            if param_counter[param_name] > 1:
                param_name = f"{param_name}_{param_counter[param_name]}"

            pattern_parts.append(f"{{{param_name}}}")
            params.append(param_name)
        else:
            pattern_parts.append(seg)

    pattern = "/" + "/".join(pattern_parts) if pattern_parts else "/"
    return pattern, params


def _group_into_endpoints(
    exchanges: List[HttpExchange], base_url: str
) -> Dict[Tuple[str, str, Tuple[str, ...]], List[HttpExchange]]:
    """
    Group exchanges into endpoints by (method, normalized_path_pattern).

    Returns a dict mapping (method, pattern, path_param_names) -> [exchanges].
    """
    groups: Dict[Tuple[str, str, Tuple[str, ...]], List[HttpExchange]] = defaultdict(
        list
    )

    for ex in exchanges:
        if not ex.url.startswith(base_url):
            continue

        parsed = urlparse(ex.url)
        path = parsed.path
        pattern, params = _normalize_path(path)
        key = (ex.method.upper(), pattern, tuple(params))
        groups[key].append(ex)

    return dict(groups)


def _build_endpoint(
    method: str,
    pattern: str,
    path_param_names: Tuple[str, ...],
    exchanges: List[HttpExchange],
    base_url: str,
) -> Endpoint:
    """Build a full Endpoint spec from a group of exchanges to the same endpoint."""
    # Path params
    path_params = []
    for name in path_param_names:
        # Collect example values
        examples = _extract_path_param_examples(pattern, name, exchanges, base_url)
        param_type = _infer_param_type(examples)
        path_params.append(
            ParamInfo(
                name=name,
                type_str=param_type,
                required=True,
                example_values=examples[:5],
            )
        )

    # Query params
    query_params = _extract_query_params(exchanges)

    # Status codes
    status_codes = sorted(set(ex.status_code for ex in exchanges if ex.status_code > 0))

    # Request schema (for POST/PUT/PATCH)
    request_schema = None
    example_request = None
    if method in ("POST", "PUT", "PATCH"):
        request_bodies = []
        for ex in exchanges:
            parsed = ex.parsed_request_json()
            if parsed is not None:
                request_bodies.append(parsed)
        if request_bodies:
            request_schema = _infer_schema(request_bodies)
            example_request = request_bodies[0]

    # Response schema (from successful JSON responses)
    response_schema = None
    example_response = None
    response_bodies = []
    for ex in exchanges:
        if 200 <= ex.status_code < 300 and ex.is_json_response:
            parsed = ex.parsed_response_json()
            if parsed is not None:
                response_bodies.append(parsed)
    if response_bodies:
        response_schema = _infer_schema(response_bodies)
        example_response = response_bodies[0]

    # Per-endpoint headers (beyond common ones)
    endpoint_headers = _extract_endpoint_headers(exchanges)

    return Endpoint(
        method=method,
        path_pattern=pattern,
        path_params=path_params,
        query_params=query_params,
        request_schema=request_schema,
        response_schema=response_schema,
        headers=endpoint_headers,
        example_request=example_request,
        example_response=example_response,
        status_codes=status_codes,
        request_count=len(exchanges),
    )


def _extract_path_param_examples(
    pattern: str, param_name: str, exchanges: List[HttpExchange], base_url: str
) -> List[str]:
    """Extract actual values for a path parameter from exchanges."""
    examples: List[str] = []
    pattern_parts = pattern.strip("/").split("/")

    param_index = None
    for i, part in enumerate(pattern_parts):
        if part == f"{{{param_name}}}":
            param_index = i
            break

    if param_index is None:
        return examples

    seen: Set[str] = set()
    for ex in exchanges:
        parsed = urlparse(ex.url)
        path_parts = parsed.path.strip("/").split("/")
        if param_index < len(path_parts):
            val = path_parts[param_index]
            if val not in seen:
                seen.add(val)
                examples.append(val)

    return examples


def _infer_param_type(examples: List[str]) -> str:
    """Infer a parameter type from example values."""
    if not examples:
        return "str"

    if all(NUMERIC_RE.match(e) for e in examples):
        return "int"
    if all(UUID_RE.match(e) for e in examples):
        return "str"  # UUIDs are strings
    return "str"


def _extract_query_params(exchanges: List[HttpExchange]) -> List[ParamInfo]:
    """Extract query parameters and their characteristics from exchanges."""
    param_values: Dict[str, List[str]] = defaultdict(list)
    param_presence: Dict[str, int] = defaultdict(int)
    total = len(exchanges)

    for ex in exchanges:
        parsed = urlparse(ex.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        seen_in_this_request: Set[str] = set()
        for name, values in qs.items():
            for v in values:
                param_values[name].append(v)
            seen_in_this_request.add(name)
        for name in seen_in_this_request:
            param_presence[name] += 1

    params: List[ParamInfo] = []
    for name, values in param_values.items():
        presence_ratio = param_presence[name] / max(total, 1)
        required = presence_ratio > 0.9
        param_type = _infer_param_type(values[:10])
        params.append(
            ParamInfo(
                name=name,
                type_str=param_type,
                required=required,
                example_values=list(dict.fromkeys(values))[:5],  # Unique, ordered
            )
        )

    return sorted(params, key=lambda p: (not p.required, p.name))


def _extract_endpoint_headers(exchanges: List[HttpExchange]) -> List[HeaderInfo]:
    """Extract per-endpoint header patterns."""
    header_values: Dict[str, List[str]] = defaultdict(list)
    total = len(exchanges)

    for ex in exchanges:
        for name, value in ex.request_headers.items():
            lower = name.lower()
            if lower not in SKIP_HEADERS:
                header_values[lower].append(value)

    headers: List[HeaderInfo] = []
    for name, values in header_values.items():
        if len(values) < total * 0.5:
            continue  # Skip infrequent headers

        unique = set(values)
        example = values[0]

        if _is_auth_header(name):
            classification = "auth"
            example = _mask_value(example)
        elif _is_dynamic_header(name) or len(unique) > max(3, len(values) * 0.5):
            classification = "dynamic"
        else:
            classification = "static"

        headers.append(
            HeaderInfo(
                name=name,
                classification=classification,
                example_value=example,
            )
        )

    return sorted(headers, key=lambda h: h.name)


def _infer_schema(samples: List[Any]) -> List[FieldSchema]:
    """
    Infer a JSON schema from one or more sample values.

    If the samples are dicts, produces a list of FieldSchema for the object's fields.
    If the samples are lists, infers the schema of the list items.
    For primitives, returns a single-element list with a "value" FieldSchema.
    """
    if not samples:
        return []

    first = samples[0]

    if isinstance(first, dict):
        return _infer_object_schema(samples)
    elif isinstance(first, list):
        # Flatten all list items for element schema
        all_items = []
        for s in samples:
            if isinstance(s, list):
                all_items.extend(s)
        if all_items:
            element_schema = _infer_schema(all_items)
            type_str = _python_type_for_value(all_items[0]) if all_items else "Any"
            return [
                FieldSchema(
                    name="_items",
                    type_str=f"List[{type_str}]",
                    optional=False,
                    example_value=first[:1] if first else None,
                    nested=element_schema if isinstance(all_items[0], dict) else None,
                )
            ]
        return [FieldSchema(name="_items", type_str="List[Any]", optional=False)]
    else:
        return [
            FieldSchema(
                name="_value",
                type_str=_python_type_for_value(first),
                example_value=first,
            )
        ]


def _infer_object_schema(samples: List[Any]) -> List[FieldSchema]:
    """Infer field schemas from a list of dict samples (merge across samples)."""
    # Only consider dict samples
    dict_samples = [s for s in samples if isinstance(s, dict)]
    if not dict_samples:
        return []

    total = len(dict_samples)

    # Collect all field names and their values across samples
    field_values: Dict[str, List[Any]] = defaultdict(list)
    field_presence: Dict[str, int] = defaultdict(int)

    for d in dict_samples:
        for key, val in d.items():
            field_values[key].append(val)
            field_presence[key] += 1

    fields: List[FieldSchema] = []
    for name, values in field_values.items():
        # Determine if optional (not present in all samples)
        optional = field_presence[name] < total

        # Filter out None values for type inference
        non_none = [v for v in values if v is not None]
        has_none = len(non_none) < len(values)
        if has_none:
            optional = True

        if not non_none:
            type_str = "Any"
            nested = None
            example = None
        else:
            type_str = _python_type_for_value(non_none[0])
            example = non_none[0]
            nested = None

            # For nested objects, recurse
            if isinstance(non_none[0], dict):
                nested = _infer_object_schema(non_none)
                type_str = "Dict[str, Any]"  # Will be replaced by a model class
            elif isinstance(non_none[0], list) and non_none[0]:
                inner = non_none[0][0]
                inner_type = _python_type_for_value(inner)
                type_str = f"List[{inner_type}]"
                if isinstance(inner, dict):
                    all_inner = []
                    for lst in non_none:
                        if isinstance(lst, list):
                            all_inner.extend(
                                item for item in lst if isinstance(item, dict)
                            )
                    nested = _infer_object_schema(all_inner) if all_inner else None

            # Reconcile types across samples (check for mixed types)
            types_seen = set()
            for v in non_none:
                types_seen.add(_python_type_for_value(v))
            if len(types_seen) > 1:
                type_str = "Any"
                nested = None

        if optional and type_str != "Any":
            display_type = f"Optional[{type_str}]"
        elif optional:
            display_type = "Optional[Any]"
        else:
            display_type = type_str

        fields.append(
            FieldSchema(
                name=name,
                type_str=display_type,
                optional=optional,
                example_value=_truncate_example(example),
                nested=nested,
            )
        )

    return sorted(fields, key=lambda f: (f.optional, f.name))


def _python_type_for_value(value: Any) -> str:
    """Map a Python value to a type string for code generation."""
    if value is None:
        return "Any"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        if not value:
            return "List[Any]"
        inner = _python_type_for_value(value[0])
        return f"List[{inner}]"
    if isinstance(value, dict):
        return "Dict[str, Any]"
    return "Any"


def _truncate_example(value: Any, max_len: int = 100) -> Any:
    """Truncate example values that are too long for display."""
    if value is None:
        return None
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + "..."
    if isinstance(value, (list, dict)):
        s = str(value)
        if len(s) > max_len:
            return str(value)[:max_len] + "..."
    return value
