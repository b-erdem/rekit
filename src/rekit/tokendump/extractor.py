"""tokendump.extractor — Extract tokens from captured HTTP traffic."""

from __future__ import annotations

import base64
import json
import math
import re
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from rekit.hargen.parser import HttpExchange


class TokenType(Enum):
    """Classification of authentication token types."""

    JWT = "jwt"
    OPAQUE = "opaque"
    API_KEY = "api_key"
    SESSION_COOKIE = "session_cookie"
    CSRF = "csrf"
    OAUTH_ACCESS = "oauth_access"
    OAUTH_REFRESH = "oauth_refresh"
    BEARER = "bearer"
    UNKNOWN = "unknown"


@dataclass
class Token:
    """A single authentication token extracted from HTTP traffic."""

    value: str
    token_type: TokenType
    source: str
    exchange_index: int
    url: str
    timestamp: Optional[datetime] = None
    decoded: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    scopes: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    subject: Optional[str] = None
    algorithm: Optional[str] = None
    key_id: Optional[str] = None


# Keys to scan for in JSON bodies
_TOKEN_BODY_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "jwt",
    "api_key",
    "session_token",
    "auth_token",
    "csrf_token",
    "xsrf_token",
}

# Common session cookie name patterns
_SESSION_COOKIE_PATTERNS = re.compile(
    r"^(session|sess_id|phpsessid|jsessionid|connect\.sid|"
    r"_session|sid|session_id|sessionid|aspsessionid.*)$",
    re.IGNORECASE,
)


def extract_tokens(exchanges: List[HttpExchange]) -> List[Token]:
    """Extract all authentication tokens from a list of HTTP exchanges.

    Scans request headers (Authorization, X-API-Key, Cookie), response headers
    (Set-Cookie, X-CSRF-Token), and JSON bodies for token-like values.

    Args:
        exchanges: List of HttpExchange objects from parsed HAR traffic.

    Returns:
        List of Token objects found across all exchanges.
    """
    tokens: List[Token] = []

    for idx, ex in enumerate(exchanges):
        tokens.extend(_extract_from_request_headers(ex, idx))
        tokens.extend(_extract_from_response_headers(ex, idx))
        tokens.extend(_extract_from_response_body(ex, idx))
        tokens.extend(_extract_from_request_body(ex, idx))

    return tokens


def _extract_from_request_headers(ex: HttpExchange, idx: int) -> List[Token]:
    """Extract tokens from request headers."""
    tokens: List[Token] = []
    headers = ex.request_headers

    # Authorization header
    auth = headers.get("authorization", "")
    if auth:
        if auth.lower().startswith("bearer "):
            value = auth[7:].strip()
            if value:
                tok = _make_token(
                    value=value,
                    name="bearer",
                    source="request:authorization",
                    exchange=ex,
                    idx=idx,
                )
                tokens.append(tok)
        elif auth.lower().startswith("basic "):
            value = auth[6:].strip()
            if value:
                tokens.append(
                    Token(
                        value=value,
                        token_type=TokenType.OPAQUE,
                        source="request:authorization",
                        exchange_index=idx,
                        url=ex.url,
                        timestamp=ex.timestamp,
                    )
                )

    # X-API-Key, X-Auth-Token, X-Access-Token
    for header_name in ("x-api-key", "x-auth-token", "x-access-token"):
        val = headers.get(header_name, "")
        if val:
            tok = _make_token(
                value=val,
                name=header_name,
                source=f"request:{header_name}",
                exchange=ex,
                idx=idx,
            )
            tokens.append(tok)

    # Cookie header — parse individual cookies
    cookie_header = headers.get("cookie", "")
    if cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                cname, cval = part.split("=", 1)
                cname = cname.strip()
                cval = cval.strip()
                if cval and _is_token_like(cval):
                    tok = _make_token(
                        value=cval,
                        name=cname,
                        source=f"request:cookie:{cname}",
                        exchange=ex,
                        idx=idx,
                    )
                    tokens.append(tok)

    return tokens


def _extract_from_response_headers(ex: HttpExchange, idx: int) -> List[Token]:
    """Extract tokens from response headers."""
    tokens: List[Token] = []
    headers = ex.response_headers

    # Set-Cookie
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        # May contain multiple cookies separated by commas (though uncommon)
        # More reliable: HAR usually has one set-cookie value per header entry,
        # but our parser merges them. Parse conservatively.
        for cookie_str in _split_set_cookies(set_cookie):
            parsed = _parse_set_cookie(cookie_str)
            if parsed:
                cname, cval, expires = parsed
                if cval and _is_token_like(cval):
                    tok = _make_token(
                        value=cval,
                        name=cname,
                        source=f"response:set-cookie:{cname}",
                        exchange=ex,
                        idx=idx,
                    )
                    if expires:
                        tok.expires_at = expires
                    tokens.append(tok)

    # CSRF headers
    for header_name in ("x-csrf-token", "x-xsrf-token"):
        val = headers.get(header_name, "")
        if val:
            tok = _make_token(
                value=val,
                name=header_name,
                source=f"response:{header_name}",
                exchange=ex,
                idx=idx,
            )
            tokens.append(tok)

    return tokens


def _extract_from_response_body(ex: HttpExchange, idx: int) -> List[Token]:
    """Extract tokens from JSON response bodies."""
    if not ex.is_json_response:
        return []
    data = ex.parsed_response_json()
    if not isinstance(data, dict):
        return []
    return _extract_from_json(data, "response:body", ex, idx)


def _extract_from_request_body(ex: HttpExchange, idx: int) -> List[Token]:
    """Extract tokens from JSON request bodies."""
    if not ex.is_json_request:
        return []
    data = ex.parsed_request_json()
    if not isinstance(data, dict):
        return []
    return _extract_from_json(data, "request:body", ex, idx)


def _extract_from_json(
    data: Dict[str, Any], source_prefix: str, ex: HttpExchange, idx: int
) -> List[Token]:
    """Extract tokens from a JSON dictionary by scanning known keys."""
    tokens: List[Token] = []
    for key in _TOKEN_BODY_KEYS:
        if key in data:
            val = data[key]
            if isinstance(val, str) and val:
                tok = _make_token(
                    value=val,
                    name=key,
                    source=f"{source_prefix}:{key}",
                    exchange=ex,
                    idx=idx,
                )
                tokens.append(tok)
    return tokens


def _make_token(
    value: str,
    name: str,
    source: str,
    exchange: HttpExchange,
    idx: int,
) -> Token:
    """Create a Token with automatic type detection and JWT decoding."""
    token_type = _detect_token_type(name, value)
    decoded = None
    expires_at = None
    issued_at = None
    scopes: List[str] = []
    issuer = None
    subject = None
    algorithm = None
    key_id = None

    if token_type == TokenType.JWT or (token_type != TokenType.JWT and _is_jwt(value)):
        token_type = TokenType.JWT
        decoded = _decode_jwt(value)
        if decoded:
            payload = decoded.get("payload", {})
            header = decoded.get("header", {})
            # Extract claims
            if "exp" in payload:
                try:
                    expires_at = datetime.fromtimestamp(
                        int(payload["exp"]), tz=timezone.utc
                    )
                except (ValueError, OSError, OverflowError):
                    pass
            if "iat" in payload:
                try:
                    issued_at = datetime.fromtimestamp(
                        int(payload["iat"]), tz=timezone.utc
                    )
                except (ValueError, OSError, OverflowError):
                    pass
            scope_val = payload.get("scope") or payload.get("scp")
            if isinstance(scope_val, str):
                scopes = scope_val.split()
            elif isinstance(scope_val, list):
                scopes = [str(s) for s in scope_val]
            issuer = payload.get("iss")
            subject = payload.get("sub")
            algorithm = header.get("alg")
            key_id = header.get("kid")

    return Token(
        value=value,
        token_type=token_type,
        source=source,
        exchange_index=idx,
        url=exchange.url,
        timestamp=exchange.timestamp,
        decoded=decoded,
        expires_at=expires_at,
        issued_at=issued_at,
        scopes=scopes,
        issuer=issuer if isinstance(issuer, str) else None,
        subject=subject if isinstance(subject, str) else None,
        algorithm=algorithm,
        key_id=key_id,
    )


def _detect_token_type(name: str, value: str) -> TokenType:
    """Detect the type of a token based on its name and value.

    Args:
        name: The key/header name where the token was found.
        value: The raw token string.

    Returns:
        The detected TokenType.
    """
    name_lower = name.lower()

    # Check JWT first by structure
    if _is_jwt(value):
        return TokenType.JWT

    # CSRF tokens
    if "csrf" in name_lower or "xsrf" in name_lower:
        return TokenType.CSRF

    # API key
    if name_lower in ("api_key", "apikey", "api-key", "x-api-key"):
        return TokenType.API_KEY

    # OAuth tokens by key name
    if name_lower == "access_token":
        return TokenType.OAUTH_ACCESS
    if name_lower == "refresh_token":
        return TokenType.OAUTH_REFRESH

    # Session cookies
    if _SESSION_COOKIE_PATTERNS.match(name_lower):
        return TokenType.SESSION_COOKIE

    # Bearer from Authorization header
    if name_lower == "bearer":
        return TokenType.BEARER

    # If it looks like a token but we can't classify it
    if _is_token_like(value):
        return TokenType.OPAQUE

    return TokenType.UNKNOWN


def _is_jwt(value: str) -> bool:
    """Check if a string is a JWT by structure.

    A JWT has three dot-separated base64url segments, where the first
    segment decodes to JSON containing an 'alg' field.

    Args:
        value: The string to check.

    Returns:
        True if the string appears to be a valid JWT.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False
    # All parts must be non-empty
    if not all(parts):
        return False
    try:
        header_json = _base64url_decode(parts[0])
        header = json.loads(header_json)
        return isinstance(header, dict) and "alg" in header
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT without verification.

    Parses the header and payload segments of a JWT by base64url-decoding
    them. Does not verify the signature.

    Args:
        token: The raw JWT string (three dot-separated segments).

    Returns:
        Dict with 'header' and 'payload' keys, or None if decoding fails.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header_json = _base64url_decode(parts[0])
        payload_json = _base64url_decode(parts[1])
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        return {"header": header, "payload": payload}
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _base64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, adding padding as needed."""
    # Add padding
    remainder = len(segment) % 4
    if remainder:
        segment += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(segment)


def _is_token_like(value: str) -> bool:
    """Heuristic check: is this string likely a token?

    Checks length (>= 16), entropy, and that it's not a plain word or URL.

    Args:
        value: The string to check.

    Returns:
        True if the string looks like a token.
    """
    if len(value) < 16:
        return False

    # Reject plain URLs
    if value.startswith(("http://", "https://", "/")):
        return False

    # Check entropy — tokens tend to have high character diversity
    entropy = _shannon_entropy(value)
    if entropy < 2.5:
        return False

    # Must contain a mix of character types (not all lowercase words)
    has_upper = any(c in string.ascii_uppercase for c in value)
    has_lower = any(c in string.ascii_lowercase for c in value)
    has_digit = any(c in string.digits for c in value)
    has_special = any(c in "._-+/=" for c in value)

    char_types = sum([has_upper, has_lower, has_digit, has_special])
    return char_types >= 2


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _split_set_cookies(header_value: str) -> List[str]:
    """Split a Set-Cookie header value into individual cookies.

    Handles the case where multiple Set-Cookie values may be joined.
    """
    # Simple approach: split on comma followed by a cookie name pattern
    # but avoid splitting within expires= date values
    cookies: List[str] = []
    current = ""
    for part in header_value.split(","):
        stripped = part.strip()
        # If this looks like a new cookie (has = before ;), start new
        if current and re.match(r"^[a-zA-Z_][a-zA-Z0-9_.-]*=", stripped):
            cookies.append(current.strip())
            current = part
        else:
            current = current + "," + part if current else part
    if current:
        cookies.append(current.strip())
    return cookies


def _parse_set_cookie(
    cookie_str: str,
) -> Optional[tuple[str, str, Optional[datetime]]]:
    """Parse a Set-Cookie string into (name, value, expires)."""
    parts = cookie_str.split(";")
    if not parts:
        return None
    name_value = parts[0].strip()
    if "=" not in name_value:
        return None
    name, value = name_value.split("=", 1)
    name = name.strip()
    value = value.strip()

    expires = None
    for attr in parts[1:]:
        attr = attr.strip().lower()
        if attr.startswith("expires="):
            date_str = attr[8:].strip()
            try:
                expires = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
                expires = expires.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

    return name, value, expires


def mask_token(value: str) -> str:
    """Mask a token value for safe display.

    Shows the first 8 characters and last 4 characters with '...' in between.

    Args:
        value: The raw token string.

    Returns:
        Masked string like 'eyJhbGci...xyz9'.
    """
    if len(value) <= 16:
        return value[:4] + "..." + value[-2:]
    return value[:8] + "..." + value[-4:]
