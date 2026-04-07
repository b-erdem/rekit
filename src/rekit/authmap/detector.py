"""authmap.detector — Detect authentication flow patterns from HTTP traffic."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from rekit.hargen.parser import HttpExchange
from rekit.tokendump.extractor import Token, extract_tokens


class AuthFlowType(Enum):
    """Types of authentication flows that can be detected."""

    OAUTH2_AUTH_CODE = "oauth2_auth_code"
    OAUTH2_PKCE = "oauth2_pkce"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_DEVICE_CODE = "oauth2_device_code"
    CUSTOM_LOGIN = "custom_login"
    API_KEY_STATIC = "api_key_static"
    SESSION_COOKIE = "session_cookie"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    HMAC_SIGNATURE = "hmac_signature"
    UNKNOWN = "unknown"


@dataclass
class AuthStep:
    """A single step in an authentication flow."""

    exchange_index: int
    url: str
    method: str
    step_type: str  # e.g. "login_request", "token_response", "api_call_with_token"
    tokens_sent: List[str] = field(default_factory=list)
    tokens_received: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class AuthFlow:
    """A detected authentication flow."""

    flow_type: AuthFlowType
    steps: List[AuthStep] = field(default_factory=list)
    description: str = ""
    tokens_involved: Set[str] = field(default_factory=set)
    refresh_detected: bool = False
    token_endpoint: Optional[str] = None
    login_endpoint: Optional[str] = None
    redirect_uri: Optional[str] = None


# URL patterns for OAuth2 endpoints
_OAUTH_URL_PATTERNS = re.compile(
    r"(/oauth/|/oauth2/|/token|/authorize|/auth/)", re.IGNORECASE
)

# URL patterns for login endpoints
_LOGIN_URL_PATTERNS = re.compile(
    r"(/login|/signin|/sign-in|/authenticate|/auth|/session)", re.IGNORECASE
)

# Session cookie name patterns
_SESSION_COOKIE_NAMES = re.compile(
    r"^(session|sess_id|phpsessid|jsessionid|connect\.sid|"
    r"_session|sid|session_id|sessionid|aspsessionid.*)$",
    re.IGNORECASE,
)

# Token-like response body keys
_TOKEN_RESPONSE_KEYS = {
    "access_token",
    "token",
    "jwt",
    "session",
    "session_token",
    "auth_token",
    "id_token",
}


def detect_auth_flows(exchanges: List[HttpExchange]) -> List[AuthFlow]:
    """Detect authentication flows from a chronological list of HTTP exchanges.

    Analyzes exchanges in two passes:
    1. Identify all token locations using tokendump's extract_tokens
    2. Detect flow patterns (OAuth2, custom login, API key, etc.)

    Args:
        exchanges: Chronologically ordered HTTP exchanges.

    Returns:
        List of detected AuthFlow objects.
    """
    if not exchanges:
        return []

    # First pass: extract all tokens
    tokens = extract_tokens(exchanges)

    # Build lookup structures
    tokens_by_exchange: Dict[int, List[Token]] = {}
    for tok in tokens:
        tokens_by_exchange.setdefault(tok.exchange_index, []).append(tok)

    flows: List[AuthFlow] = []

    # Detect specific flow types
    oauth_flows = _detect_oauth2_flows(exchanges, tokens_by_exchange)
    flows.extend(oauth_flows)

    custom_login = _detect_custom_login(exchanges, tokens_by_exchange)
    if custom_login:
        flows.append(custom_login)

    api_key = _detect_api_key(exchanges)
    if api_key:
        flows.append(api_key)

    session_cookie = _detect_session_cookie(exchanges)
    if session_cookie:
        flows.append(session_cookie)

    basic_auth = _detect_basic_auth(exchanges)
    if basic_auth:
        flows.append(basic_auth)

    bearer = _detect_bearer_token(exchanges)
    if bearer:
        flows.append(bearer)

    hmac = _detect_hmac_pattern(exchanges)
    if hmac:
        flows.append(hmac)

    # Detect token refresh across all flows
    refresh_flow = _detect_token_refresh(exchanges, tokens_by_exchange)
    if refresh_flow:
        # Mark refresh on existing flows or add standalone
        marked = False
        for f in flows:
            if f.flow_type in (
                AuthFlowType.OAUTH2_AUTH_CODE,
                AuthFlowType.OAUTH2_PKCE,
                AuthFlowType.OAUTH2_CLIENT_CREDENTIALS,
                AuthFlowType.BEARER_TOKEN,
                AuthFlowType.CUSTOM_LOGIN,
            ):
                f.refresh_detected = True
                f.steps.extend(refresh_flow.steps)
                marked = True
                break
        if not marked:
            flows.append(refresh_flow)

    if not flows:
        flows.append(
            AuthFlow(
                flow_type=AuthFlowType.UNKNOWN,
                description="No recognizable authentication pattern detected.",
            )
        )

    return flows


def _get_request_body_params(ex: HttpExchange) -> Dict[str, str]:
    """Parse request body as form params or JSON into a flat dict."""
    params: Dict[str, str] = {}
    if not ex.request_body:
        return params
    body = ex.request_body
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")

    # Try form-encoded
    ct = ex.request_headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in ct:
        parsed = parse_qs(body, keep_blank_values=True)
        for k, v in parsed.items():
            params[k] = v[0] if v else ""
        return params

    # Try JSON
    if "json" in ct:
        import json

        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    params[k] = str(v) if not isinstance(v, str) else v
        except (ValueError, TypeError):
            pass
        return params

    # Fallback: try form-encoded anyway
    try:
        parsed = parse_qs(body, keep_blank_values=True)
        if parsed:
            for k, v in parsed.items():
                params[k] = v[0] if v else ""
    except Exception:
        pass

    return params


def _detect_oauth2_flows(
    exchanges: List[HttpExchange],
    tokens_by_exchange: Dict[int, List[Token]],
) -> List[AuthFlow]:
    """Detect OAuth2 authorization code, PKCE, client credentials, and device code flows."""
    flows: List[AuthFlow] = []

    for idx, ex in enumerate(exchanges):
        body_params = _get_request_body_params(ex)

        # Check for token endpoint requests
        grant_type = body_params.get("grant_type", "")

        if grant_type == "client_credentials":
            flow = AuthFlow(
                flow_type=AuthFlowType.OAUTH2_CLIENT_CREDENTIALS,
                description="OAuth2 Client Credentials flow detected.",
                token_endpoint=ex.url,
            )
            tokens_received = [
                t.source.split(":")[-1]
                for t in tokens_by_exchange.get(idx, [])
                if t.source.startswith("response:")
            ]
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="token_request",
                    tokens_sent=["client_credentials"],
                    tokens_received=tokens_received,
                    description="Client credentials token request",
                )
            )
            flow.tokens_involved.update(tokens_received)
            # Find subsequent API calls using the token
            _add_api_call_steps(flow, exchanges, tokens_by_exchange, idx + 1)
            flows.append(flow)
            continue

        if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            flow = AuthFlow(
                flow_type=AuthFlowType.OAUTH2_DEVICE_CODE,
                description="OAuth2 Device Code flow detected.",
                token_endpoint=ex.url,
            )
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="device_code_request",
                    description="Device code token request",
                )
            )
            flows.append(flow)
            continue

        if grant_type == "authorization_code":
            # Check for PKCE
            has_pkce = "code_verifier" in body_params
            flow_type = (
                AuthFlowType.OAUTH2_PKCE if has_pkce else AuthFlowType.OAUTH2_AUTH_CODE
            )
            desc = (
                "OAuth2 Authorization Code with PKCE flow detected."
                if has_pkce
                else "OAuth2 Authorization Code flow detected."
            )
            flow = AuthFlow(
                flow_type=flow_type,
                description=desc,
                token_endpoint=ex.url,
            )
            if "redirect_uri" in body_params:
                flow.redirect_uri = body_params["redirect_uri"]
            tokens_received = [
                t.source.split(":")[-1]
                for t in tokens_by_exchange.get(idx, [])
                if t.source.startswith("response:")
            ]
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="token_request",
                    tokens_sent=["authorization_code"],
                    tokens_received=tokens_received,
                    description="Exchange authorization code for tokens",
                )
            )
            flow.tokens_involved.update(tokens_received)
            _add_api_call_steps(flow, exchanges, tokens_by_exchange, idx + 1)
            flows.append(flow)
            continue

        # Check for authorization redirects (code in URL query)
        parsed_url = urlparse(ex.url)
        query_params = parse_qs(parsed_url.query)

        if "code_challenge" in body_params or "code_challenge" in query_params:
            # PKCE authorize step — look ahead for the token exchange
            flow = AuthFlow(
                flow_type=AuthFlowType.OAUTH2_PKCE,
                description="OAuth2 Authorization Code with PKCE flow detected.",
            )
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="authorize_request",
                    tokens_sent=["code_challenge"],
                    description="PKCE authorization request with code_challenge",
                )
            )
            flows.append(flow)
            continue

        # Detect redirect with ?code= parameter (auth code callback)
        if (
            ex.status_code in (301, 302, 303, 307, 308)
            and "location" in ex.response_headers
        ):
            location = ex.response_headers["location"]
            loc_parsed = urlparse(location)
            loc_params = parse_qs(loc_parsed.query)
            if "code" in loc_params:
                flow = AuthFlow(
                    flow_type=AuthFlowType.OAUTH2_AUTH_CODE,
                    description="OAuth2 Authorization Code flow detected (redirect with code).",
                    redirect_uri=location.split("?")[0],
                )
                flow.steps.append(
                    AuthStep(
                        exchange_index=idx,
                        url=ex.url,
                        method=ex.method,
                        step_type="redirect",
                        tokens_received=["authorization_code"],
                        description="Redirect with authorization code",
                    )
                )
                flows.append(flow)
                continue

    return flows


def _add_api_call_steps(
    flow: AuthFlow,
    exchanges: List[HttpExchange],
    tokens_by_exchange: Dict[int, List[Token]],
    start_idx: int,
) -> None:
    """Add subsequent API call steps that use tokens from the flow."""
    for idx in range(start_idx, len(exchanges)):
        ex = exchanges[idx]
        req_tokens = [
            t
            for t in tokens_by_exchange.get(idx, [])
            if t.source.startswith("request:")
        ]
        if req_tokens:
            token_names = [t.source.split(":")[-1] for t in req_tokens]
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="api_call_with_token",
                    tokens_sent=token_names,
                    description=f"API call with auth token to {ex.url}",
                )
            )
            flow.tokens_involved.update(token_names)


def _detect_custom_login(
    exchanges: List[HttpExchange],
    tokens_by_exchange: Dict[int, List[Token]],
) -> Optional[AuthFlow]:
    """Detect custom login flow (POST to login endpoint returning a token)."""
    for idx, ex in enumerate(exchanges):
        if ex.method != "POST":
            continue
        url_lower = ex.url.lower()
        if not _LOGIN_URL_PATTERNS.search(url_lower):
            continue
        # Skip if this is an OAuth token endpoint
        if _OAUTH_URL_PATTERNS.search(url_lower):
            continue

        # Check if response contains token-like fields
        resp_tokens = [
            t
            for t in tokens_by_exchange.get(idx, [])
            if t.source.startswith("response:")
        ]
        if not resp_tokens:
            continue

        flow = AuthFlow(
            flow_type=AuthFlowType.CUSTOM_LOGIN,
            description="Custom login flow detected.",
            login_endpoint=ex.url,
        )
        token_names = [t.source.split(":")[-1] for t in resp_tokens]
        flow.steps.append(
            AuthStep(
                exchange_index=idx,
                url=ex.url,
                method=ex.method,
                step_type="login_request",
                tokens_received=token_names,
                description=f"Login request to {ex.url}",
            )
        )
        flow.tokens_involved.update(token_names)

        # Find subsequent requests using the token
        _add_api_call_steps(flow, exchanges, tokens_by_exchange, idx + 1)
        return flow

    return None


def _detect_api_key(exchanges: List[HttpExchange]) -> Optional[AuthFlow]:
    """Detect static API key usage (same key header across all requests)."""
    api_key_headers = ("x-api-key", "apikey", "api-key", "api_key")
    header_values: Dict[str, Set[str]] = {}

    for ex in exchanges:
        for hname in api_key_headers:
            val = ex.request_headers.get(hname, "")
            if val:
                header_values.setdefault(hname, set()).add(val)

    for hname, values in header_values.items():
        if len(values) == 1:
            # Same value across all requests that have it
            flow = AuthFlow(
                flow_type=AuthFlowType.API_KEY_STATIC,
                description=f"Static API key detected in {hname} header.",
                tokens_involved={hname},
            )
            for idx, ex in enumerate(exchanges):
                if ex.request_headers.get(hname, ""):
                    flow.steps.append(
                        AuthStep(
                            exchange_index=idx,
                            url=ex.url,
                            method=ex.method,
                            step_type="api_call_with_token",
                            tokens_sent=[hname],
                            description=f"Request with {hname} header",
                        )
                    )
            return flow

    return None


def _detect_session_cookie(exchanges: List[HttpExchange]) -> Optional[AuthFlow]:
    """Detect session cookie flow (Set-Cookie in response, Cookie in subsequent requests)."""
    steps: List[AuthStep] = []
    session_cookie_name: Optional[str] = None

    for idx, ex in enumerate(exchanges):
        # Check for Set-Cookie in response
        set_cookie = ex.response_headers.get("set-cookie", "")
        if set_cookie:
            for part in set_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    cname = part.split("=", 1)[0].strip()
                    if _SESSION_COOKIE_NAMES.match(cname):
                        session_cookie_name = cname
                        steps.append(
                            AuthStep(
                                exchange_index=idx,
                                url=ex.url,
                                method=ex.method,
                                step_type="token_response",
                                tokens_received=[cname],
                                description=f"Server sets session cookie: {cname}",
                            )
                        )
                        break

        # Check for Cookie header with session cookie
        cookie_header = ex.request_headers.get("cookie", "")
        if cookie_header and session_cookie_name:
            if session_cookie_name in cookie_header:
                steps.append(
                    AuthStep(
                        exchange_index=idx,
                        url=ex.url,
                        method=ex.method,
                        step_type="api_call_with_token",
                        tokens_sent=[session_cookie_name],
                        description=f"Request with session cookie: {session_cookie_name}",
                    )
                )

    if session_cookie_name and steps:
        return AuthFlow(
            flow_type=AuthFlowType.SESSION_COOKIE,
            description=f"Session cookie flow detected ({session_cookie_name}).",
            steps=steps,
            tokens_involved={session_cookie_name},
        )

    return None


def _detect_basic_auth(exchanges: List[HttpExchange]) -> Optional[AuthFlow]:
    """Detect HTTP Basic Authentication."""
    steps: List[AuthStep] = []

    for idx, ex in enumerate(exchanges):
        auth = ex.request_headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="api_call_with_token",
                    tokens_sent=["basic_credentials"],
                    description="Request with Basic auth credentials",
                )
            )

    if steps:
        return AuthFlow(
            flow_type=AuthFlowType.BASIC_AUTH,
            description="HTTP Basic Authentication detected.",
            steps=steps,
            tokens_involved={"basic_credentials"},
        )

    return None


def _detect_bearer_token(exchanges: List[HttpExchange]) -> Optional[AuthFlow]:
    """Detect static bearer token (same token value across all requests, no refresh)."""
    bearer_values: Set[str] = set()
    bearer_exchanges: List[Tuple[int, HttpExchange]] = []

    for idx, ex in enumerate(exchanges):
        auth = ex.request_headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            value = auth[7:].strip()
            bearer_values.add(value)
            bearer_exchanges.append((idx, ex))

    # Only flag as static bearer if exactly one value used across all bearer requests
    if len(bearer_values) == 1 and bearer_exchanges:
        flow = AuthFlow(
            flow_type=AuthFlowType.BEARER_TOKEN,
            description="Static Bearer token detected.",
            tokens_involved={"bearer_token"},
        )
        for idx, ex in bearer_exchanges:
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="api_call_with_token",
                    tokens_sent=["bearer_token"],
                    description="Request with Bearer token",
                )
            )
        return flow

    return None


def _detect_hmac_pattern(exchanges: List[HttpExchange]) -> Optional[AuthFlow]:
    """Detect HMAC/Signature authentication patterns.

    Looks for headers with high-entropy values that change every request
    while other identifying headers stay constant. Common patterns include
    X-Signature, X-HMAC, or Authorization with a signature component,
    especially when paired with a timestamp header.
    """
    if len(exchanges) < 2:
        return None

    signature_headers = (
        "x-signature",
        "x-hmac",
        "x-mac",
        "x-request-signature",
        "x-auth-signature",
    )
    timestamp_headers = (
        "x-timestamp",
        "x-date",
        "x-request-time",
        "x-nonce",
    )

    # Collect header values across all exchanges
    header_values: Dict[str, List[str]] = {}
    for ex in exchanges:
        for hname, hval in ex.request_headers.items():
            header_values.setdefault(hname, []).append(hval)

    # Find signature-like headers: present in most requests, high entropy, values change
    sig_header_name: Optional[str] = None
    has_timestamp = False

    for hname in signature_headers:
        values = header_values.get(hname, [])
        if len(values) >= 2 and len(set(values)) > 1:
            # Check entropy of values
            avg_entropy = sum(_shannon_entropy(v) for v in values) / len(values)
            if avg_entropy > 2.5:
                sig_header_name = hname
                break

    if not sig_header_name:
        # Check for Authorization header with signature-like pattern
        auth_values = header_values.get("authorization", [])
        if len(auth_values) >= 2 and len(set(auth_values)) > 1:
            # Check if values contain "signature" or similar
            if any("signature" in v.lower() for v in auth_values):
                sig_header_name = "authorization"

    if not sig_header_name:
        return None

    # Check for timestamp header
    for hname in timestamp_headers:
        if hname in header_values and len(header_values[hname]) >= 2:
            has_timestamp = True
            break

    flow = AuthFlow(
        flow_type=AuthFlowType.HMAC_SIGNATURE,
        description=f"HMAC/Signature authentication detected via {sig_header_name} header."
        + (" Timestamp header present." if has_timestamp else ""),
        tokens_involved={sig_header_name},
    )

    for idx, ex in enumerate(exchanges):
        if ex.request_headers.get(sig_header_name, ""):
            tokens_sent = [sig_header_name]
            if has_timestamp:
                tokens_sent.append("timestamp")
            flow.steps.append(
                AuthStep(
                    exchange_index=idx,
                    url=ex.url,
                    method=ex.method,
                    step_type="api_call_with_token",
                    tokens_sent=tokens_sent,
                    description=f"Signed request with {sig_header_name}",
                )
            )

    return flow


def _detect_token_refresh(
    exchanges: List[HttpExchange],
    tokens_by_exchange: Dict[int, List[Token]],
) -> Optional[AuthFlow]:
    """Detect token refresh pattern: 401 -> token request -> new token used."""
    for idx in range(len(exchanges) - 2):
        ex = exchanges[idx]
        if ex.status_code != 401:
            continue

        # Look at next exchange for token refresh
        next_ex = exchanges[idx + 1]
        body_params = _get_request_body_params(next_ex)
        grant_type = body_params.get("grant_type", "")

        is_refresh = grant_type == "refresh_token" or _OAUTH_URL_PATTERNS.search(
            next_ex.url.lower()
        )
        if not is_refresh:
            continue

        # Check if the exchange after that uses a new token
        resp_tokens = [
            t
            for t in tokens_by_exchange.get(idx + 1, [])
            if t.source.startswith("response:")
        ]
        if not resp_tokens:
            continue

        flow = AuthFlow(
            flow_type=AuthFlowType.UNKNOWN,
            description="Token refresh flow detected (401 -> refresh -> new token).",
            refresh_detected=True,
        )
        flow.steps.append(
            AuthStep(
                exchange_index=idx,
                url=ex.url,
                method=ex.method,
                step_type="token_expired",
                description="Request received 401 Unauthorized",
            )
        )
        flow.steps.append(
            AuthStep(
                exchange_index=idx + 1,
                url=next_ex.url,
                method=next_ex.method,
                step_type="token_refresh",
                tokens_received=[t.source.split(":")[-1] for t in resp_tokens],
                description="Token refresh request",
            )
        )
        if idx + 2 < len(exchanges):
            after_ex = exchanges[idx + 2]
            req_tokens = [
                t
                for t in tokens_by_exchange.get(idx + 2, [])
                if t.source.startswith("request:")
            ]
            if req_tokens:
                flow.steps.append(
                    AuthStep(
                        exchange_index=idx + 2,
                        url=after_ex.url,
                        method=after_ex.method,
                        step_type="api_call_with_token",
                        tokens_sent=[t.source.split(":")[-1] for t in req_tokens],
                        description="Request with refreshed token",
                    )
                )
        return flow

    return None


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
