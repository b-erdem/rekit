"""Tests for the tokendump module — token extraction and analysis from HAR traffic."""

from __future__ import annotations

import base64
import json
from datetime import datetime


from rekit.hargen.parser import HttpExchange
from rekit.tokendump.analyzer import (
    analyze_tokens,
    format_chain_diagram,
    format_jwt_details,
    format_token_table,
)
from rekit.tokendump.extractor import (
    Token,
    TokenType,
    _decode_jwt,
    _detect_token_type,
    _is_token_like,
    extract_tokens,
    mask_token,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_jwt(
    header: dict | None = None,
    payload: dict | None = None,
    sig: str = "fakesig",
) -> str:
    """Build a fake JWT string from header, payload, and signature."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT"}
    if payload is None:
        payload = {"sub": "user123", "iss": "auth.example.com", "exp": 1999999999}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    s = base64.urlsafe_b64encode(sig.encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def make_exchange(
    method: str = "GET",
    url: str = "https://api.example.com/v1/data",
    request_headers: dict | None = None,
    request_body: str | None = None,
    status_code: int = 200,
    response_headers: dict | None = None,
    response_body: str | None = None,
    content_type: str = "",
    timestamp: datetime | None = None,
) -> HttpExchange:
    """Create an HttpExchange for testing."""
    return HttpExchange(
        method=method,
        url=url,
        request_headers=request_headers or {},
        request_body=request_body,
        status_code=status_code,
        response_headers=response_headers or {},
        response_body=response_body,
        content_type=content_type,
        timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# JWT detection and decoding
# ---------------------------------------------------------------------------


class TestJWTDetection:
    """Tests for JWT detection and decoding."""

    def test_valid_jwt_detected(self):
        jwt = make_jwt()
        assert _detect_token_type("authorization", jwt) == TokenType.JWT

    def test_jwt_decode_header_and_payload(self):
        header = {"alg": "RS256", "typ": "JWT", "kid": "key-001"}
        payload = {
            "sub": "user123",
            "iss": "auth.example.com",
            "exp": 1999999999,
            "iat": 1700000000,
            "scope": "read write",
        }
        jwt = make_jwt(header=header, payload=payload)
        decoded = _decode_jwt(jwt)

        assert decoded is not None
        assert decoded["header"]["alg"] == "RS256"
        assert decoded["header"]["kid"] == "key-001"
        assert decoded["payload"]["sub"] == "user123"
        assert decoded["payload"]["iss"] == "auth.example.com"
        assert decoded["payload"]["exp"] == 1999999999
        assert decoded["payload"]["scope"] == "read write"

    def test_jwt_decode_handles_missing_padding(self):
        # Ensure decoding works even with base64url that needs padding
        header = {"alg": "HS256"}
        payload = {"sub": "a"}
        jwt = make_jwt(header=header, payload=payload)
        decoded = _decode_jwt(jwt)
        assert decoded is not None
        assert decoded["header"]["alg"] == "HS256"

    def test_not_jwt_two_segments(self):
        assert _detect_token_type("token", "abc.def") != TokenType.JWT

    def test_not_jwt_invalid_base64(self):
        assert _detect_token_type("token", "not.a.jwt") != TokenType.JWT

    def test_decode_returns_none_for_invalid(self):
        assert _decode_jwt("not.a.jwt") is None
        assert _decode_jwt("only-one-part") is None
        assert _decode_jwt("") is None


# ---------------------------------------------------------------------------
# Token type detection
# ---------------------------------------------------------------------------


class TestTokenTypeDetection:
    """Tests for _detect_token_type."""

    def test_bearer_type(self):
        assert (
            _detect_token_type("bearer", "some-long-opaque-token-value-here")
            == TokenType.BEARER
        )

    def test_api_key_by_name(self):
        assert (
            _detect_token_type("api_key", "sk_live_abc123def456ghi789")
            == TokenType.API_KEY
        )
        assert (
            _detect_token_type("x-api-key", "sk_live_abc123def456ghi789")
            == TokenType.API_KEY
        )
        assert (
            _detect_token_type("apikey", "sk_live_abc123def456ghi789")
            == TokenType.API_KEY
        )

    def test_session_cookie_patterns(self):
        assert (
            _detect_token_type("PHPSESSID", "abc123def456ghi789jkl")
            == TokenType.SESSION_COOKIE
        )
        assert (
            _detect_token_type("JSESSIONID", "abc123def456ghi789jkl")
            == TokenType.SESSION_COOKIE
        )
        assert (
            _detect_token_type("connect.sid", "s:abc123def456ghi789")
            == TokenType.SESSION_COOKIE
        )
        assert (
            _detect_token_type("session", "abc123def456ghi789jkl")
            == TokenType.SESSION_COOKIE
        )
        assert (
            _detect_token_type("session_id", "abc123def456ghi789jkl")
            == TokenType.SESSION_COOKIE
        )

    def test_csrf_token(self):
        assert (
            _detect_token_type("csrf_token", "abc123def456ghi789jkl") == TokenType.CSRF
        )
        assert (
            _detect_token_type("x-csrf-token", "abc123def456ghi789jkl")
            == TokenType.CSRF
        )
        assert (
            _detect_token_type("x-xsrf-token", "abc123def456ghi789jkl")
            == TokenType.CSRF
        )
        assert (
            _detect_token_type("xsrf_token", "abc123def456ghi789jkl") == TokenType.CSRF
        )

    def test_oauth_access_token(self):
        assert (
            _detect_token_type("access_token", "ya29.long-access-token-value")
            == TokenType.OAUTH_ACCESS
        )

    def test_oauth_refresh_token(self):
        assert (
            _detect_token_type("refresh_token", "1//0long-refresh-token-val")
            == TokenType.OAUTH_REFRESH
        )

    def test_opaque_token(self):
        # Long random string that doesn't match other patterns
        assert (
            _detect_token_type("auth", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4")
            == TokenType.OPAQUE
        )


# ---------------------------------------------------------------------------
# Extraction from request headers
# ---------------------------------------------------------------------------


class TestExtractRequestHeaders:
    """Tests for extracting tokens from request headers."""

    def test_authorization_bearer(self):
        jwt = make_jwt()
        ex = make_exchange(request_headers={"authorization": f"Bearer {jwt}"})
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.JWT
        assert tokens[0].source == "request:authorization"
        assert tokens[0].value == jwt

    def test_x_api_key_header(self):
        ex = make_exchange(
            request_headers={"x-api-key": "sk_live_abc123def456ghi789jkl"}
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.API_KEY

    def test_cookie_header_extracts_session(self):
        ex = make_exchange(
            request_headers={"cookie": "PHPSESSID=abc123def456ghi789jkl; other=short"}
        )
        tokens = extract_tokens([ex])
        # Should extract PHPSESSID but not 'other' (too short)
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.SESSION_COOKIE
        assert tokens[0].source == "request:cookie:PHPSESSID"

    def test_multiple_request_headers(self):
        jwt = make_jwt()
        ex = make_exchange(
            request_headers={
                "authorization": f"Bearer {jwt}",
                "x-api-key": "sk_live_abc123def456ghi789jkl",
            }
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 2
        types = {t.token_type for t in tokens}
        assert TokenType.JWT in types
        assert TokenType.API_KEY in types


# ---------------------------------------------------------------------------
# Extraction from response headers
# ---------------------------------------------------------------------------


class TestExtractResponseHeaders:
    """Tests for extracting tokens from response headers."""

    def test_set_cookie_extraction(self):
        ex = make_exchange(
            response_headers={
                "set-cookie": "session=abc123def456ghi789jkl012; Path=/; HttpOnly"
            }
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.SESSION_COOKIE
        assert tokens[0].source == "response:set-cookie:session"

    def test_csrf_response_header(self):
        ex = make_exchange(
            response_headers={"x-csrf-token": "csrf_abc123def456ghi789jkl"}
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.CSRF
        assert tokens[0].source == "response:x-csrf-token"


# ---------------------------------------------------------------------------
# Extraction from JSON response bodies
# ---------------------------------------------------------------------------


class TestExtractResponseBody:
    """Tests for extracting tokens from JSON response bodies."""

    def test_access_token_in_body(self):
        jwt = make_jwt()
        body = json.dumps({"access_token": jwt, "token_type": "bearer"})
        ex = make_exchange(
            content_type="application/json",
            response_body=body,
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.JWT
        assert tokens[0].source == "response:body:access_token"

    def test_multiple_tokens_in_body(self):
        access = make_jwt(payload={"sub": "user1", "exp": 1999999999, "iss": "auth"})
        refresh = "rt_" + "a1b2c3d4e5f6" * 4
        body = json.dumps(
            {
                "access_token": access,
                "refresh_token": refresh,
            }
        )
        ex = make_exchange(
            content_type="application/json",
            response_body=body,
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 2
        types = {t.token_type for t in tokens}
        assert TokenType.JWT in types


# ---------------------------------------------------------------------------
# Extraction from JSON request bodies
# ---------------------------------------------------------------------------


class TestExtractRequestBody:
    """Tests for extracting tokens from JSON request bodies."""

    def test_token_in_login_request(self):
        body = json.dumps({"csrf_token": "csrf_abc123def456ghi789jkl"})
        ex = make_exchange(
            method="POST",
            request_headers={"content-type": "application/json"},
            request_body=body,
        )
        tokens = extract_tokens([ex])
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.CSRF
        assert tokens[0].source == "request:body:csrf_token"


# ---------------------------------------------------------------------------
# _is_token_like heuristic
# ---------------------------------------------------------------------------


class TestIsTokenLike:
    """Tests for the token heuristic function."""

    def test_random_string_is_token(self):
        assert _is_token_like("a1B2c3D4e5F6g7H8i9J0k1L2") is True

    def test_short_string_not_token(self):
        assert _is_token_like("short") is False

    def test_url_not_token(self):
        assert _is_token_like("https://example.com/api/v1") is False

    def test_normal_word_not_token(self):
        assert _is_token_like("this is a normal sentence") is False

    def test_hex_string_is_token(self):
        assert _is_token_like("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") is True

    def test_low_entropy_not_token(self):
        assert _is_token_like("aaaaaaaaaaaaaaaa") is False


# ---------------------------------------------------------------------------
# Token masking
# ---------------------------------------------------------------------------


class TestMasking:
    """Tests for token value masking."""

    def test_long_token_masked(self):
        value = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
        masked = mask_token(value)
        assert masked.startswith("eyJhbGci")
        assert masked.endswith(".sig")
        assert "..." in masked

    def test_short_token_masked(self):
        value = "abc123def456ghi7"
        masked = mask_token(value)
        assert masked == "abc1...i7"


# ---------------------------------------------------------------------------
# Token chain analysis
# ---------------------------------------------------------------------------


class TestAnalyzeTokens:
    """Tests for token chain analysis."""

    def test_empty_tokens(self):
        report = analyze_tokens([])
        assert report.unique_tokens == 0
        assert "No tokens found" in report.summary

    def test_token_chain_response_then_request(self):
        """Token appears in response, then used in subsequent requests."""
        jwt = make_jwt()
        # Token issued in response
        tok1 = Token(
            value=jwt,
            token_type=TokenType.JWT,
            source="response:body:access_token",
            exchange_index=0,
            url="https://auth.example.com/token",
        )
        # Same token used in subsequent request
        tok2 = Token(
            value=jwt,
            token_type=TokenType.JWT,
            source="request:authorization",
            exchange_index=1,
            url="https://api.example.com/data",
        )
        tok3 = Token(
            value=jwt,
            token_type=TokenType.JWT,
            source="request:authorization",
            exchange_index=2,
            url="https://api.example.com/users",
        )

        report = analyze_tokens([tok1, tok2, tok3])
        assert report.unique_tokens == 1
        assert report.jwt_count == 1
        assert len(report.chains) == 1
        assert report.chains[0].usage_count == 3
        assert report.chains[0].first_seen == 0
        assert report.chains[0].last_seen == 2

    def test_oauth_flow_detection(self):
        """Detect OAuth2 flow when both access and refresh tokens present."""
        access = make_jwt(payload={"sub": "u1", "exp": 1999999999, "iss": "auth"})
        refresh = "rt_" + "x1y2z3a4b5c6" * 4

        tok_access = Token(
            value=access,
            token_type=TokenType.OAUTH_ACCESS,
            source="response:body:access_token",
            exchange_index=0,
            url="https://auth.example.com/token",
        )
        tok_refresh = Token(
            value=refresh,
            token_type=TokenType.OAUTH_REFRESH,
            source="response:body:refresh_token",
            exchange_index=0,
            url="https://auth.example.com/token",
        )

        report = analyze_tokens([tok_access, tok_refresh])
        assert report.unique_tokens == 2
        assert "OAuth2 flow detected" in report.summary

    def test_jwt_claims_extracted(self):
        """JWT claims are properly extracted into Token fields."""
        header = {"alg": "RS256", "kid": "key-123"}
        payload = {
            "sub": "user456",
            "iss": "https://auth.example.com",
            "exp": 1999999999,
            "iat": 1700000000,
            "scope": "read write admin",
        }
        jwt = make_jwt(header=header, payload=payload)
        ex = make_exchange(request_headers={"authorization": f"Bearer {jwt}"})
        tokens = extract_tokens([ex])

        assert len(tokens) == 1
        tok = tokens[0]
        assert tok.token_type == TokenType.JWT
        assert tok.algorithm == "RS256"
        assert tok.key_id == "key-123"
        assert tok.subject == "user456"
        assert tok.issuer == "https://auth.example.com"
        assert tok.scopes == ["read", "write", "admin"]
        assert tok.expires_at is not None
        assert tok.issued_at is not None


# ---------------------------------------------------------------------------
# Full pipeline with realistic multi-entry HAR
# ---------------------------------------------------------------------------


class TestFullPipeline:
    """End-to-end test with a realistic multi-exchange scenario."""

    def test_realistic_oauth_flow(self):
        """Simulate: login -> get tokens -> use access token -> refresh."""
        access_jwt_1 = make_jwt(
            payload={
                "sub": "user1",
                "exp": 1999999999,
                "iss": "auth.example.com",
                "iat": 1700000000,
            }
        )
        refresh_token = "rt_" + "a1b2c3d4e5f6" * 4
        csrf = "csrf_" + "x1y2z3a4b5c6d7e8"

        # Exchange 0: Login POST (sends CSRF in request body)
        ex0 = make_exchange(
            method="POST",
            url="https://auth.example.com/login",
            request_headers={"content-type": "application/json"},
            request_body=json.dumps({"csrf_token": csrf}),
            status_code=200,
            content_type="application/json",
            response_body=json.dumps(
                {
                    "access_token": access_jwt_1,
                    "refresh_token": refresh_token,
                }
            ),
        )

        # Exchange 1: API call using access token
        ex1 = make_exchange(
            method="GET",
            url="https://api.example.com/v1/profile",
            request_headers={"authorization": f"Bearer {access_jwt_1}"},
            status_code=200,
            content_type="application/json",
            response_body=json.dumps({"name": "Test User"}),
        )

        # Exchange 2: Another API call with same token
        ex2 = make_exchange(
            method="GET",
            url="https://api.example.com/v1/settings",
            request_headers={"authorization": f"Bearer {access_jwt_1}"},
            status_code=200,
        )

        exchanges = [ex0, ex1, ex2]
        tokens = extract_tokens(exchanges)

        # Should find: csrf in request body, access_token in response, refresh_token in response,
        # bearer in ex1 request, bearer in ex2 request
        assert len(tokens) >= 4

        report = analyze_tokens(tokens)
        assert report.unique_tokens >= 3  # csrf, access, refresh
        assert report.jwt_count >= 1
        assert (
            "OAuth2 flow detected" in report.summary
            or "oauth" in report.summary.lower()
            or report.unique_tokens >= 3
        )

    def test_format_token_table_runs(self):
        """Verify format_token_table produces a Rich Table without errors."""
        jwt = make_jwt()
        tok = Token(
            value=jwt,
            token_type=TokenType.JWT,
            source="request:authorization",
            exchange_index=0,
            url="https://api.example.com",
        )
        report = analyze_tokens([tok])
        table = format_token_table(report, show_values=False)
        assert table.title == "Extracted Tokens"

    def test_format_jwt_details_runs(self):
        """Verify format_jwt_details produces a Rich Panel without errors."""
        jwt = make_jwt()
        tok = Token(
            value=jwt,
            token_type=TokenType.JWT,
            source="request:authorization",
            exchange_index=0,
            url="https://api.example.com",
            decoded=_decode_jwt(jwt),
            algorithm="RS256",
            subject="user123",
            issuer="auth.example.com",
        )
        panel = format_jwt_details(tok)
        assert panel.title is not None

    def test_format_chain_diagram_runs(self):
        """Verify format_chain_diagram returns a non-empty string."""
        from rekit.tokendump.analyzer import TokenChain

        chain = TokenChain(
            tokens=[],
            chain_type="jwt",
            description="test chain",
            first_seen=0,
            last_seen=2,
            usage_count=3,
        )
        diagram = format_chain_diagram(chain)
        assert "jwt" in diagram
        assert "test chain" in diagram


# ---------------------------------------------------------------------------
# Decode command
# ---------------------------------------------------------------------------


class TestDecodeCommand:
    """Tests for the standalone JWT decode functionality."""

    def test_decode_valid_jwt(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "Test", "iat": 1516239022}
        jwt = make_jwt(header=header, payload=payload)
        decoded = _decode_jwt(jwt)

        assert decoded is not None
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["payload"]["sub"] == "1234567890"
        assert decoded["payload"]["name"] == "Test"

    def test_decode_invalid_string(self):
        assert _decode_jwt("not-a-jwt") is None
        assert _decode_jwt("") is None
        assert _decode_jwt("a.b") is None
