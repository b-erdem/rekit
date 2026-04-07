"""Tests for rekit.authmap — auth flow detection and code generation."""

from __future__ import annotations

import ast
import json
from datetime import datetime
from typing import List

from rekit.authmap.detector import (
    AuthFlow,
    AuthFlowType,
    AuthStep,
    detect_auth_flows,
)
from rekit.authmap.generator import generate_auth_module
from rekit.hargen.parser import HttpExchange


# ---------------------------------------------------------------------------
# Helpers to build realistic exchanges
# ---------------------------------------------------------------------------


def _make_exchange(
    method: str = "GET",
    url: str = "https://api.example.com/resource",
    request_headers: dict | None = None,
    request_body: str | None = None,
    status_code: int = 200,
    response_headers: dict | None = None,
    response_body: str | None = None,
    content_type: str = "",
    timestamp: datetime | None = None,
) -> HttpExchange:
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
# OAuth2 Authorization Code Flow
# ---------------------------------------------------------------------------


class TestOAuth2AuthCodeFlow:
    def _build_exchanges(self) -> List[HttpExchange]:
        """Build a realistic OAuth2 auth code flow: authorize redirect, token exchange, API call."""
        return [
            # Step 1: Authorization redirect with ?code= in Location
            _make_exchange(
                method="GET",
                url="https://auth.example.com/oauth/authorize?response_type=code&client_id=my_app&redirect_uri=https://app.example.com/callback",
                status_code=302,
                response_headers={
                    "location": "https://app.example.com/callback?code=AUTH_CODE_12345"
                },
            ),
            # Step 2: Token exchange
            _make_exchange(
                method="POST",
                url="https://auth.example.com/oauth/token",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="grant_type=authorization_code&code=AUTH_CODE_12345&redirect_uri=https://app.example.com/callback&client_id=my_app",
                status_code=200,
                response_body=json.dumps(
                    {
                        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxaOoaBSTLJoQ4w",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4gZm9yIHRlc3Rpbmc",
                    }
                ),
                content_type="application/json",
            ),
            # Step 3: API call with bearer token
            _make_exchange(
                method="GET",
                url="https://api.example.com/users/me",
                request_headers={
                    "authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxaOoaBSTLJoQ4w"
                },
                status_code=200,
                response_body=json.dumps({"id": 1, "name": "John Doe"}),
                content_type="application/json",
            ),
        ]

    def test_detect_oauth2_auth_code(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        auth_code_flows = [
            f for f in flows if f.flow_type == AuthFlowType.OAUTH2_AUTH_CODE
        ]
        assert len(auth_code_flows) >= 1
        flow = auth_code_flows[0]
        assert flow.flow_type == AuthFlowType.OAUTH2_AUTH_CODE
        assert len(flow.steps) >= 1

    def test_redirect_with_code_detected(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        auth_code_flows = [
            f for f in flows if f.flow_type == AuthFlowType.OAUTH2_AUTH_CODE
        ]
        # Should have found the redirect step and the token exchange step
        redirect_steps = []
        token_steps = []
        for f in auth_code_flows:
            for s in f.steps:
                if s.step_type == "redirect":
                    redirect_steps.append(s)
                if s.step_type == "token_request":
                    token_steps.append(s)
        assert len(redirect_steps) >= 1 or len(token_steps) >= 1


# ---------------------------------------------------------------------------
# OAuth2 PKCE Flow
# ---------------------------------------------------------------------------


class TestOAuth2PKCEFlow:
    def _build_exchanges(self) -> List[HttpExchange]:
        return [
            # PKCE token exchange with code_verifier
            _make_exchange(
                method="POST",
                url="https://auth.example.com/oauth/token",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="grant_type=authorization_code&code=PKCE_CODE_ABCDE&redirect_uri=https://app.example.com/callback&client_id=my_app&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                status_code=200,
                response_body=json.dumps(
                    {
                        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxaOoaBSTLJoQ4w",
                        "token_type": "bearer",
                        "expires_in": 3600,
                    }
                ),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/data",
                request_headers={
                    "authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxaOoaBSTLJoQ4w"
                },
                status_code=200,
                response_body=json.dumps({"data": "stuff"}),
                content_type="application/json",
            ),
        ]

    def test_detect_pkce(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        pkce_flows = [f for f in flows if f.flow_type == AuthFlowType.OAUTH2_PKCE]
        assert len(pkce_flows) >= 1
        assert pkce_flows[0].token_endpoint == "https://auth.example.com/oauth/token"


# ---------------------------------------------------------------------------
# OAuth2 Client Credentials Flow
# ---------------------------------------------------------------------------


class TestOAuth2ClientCredentialsFlow:
    def _build_exchanges(self) -> List[HttpExchange]:
        return [
            _make_exchange(
                method="POST",
                url="https://auth.example.com/oauth/token",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="grant_type=client_credentials&client_id=service_app&client_secret=s3cr3t",
                status_code=200,
                response_body=json.dumps(
                    {
                        "access_token": "cc_token_abcdef1234567890abcdef1234567890",
                        "token_type": "bearer",
                        "expires_in": 7200,
                    }
                ),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/internal/data",
                request_headers={
                    "authorization": "Bearer cc_token_abcdef1234567890abcdef1234567890"
                },
                status_code=200,
                response_body=json.dumps({"internal": "data"}),
                content_type="application/json",
            ),
        ]

    def test_detect_client_credentials(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        cc_flows = [
            f for f in flows if f.flow_type == AuthFlowType.OAUTH2_CLIENT_CREDENTIALS
        ]
        assert len(cc_flows) >= 1
        assert cc_flows[0].token_endpoint == "https://auth.example.com/oauth/token"


# ---------------------------------------------------------------------------
# Custom Login Flow
# ---------------------------------------------------------------------------


class TestCustomLoginFlow:
    def _build_exchanges(self) -> List[HttpExchange]:
        return [
            # Login POST
            _make_exchange(
                method="POST",
                url="https://api.example.com/login",
                request_headers={"content-type": "application/json"},
                request_body=json.dumps(
                    {"username": "testuser", "password": "testpass"}
                ),
                status_code=200,
                response_body=json.dumps(
                    {
                        "access_token": "custom_tok_xYz987654321AbCdEfGhIjKlMnOpQrStUvWx",
                        "expires_in": 3600,
                    }
                ),
                content_type="application/json",
            ),
            # Subsequent API call
            _make_exchange(
                method="GET",
                url="https://api.example.com/profile",
                request_headers={
                    "authorization": "Bearer custom_tok_xYz987654321AbCdEfGhIjKlMnOpQrStUvWx"
                },
                status_code=200,
                response_body=json.dumps({"user": "testuser"}),
                content_type="application/json",
            ),
        ]

    def test_detect_custom_login(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        login_flows = [f for f in flows if f.flow_type == AuthFlowType.CUSTOM_LOGIN]
        assert len(login_flows) >= 1
        flow = login_flows[0]
        assert flow.login_endpoint == "https://api.example.com/login"
        assert any(s.step_type == "login_request" for s in flow.steps)

    def test_subsequent_api_calls_tracked(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        login_flows = [f for f in flows if f.flow_type == AuthFlowType.CUSTOM_LOGIN]
        assert len(login_flows) >= 1
        flow = login_flows[0]
        api_steps = [s for s in flow.steps if s.step_type == "api_call_with_token"]
        assert len(api_steps) >= 1


# ---------------------------------------------------------------------------
# API Key Detection
# ---------------------------------------------------------------------------


class TestAPIKeyDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        return [
            _make_exchange(
                method="GET",
                url="https://api.example.com/data",
                request_headers={"x-api-key": "ak_live_xYz987654321AbCdEfGhIjKl"},
                status_code=200,
                response_body=json.dumps({"data": [1, 2, 3]}),
                content_type="application/json",
            ),
            _make_exchange(
                method="POST",
                url="https://api.example.com/data",
                request_headers={
                    "x-api-key": "ak_live_xYz987654321AbCdEfGhIjKl",
                    "content-type": "application/json",
                },
                request_body=json.dumps({"value": 42}),
                status_code=201,
                response_body=json.dumps({"id": 99}),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/data/99",
                request_headers={"x-api-key": "ak_live_xYz987654321AbCdEfGhIjKl"},
                status_code=200,
                response_body=json.dumps({"id": 99, "value": 42}),
                content_type="application/json",
            ),
        ]

    def test_detect_api_key(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        api_key_flows = [f for f in flows if f.flow_type == AuthFlowType.API_KEY_STATIC]
        assert len(api_key_flows) == 1
        flow = api_key_flows[0]
        assert "x-api-key" in flow.tokens_involved
        assert len(flow.steps) == 3


# ---------------------------------------------------------------------------
# Session Cookie Detection
# ---------------------------------------------------------------------------


class TestSessionCookieDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        return [
            # Server sets session cookie
            _make_exchange(
                method="POST",
                url="https://app.example.com/login",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="username=admin&password=pass",
                status_code=200,
                response_headers={
                    "set-cookie": "JSESSIONID=abc123def456ghi789jkl012mno345pqr678; Path=/; HttpOnly"
                },
                response_body="<html>Welcome</html>",
                content_type="text/html",
            ),
            # Subsequent request with cookie
            _make_exchange(
                method="GET",
                url="https://app.example.com/dashboard",
                request_headers={
                    "cookie": "JSESSIONID=abc123def456ghi789jkl012mno345pqr678"
                },
                status_code=200,
                response_body="<html>Dashboard</html>",
                content_type="text/html",
            ),
            # Another request with cookie
            _make_exchange(
                method="GET",
                url="https://app.example.com/api/stats",
                request_headers={
                    "cookie": "JSESSIONID=abc123def456ghi789jkl012mno345pqr678"
                },
                status_code=200,
                response_body=json.dumps({"visitors": 42}),
                content_type="application/json",
            ),
        ]

    def test_detect_session_cookie(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        cookie_flows = [f for f in flows if f.flow_type == AuthFlowType.SESSION_COOKIE]
        assert len(cookie_flows) == 1
        flow = cookie_flows[0]
        assert "JSESSIONID" in flow.tokens_involved
        # Should have the set-cookie step and at least one api call step
        assert any(s.step_type == "token_response" for s in flow.steps)
        assert any(s.step_type == "api_call_with_token" for s in flow.steps)


# ---------------------------------------------------------------------------
# Bearer Token Detection (static)
# ---------------------------------------------------------------------------


class TestBearerTokenDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        token = "static_bearer_AbCdEf123456GhIjKlMnOpQrStUvWxYz"
        return [
            _make_exchange(
                method="GET",
                url="https://api.example.com/v1/users",
                request_headers={"authorization": f"Bearer {token}"},
                status_code=200,
                response_body=json.dumps({"users": []}),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/v1/items",
                request_headers={"authorization": f"Bearer {token}"},
                status_code=200,
                response_body=json.dumps({"items": []}),
                content_type="application/json",
            ),
        ]

    def test_detect_bearer_token(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        bearer_flows = [f for f in flows if f.flow_type == AuthFlowType.BEARER_TOKEN]
        assert len(bearer_flows) == 1
        assert len(bearer_flows[0].steps) == 2


# ---------------------------------------------------------------------------
# Basic Auth Detection
# ---------------------------------------------------------------------------


class TestBasicAuthDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        # Basic auth: base64("admin:password") = "YWRtaW46cGFzc3dvcmQ="
        return [
            _make_exchange(
                method="GET",
                url="https://api.example.com/protected",
                request_headers={"authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
                status_code=200,
                response_body=json.dumps({"status": "ok"}),
                content_type="application/json",
            ),
            _make_exchange(
                method="POST",
                url="https://api.example.com/protected/action",
                request_headers={
                    "authorization": "Basic YWRtaW46cGFzc3dvcmQ=",
                    "content-type": "application/json",
                },
                request_body=json.dumps({"action": "do_thing"}),
                status_code=200,
                response_body=json.dumps({"result": "done"}),
                content_type="application/json",
            ),
        ]

    def test_detect_basic_auth(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        basic_flows = [f for f in flows if f.flow_type == AuthFlowType.BASIC_AUTH]
        assert len(basic_flows) == 1
        assert len(basic_flows[0].steps) == 2


# ---------------------------------------------------------------------------
# HMAC Signature Detection
# ---------------------------------------------------------------------------


class TestHMACSignatureDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        """Build exchanges with changing X-Signature and X-Timestamp headers."""
        return [
            _make_exchange(
                method="GET",
                url="https://api.example.com/secure/data",
                request_headers={
                    "x-api-key": "static_key_123456789012345678",
                    "x-signature": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
                    "x-timestamp": "1700000001",
                },
                status_code=200,
                response_body=json.dumps({"data": 1}),
                content_type="application/json",
            ),
            _make_exchange(
                method="POST",
                url="https://api.example.com/secure/data",
                request_headers={
                    "x-api-key": "static_key_123456789012345678",
                    "x-signature": "f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1",
                    "x-timestamp": "1700000002",
                    "content-type": "application/json",
                },
                request_body=json.dumps({"value": "test"}),
                status_code=200,
                response_body=json.dumps({"id": 42}),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/secure/data/42",
                request_headers={
                    "x-api-key": "static_key_123456789012345678",
                    "x-signature": "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
                    "x-timestamp": "1700000003",
                },
                status_code=200,
                response_body=json.dumps({"id": 42, "value": "test"}),
                content_type="application/json",
            ),
        ]

    def test_detect_hmac_signature(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        hmac_flows = [f for f in flows if f.flow_type == AuthFlowType.HMAC_SIGNATURE]
        assert len(hmac_flows) == 1
        flow = hmac_flows[0]
        assert "x-signature" in flow.tokens_involved
        assert len(flow.steps) == 3
        # Each step should send both signature and timestamp
        for step in flow.steps:
            assert "x-signature" in step.tokens_sent
            assert "timestamp" in step.tokens_sent


# ---------------------------------------------------------------------------
# Token Refresh Detection
# ---------------------------------------------------------------------------


class TestTokenRefreshDetection:
    def _build_exchanges(self) -> List[HttpExchange]:
        """Build: API call -> 401 -> refresh -> API call with new token."""
        old_token = "old_bearer_token_AbCdEf123456GhIjKlMnOp"
        new_token = "new_bearer_token_QrStUvWxYz789012AbCdEf"
        return [
            # Normal API call
            _make_exchange(
                method="GET",
                url="https://api.example.com/data",
                request_headers={"authorization": f"Bearer {old_token}"},
                status_code=200,
                response_body=json.dumps({"data": "ok"}),
                content_type="application/json",
            ),
            # Token expired - 401
            _make_exchange(
                method="GET",
                url="https://api.example.com/data",
                request_headers={"authorization": f"Bearer {old_token}"},
                status_code=401,
                response_body=json.dumps({"error": "token_expired"}),
                content_type="application/json",
            ),
            # Token refresh
            _make_exchange(
                method="POST",
                url="https://auth.example.com/oauth/token",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="grant_type=refresh_token&refresh_token=my_refresh_tok_abcdef1234567890",
                status_code=200,
                response_body=json.dumps(
                    {
                        "access_token": new_token,
                        "expires_in": 3600,
                    }
                ),
                content_type="application/json",
            ),
            # Retry with new token
            _make_exchange(
                method="GET",
                url="https://api.example.com/data",
                request_headers={"authorization": f"Bearer {new_token}"},
                status_code=200,
                response_body=json.dumps({"data": "ok_again"}),
                content_type="application/json",
            ),
        ]

    def test_detect_token_refresh(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        # Should detect refresh in at least one flow
        has_refresh = any(f.refresh_detected for f in flows)
        assert has_refresh

    def test_refresh_steps_present(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        all_steps = []
        for f in flows:
            all_steps.extend(f.steps)
        step_types = {s.step_type for s in all_steps}
        assert "token_expired" in step_types or "token_refresh" in step_types


# ---------------------------------------------------------------------------
# Code Generation Tests
# ---------------------------------------------------------------------------


class TestGenerateAuthModuleOAuth2:
    def test_generate_oauth2_produces_valid_python(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.OAUTH2_AUTH_CODE,
            description="OAuth2 Auth Code",
            token_endpoint="https://auth.example.com/oauth/token",
            redirect_uri="https://app.example.com/callback",
        )
        code = generate_auth_module([flow], class_name="MyOAuth")
        # Verify it's valid Python
        ast.parse(code)
        assert "class MyOAuth:" in code
        assert "def login(" in code
        assert "def refresh_token(" in code
        assert "def _ensure_token(" in code
        assert "def prepare_request(" in code
        assert "authorization_code" in code

    def test_generate_pkce_includes_code_verifier(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.OAUTH2_PKCE,
            description="OAuth2 PKCE",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "code_verifier" in code

    def test_generate_client_credentials(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.OAUTH2_CLIENT_CREDENTIALS,
            description="Client Credentials",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "client_credentials" in code


class TestGenerateAuthModuleAPIKey:
    def test_generate_api_key_produces_valid_python(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.API_KEY_STATIC,
            description="API Key",
            tokens_involved={"x-api-key"},
        )
        code = generate_auth_module([flow], class_name="ApiKeyAuth")
        ast.parse(code)
        assert "class ApiKeyAuth:" in code
        assert "def prepare_request(" in code
        assert "x-api-key" in code


class TestGenerateAuthModuleBasicAuth:
    def test_generate_basic_auth(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.BASIC_AUTH,
            description="Basic Auth",
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "Basic" in code
        assert "base64" in code


class TestGenerateAuthModuleBearerToken:
    def test_generate_bearer(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.BEARER_TOKEN,
            description="Bearer Token",
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "Bearer" in code


class TestGenerateAuthModuleCustomLogin:
    def test_generate_custom_login(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.CUSTOM_LOGIN,
            description="Custom Login",
            login_endpoint="https://api.example.com/auth/login",
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "def authenticate(" in code
        assert "https://api.example.com/auth/login" in code


class TestGenerateAuthModuleHMAC:
    def test_generate_hmac(self):
        flow = AuthFlow(
            flow_type=AuthFlowType.HMAC_SIGNATURE,
            description="HMAC",
            tokens_involved={"x-signature"},
        )
        code = generate_auth_module([flow])
        ast.parse(code)
        assert "hmac" in code.lower()
        assert "_sign_request" in code


# ---------------------------------------------------------------------------
# Multiple Flows in Same Capture
# ---------------------------------------------------------------------------


class TestMultipleFlows:
    def _build_exchanges(self) -> List[HttpExchange]:
        """Build a capture with both API key and session cookie auth."""
        return [
            # API endpoint using API key
            _make_exchange(
                method="GET",
                url="https://api.example.com/v1/items",
                request_headers={"x-api-key": "ak_live_xYz987654321AbCdEfGhIjKl"},
                status_code=200,
                response_body=json.dumps({"items": []}),
                content_type="application/json",
            ),
            _make_exchange(
                method="GET",
                url="https://api.example.com/v1/items/1",
                request_headers={"x-api-key": "ak_live_xYz987654321AbCdEfGhIjKl"},
                status_code=200,
                response_body=json.dumps({"id": 1}),
                content_type="application/json",
            ),
            # Web app using session cookie
            _make_exchange(
                method="POST",
                url="https://app.example.com/login",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                request_body="user=admin&pass=secret",
                status_code=200,
                response_headers={
                    "set-cookie": "session=s3ss10n_c00k1e_v4lu3_l0ng_3n0ugh; Path=/"
                },
                response_body="OK",
                content_type="text/plain",
            ),
            _make_exchange(
                method="GET",
                url="https://app.example.com/dashboard",
                request_headers={"cookie": "session=s3ss10n_c00k1e_v4lu3_l0ng_3n0ugh"},
                status_code=200,
                response_body="<html>Dashboard</html>",
                content_type="text/html",
            ),
        ]

    def test_detect_multiple_flows(self):
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        flow_types = {f.flow_type for f in flows}
        assert AuthFlowType.API_KEY_STATIC in flow_types
        assert AuthFlowType.SESSION_COOKIE in flow_types

    def test_generate_for_first_flow(self):
        """Generate code from a multi-flow capture."""
        exchanges = self._build_exchanges()
        flows = detect_auth_flows(exchanges)
        code = generate_auth_module(flows[:1])
        ast.parse(code)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_exchanges(self):
        flows = detect_auth_flows([])
        assert flows == []

    def test_no_auth_exchanges(self):
        exchanges = [
            _make_exchange(
                method="GET",
                url="https://example.com/public",
                status_code=200,
                response_body="Hello",
                content_type="text/plain",
            ),
        ]
        flows = detect_auth_flows(exchanges)
        assert len(flows) == 1
        assert flows[0].flow_type == AuthFlowType.UNKNOWN

    def test_auth_step_dataclass(self):
        step = AuthStep(
            exchange_index=0,
            url="https://example.com",
            method="GET",
            step_type="test",
        )
        assert step.tokens_sent == []
        assert step.tokens_received == []

    def test_auth_flow_dataclass(self):
        flow = AuthFlow(flow_type=AuthFlowType.UNKNOWN)
        assert flow.steps == []
        assert flow.tokens_involved == set()
        assert flow.refresh_detected is False
