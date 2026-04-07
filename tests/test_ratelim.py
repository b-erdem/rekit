"""Tests for the ratelim tool -- rate limit probing engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rich.panel import Panel

from rekit.ratelim.prober import (
    ProbeResult,
    binary_search_limit,
    measure_cooldown,
    parse_rate_limit_headers,
    probe_rate_limit,
)
from rekit.ratelim.display import format_probe_result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_response(status_code=200, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.05
    return resp


# ---------------------------------------------------------------------------
# parse_rate_limit_headers
# ---------------------------------------------------------------------------


class TestParseRateLimitHeaders:
    def test_standard_headers(self):
        headers = {
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "42",
            "X-RateLimit-Reset": "30",
        }
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.limit == 100
        assert info.remaining == 42
        assert info.reset_seconds == 30.0

    def test_ietf_draft_headers(self):
        headers = {
            "RateLimit-Limit": "200",
            "RateLimit-Remaining": "150",
            "RateLimit-Reset": "60",
        }
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.limit == 200
        assert info.remaining == 150
        assert info.reset_seconds == 60.0

    def test_retry_after_seconds(self):
        headers = {"Retry-After": "120"}
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.reset_seconds == 120.0

    def test_retry_after_http_date(self):
        # Use a date far in the future so delta is positive
        headers = {"Retry-After": "Sun, 06 Nov 2094 08:49:37 GMT"}
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.reset_seconds is not None
        assert info.reset_seconds > 0

    def test_no_rate_limit_headers(self):
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        info = parse_rate_limit_headers(headers)
        assert info is None

    def test_cf_rate_limit(self):
        headers = {"CF-Rate-Limit": "500"}
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.limit == 500

    def test_x_rate_limit_variant(self):
        headers = {
            "X-Rate-Limit-Limit": "60",
            "X-Rate-Limit-Remaining": "10",
        }
        info = parse_rate_limit_headers(headers)
        assert info is not None
        assert info.limit == 60
        assert info.remaining == 10


# ---------------------------------------------------------------------------
# probe_rate_limit
# ---------------------------------------------------------------------------


class TestProbeRateLimit:
    @patch("rekit.ratelim.prober.measure_cooldown", return_value=10.0)
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_200_then_429(self, mock_request, mock_sleep, mock_cooldown):
        """First 5 requests return 200, then 429s."""
        responses = [make_mock_response(200)] * 5 + [make_mock_response(429)] * 5
        mock_request.side_effect = responses

        result = probe_rate_limit(
            "https://api.example.com/test",
            max_requests=10,
            rps=100.0,
        )

        assert result.successful == 5
        assert result.rate_limited >= 3
        assert result.first_429_at == 6

    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_all_200(self, mock_request, mock_sleep):
        """All requests return 200 -- no rate limit detected."""
        mock_request.return_value = make_mock_response(200)

        result = probe_rate_limit(
            "https://api.example.com/test",
            max_requests=10,
            rps=100.0,
        )

        assert result.successful == 10
        assert result.rate_limited == 0
        assert result.first_429_at is None
        assert result.safe_rps is not None

    @patch("rekit.ratelim.prober.measure_cooldown", return_value=5.0)
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_counts(self, mock_request, mock_sleep, mock_cooldown):
        """Correctly count successful vs rate_limited vs errors."""
        responses = [
            make_mock_response(200),
            make_mock_response(200),
            make_mock_response(500),
            make_mock_response(429),
            make_mock_response(429),
            make_mock_response(429),
        ]
        mock_request.side_effect = responses

        result = probe_rate_limit(
            "https://api.example.com/test",
            max_requests=10,
            rps=100.0,
        )

        assert result.successful == 2
        assert result.errors == 1
        assert result.rate_limited == 3
        assert result.first_429_at == 4

    @patch("rekit.ratelim.prober.measure_cooldown", return_value=None)
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_captures_rate_limit_headers(self, mock_request, mock_sleep, mock_cooldown):
        """Rate limit headers from responses are captured."""
        resp_with_headers = make_mock_response(
            429,
            headers={
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "0",
                "Retry-After": "30",
            },
        )
        responses = [make_mock_response(200)] * 2 + [resp_with_headers] * 3
        mock_request.side_effect = responses

        result = probe_rate_limit(
            "https://api.example.com/test",
            max_requests=10,
            rps=100.0,
        )

        assert result.rate_limit_info is not None
        assert result.rate_limit_info.limit == 100
        assert "X-RateLimit-Limit" in result.headers_seen


# ---------------------------------------------------------------------------
# measure_cooldown
# ---------------------------------------------------------------------------


class TestMeasureCooldown:
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    @patch("rekit.ratelim.prober.time.monotonic")
    def test_recovers_after_delay(self, mock_monotonic, mock_request, mock_sleep):
        """Returns seconds waited when endpoint recovers."""
        # Simulate: first call at t=0, 429; second call at t=5, 200
        mock_monotonic.side_effect = [
            0.0,  # while check
            0.0,  # request start (implicit in the function)
            5.0,  # while check
            5.0,  # after successful request
        ]
        mock_request.side_effect = [
            make_mock_response(429),
            make_mock_response(200),
        ]

        result = measure_cooldown("https://api.example.com/test", max_wait=30.0)

        assert result is not None
        assert result == 5.0


# ---------------------------------------------------------------------------
# binary_search_limit
# ---------------------------------------------------------------------------


class TestBinarySearchLimit:
    @patch("rekit.ratelim.prober.measure_cooldown", return_value=5.0)
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_basic_search(self, mock_request, mock_sleep, mock_cooldown):
        """Binary search converges and returns a result with safe_rps."""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Return 429 roughly half the time to simulate a limit
            if call_count % 3 == 0:
                return make_mock_response(429)
            return make_mock_response(200)

        mock_request.side_effect = side_effect

        result = binary_search_limit(
            "https://api.example.com/test",
            low_rps=1.0,
            high_rps=20.0,
        )

        assert isinstance(result, ProbeResult)
        assert result.safe_rps is not None
        assert result.safe_rps > 0


# ---------------------------------------------------------------------------
# display
# ---------------------------------------------------------------------------


class TestDisplay:
    def test_format_probe_result_returns_panel(self):
        result = ProbeResult(
            url="https://example.com",
            total_requests=50,
            successful=45,
            rate_limited=5,
            errors=0,
            first_429_at=46,
            safe_rps=4.0,
        )
        panel = format_probe_result(result)
        assert isinstance(panel, Panel)


# ---------------------------------------------------------------------------
# ProbeResult safe_rps calculation
# ---------------------------------------------------------------------------


class TestSafeRpsCalculation:
    @patch("rekit.ratelim.prober.measure_cooldown", return_value=10.0)
    @patch("rekit.ratelim.prober.time.sleep")
    @patch("rekit.ratelim.prober.requests.request")
    def test_safe_rps_from_first_429(self, mock_request, mock_sleep, mock_cooldown):
        """safe_rps is calculated with headroom below the 429 threshold."""
        responses = [make_mock_response(200)] * 10 + [make_mock_response(429)] * 3
        mock_request.side_effect = responses

        result = probe_rate_limit(
            "https://api.example.com/test",
            max_requests=20,
            rps=10.0,
        )

        assert result.first_429_at == 11
        assert result.safe_rps is not None
        # safe_rps should be less than the tested rps
        assert result.safe_rps < 10.0
        assert result.safe_rps > 0


# ---------------------------------------------------------------------------
# CLI headers command
# ---------------------------------------------------------------------------


class TestCliHeaders:
    @patch("requests.get")
    def test_headers_command(self, mock_get):
        """The headers CLI command fetches the URL and shows results."""
        mock_get.return_value = make_mock_response(
            200,
            headers={
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "99",
                "Content-Type": "application/json",
            },
        )

        from typer.testing import CliRunner
        from rekit.ratelim.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["headers", "https://api.example.com/test"])

        assert result.exit_code == 0
        mock_get.assert_called_once()
