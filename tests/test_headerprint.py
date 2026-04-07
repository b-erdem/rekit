"""Tests for the headerprint module -- HTTP/2 and header-order fingerprinting."""

from __future__ import annotations

import pytest

from rekit.hargen.parser import HttpExchange
from rekit.headerprint.analyzer import (
    FingerprintMatch,
    HeaderFingerprint,
    analyze_header_order,
    compare_to_profiles,
    detect_anomalies,
    extract_fingerprint_from_har,
)
from rekit.headerprint.profiles import PROFILES, HeaderProfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CHROME_HEADER_ORDER = [
    "host",
    "connection",
    "cache-control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
]

FIREFOX_HEADER_ORDER = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "priority",
]

PYTHON_HEADER_ORDER = [
    "user-agent",
    "accept-encoding",
    "accept",
    "connection",
]


def _make_exchange(
    headers: dict[str, str], url: str = "https://example.com"
) -> HttpExchange:
    """Build a minimal HttpExchange with the given request headers."""
    return HttpExchange(
        method="GET",
        url=url,
        request_headers=headers,
        status_code=200,
    )


# ---------------------------------------------------------------------------
# HeaderProfile tests
# ---------------------------------------------------------------------------


class TestHeaderProfile:
    def test_creation(self):
        p = HeaderProfile(
            name="test",
            header_order=("a", "b"),
            pseudo_header_order=(":method", ":path"),
            h2_settings={"INITIAL_WINDOW_SIZE": 65536},
            h2_window_update=None,
            h2_priority=None,
            user_agent="test/1.0",
            accept="*/*",
            accept_language="en",
            accept_encoding="gzip",
            connection_type="h2",
        )
        assert p.name == "test"
        assert p.header_order == ("a", "b")

    def test_frozen(self):
        p = PROFILES["chrome_120"]
        with pytest.raises(AttributeError):
            p.name = "modified"  # type: ignore[misc]

    def test_all_profiles_exist(self):
        expected = {
            "chrome_120",
            "firefox_133",
            "safari_18",
            "edge_131",
            "python_requests",
            "curl_default",
        }
        assert expected.issubset(set(PROFILES.keys()))

    def test_profiles_have_required_fields(self):
        for name, p in PROFILES.items():
            assert p.name == name
            assert isinstance(p.header_order, tuple)
            assert isinstance(p.pseudo_header_order, tuple)
            assert isinstance(p.h2_settings, dict)
            assert isinstance(p.user_agent, str)
            assert isinstance(p.connection_type, str)
            assert p.connection_type in ("h2", "http/1.1")

    def test_pseudo_header_order_differs(self):
        """Chrome, Firefox, and Safari must have different pseudo-header orders."""
        chrome = PROFILES["chrome_120"].pseudo_header_order
        firefox = PROFILES["firefox_133"].pseudo_header_order
        safari = PROFILES["safari_18"].pseudo_header_order

        assert chrome != firefox
        assert chrome != safari
        assert firefox != safari


# ---------------------------------------------------------------------------
# analyze_header_order tests
# ---------------------------------------------------------------------------


class TestAnalyzeHeaderOrder:
    def test_identical_order_returns_one(self):
        profile = PROFILES["chrome_120"]
        score = analyze_header_order(list(profile.header_order), profile)
        assert score == pytest.approx(1.0)

    def test_reversed_order_gives_low_score(self):
        profile = PROFILES["chrome_120"]
        reversed_order = list(reversed(profile.header_order))
        score = analyze_header_order(reversed_order, profile)
        # Reversed order should have a much lower LCS-based score.
        assert score < 0.5

    def test_partial_match(self):
        profile = PROFILES["chrome_120"]
        # Take every other header.
        partial = list(profile.header_order[::2])
        score = analyze_header_order(partial, profile)
        assert 0.3 < score < 1.0

    def test_empty_observed(self):
        profile = PROFILES["chrome_120"]
        assert analyze_header_order([], profile) == 0.0

    def test_disjoint_headers(self):
        profile = PROFILES["chrome_120"]
        score = analyze_header_order(["x-custom-1", "x-custom-2"], profile)
        assert score == 0.0


# ---------------------------------------------------------------------------
# compare_to_profiles tests
# ---------------------------------------------------------------------------


class TestCompareToProfiles:
    def test_returns_best_match_first(self):
        matches = compare_to_profiles(
            HeaderFingerprint(header_order=CHROME_HEADER_ORDER)
        )
        assert len(matches) > 0
        # Similarity should be non-increasing.
        for i in range(len(matches) - 1):
            assert matches[i].similarity >= matches[i + 1].similarity

    def test_chrome_fingerprint_matches_chrome(self):
        fp = HeaderFingerprint(
            header_order=CHROME_HEADER_ORDER,
            pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
            h2_settings={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
        )
        matches = compare_to_profiles(fp)
        assert matches[0].profile_name == "chrome_120"

    def test_firefox_fingerprint_matches_firefox(self):
        fp = HeaderFingerprint(
            header_order=FIREFOX_HEADER_ORDER,
            pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
            h2_settings={
                "HEADER_TABLE_SIZE": 65536,
                "INITIAL_WINDOW_SIZE": 131072,
                "MAX_FRAME_SIZE": 16384,
            },
        )
        matches = compare_to_profiles(fp)
        assert matches[0].profile_name == "firefox_133"

    def test_python_requests_scores_low_against_browsers(self):
        fp = HeaderFingerprint(
            header_order=PYTHON_HEADER_ORDER,
            user_agent="python-requests/2.31.0",
        )
        matches = compare_to_profiles(fp)
        # The best browser match should have a relatively low score.
        browser_matches = [
            m
            for m in matches
            if m.profile_name not in ("python_requests", "curl_default")
        ]
        assert all(m.similarity < 0.7 for m in browser_matches)


# ---------------------------------------------------------------------------
# extract_fingerprint_from_har tests
# ---------------------------------------------------------------------------


class TestExtractFingerprintFromHar:
    def test_basic_extraction(self):
        headers = {
            "Host": "example.com",
            "User-Agent": "TestAgent/1.0",
            "Accept": "text/html",
            "Accept-Encoding": "gzip",
        }
        exchange = _make_exchange(headers)
        fp = extract_fingerprint_from_har([exchange])

        assert fp.header_order == ["host", "user-agent", "accept", "accept-encoding"]
        assert fp.user_agent == "TestAgent/1.0"

    def test_empty_exchanges(self):
        fp = extract_fingerprint_from_har([])
        assert fp.header_order == []

    def test_pseudo_headers_separated(self):
        headers = {
            ":method": "GET",
            ":path": "/",
            ":authority": "example.com",
            ":scheme": "https",
            "user-agent": "Browser/1.0",
            "accept": "text/html",
        }
        exchange = _make_exchange(headers)
        fp = extract_fingerprint_from_har([exchange])

        assert fp.pseudo_header_order == [
            ":method",
            ":path",
            ":authority",
            ":scheme",
        ]
        assert fp.header_order == ["user-agent", "accept"]

    def test_multiple_exchanges_uses_first(self):
        ex1 = _make_exchange({"Host": "a.com", "User-Agent": "First"})
        ex2 = _make_exchange({"Host": "b.com", "User-Agent": "Second"})
        fp = extract_fingerprint_from_har([ex1, ex2])
        assert fp.user_agent == "First"


# ---------------------------------------------------------------------------
# detect_anomalies tests
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    def test_missing_sec_fetch_headers(self):
        fp = HeaderFingerprint(
            header_order=["host", "user-agent", "accept"],
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120.0.0.0"
            ),
        )
        anomalies = detect_anomalies(fp)
        assert any("sec-fetch" in a.lower() for a in anomalies)

    def test_browser_like_no_anomalies(self):
        fp = HeaderFingerprint(
            header_order=CHROME_HEADER_ORDER,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        anomalies = detect_anomalies(fp)
        # A proper Chrome-like fingerprint should have zero anomalies.
        assert len(anomalies) == 0

    def test_python_indicators(self):
        fp = HeaderFingerprint(
            header_order=PYTHON_HEADER_ORDER,
            user_agent="python-requests/2.31.0",
        )
        anomalies = detect_anomalies(fp)
        assert any("python" in a.lower() for a in anomalies)

    def test_missing_accept_language(self):
        fp = HeaderFingerprint(
            header_order=["host", "user-agent", "accept"],
            user_agent="SomeBot/1.0",
        )
        anomalies = detect_anomalies(fp)
        assert any("accept-language" in a.lower() for a in anomalies)

    def test_missing_accept_encoding(self):
        fp = HeaderFingerprint(
            header_order=["host", "user-agent", "accept"],
            user_agent="SomeBot/1.0",
        )
        anomalies = detect_anomalies(fp)
        assert any("accept-encoding" in a.lower() for a in anomalies)

    def test_chromium_ua_missing_hints(self):
        fp = HeaderFingerprint(
            header_order=[
                "host",
                "user-agent",
                "accept",
                "accept-encoding",
                "accept-language",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-dest",
            ],
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120.0.0.0"
            ),
        )
        anomalies = detect_anomalies(fp)
        assert any("sec-ch-ua" in a for a in anomalies)

    def test_few_headers_anomaly(self):
        fp = HeaderFingerprint(
            header_order=["host", "accept"],
            user_agent="Bot/1.0",
        )
        anomalies = detect_anomalies(fp)
        assert any("few headers" in a.lower() for a in anomalies)


# ---------------------------------------------------------------------------
# FingerprintMatch tests
# ---------------------------------------------------------------------------


class TestFingerprintMatch:
    def test_comparison_fields(self):
        m = FingerprintMatch(
            profile_name="chrome_120",
            similarity=0.95,
            header_order_match=0.95,
            pseudo_header_match=1.0,
            h2_settings_match=0.9,
            differences=["H2 settings differ"],
        )
        assert m.profile_name == "chrome_120"
        assert m.similarity == pytest.approx(0.95)
        assert len(m.differences) == 1

    def test_sorting_by_similarity(self):
        m1 = FingerprintMatch(
            profile_name="a",
            similarity=0.8,
            header_order_match=0.8,
            pseudo_header_match=0.8,
            h2_settings_match=0.8,
        )
        m2 = FingerprintMatch(
            profile_name="b",
            similarity=0.95,
            header_order_match=0.95,
            pseudo_header_match=0.95,
            h2_settings_match=0.95,
        )
        ranked = sorted([m1, m2], key=lambda x: x.similarity, reverse=True)
        assert ranked[0].profile_name == "b"
