"""Tests for rekit.ja3probe — fingerprint profiles, result analysis logic."""

from __future__ import annotations

import pytest

from rekit.ja3probe.fingerprints import FingerprintProfile, PROFILES
from rekit.ja3probe.prober import (
    ProbeResult,
    AnalysisReport,
    _detect_challenge,
    analyze_results,
)


# =========================================================================
# FingerprintProfile
# =========================================================================


class TestFingerprintProfile:
    def test_profiles_registry_not_empty(self):
        assert len(PROFILES) > 0

    def test_chrome_profiles_exist(self):
        chrome_profiles = [k for k in PROFILES if k.startswith("chrome_")]
        assert len(chrome_profiles) >= 5

    def test_safari_profiles_exist(self):
        safari_profiles = [k for k in PROFILES if k.startswith("safari_")]
        assert len(safari_profiles) >= 3

    def test_firefox_profiles_exist(self):
        firefox_profiles = [k for k in PROFILES if k.startswith("firefox_")]
        assert len(firefox_profiles) >= 3

    def test_edge_profiles_exist(self):
        edge_profiles = [k for k in PROFILES if k.startswith("edge_")]
        assert len(edge_profiles) >= 1

    def test_non_browser_profiles_exist(self):
        assert "python_requests" in PROFILES
        assert "curl_default" in PROFILES

    def test_has_impersonation_with_str(self):
        p = FingerprintProfile(
            name="test",
            description="test",
            impersonate_str="chrome120",
            user_agent="test",
            browser_family="chrome",
            version="120",
        )
        assert p.has_impersonation is True

    def test_has_impersonation_without_str(self):
        p = FingerprintProfile(
            name="test",
            description="test",
            impersonate_str=None,
            user_agent="test",
            browser_family="firefox",
            version="102",
        )
        assert p.has_impersonation is False

    def test_firefox_102_no_impersonation(self):
        assert PROFILES["firefox_102"].has_impersonation is False

    def test_chrome_120_has_impersonation(self):
        assert PROFILES["chrome_120"].has_impersonation is True
        assert PROFILES["chrome_120"].impersonate_str == "chrome120"

    def test_profile_browser_families(self):
        families = {p.browser_family for p in PROFILES.values()}
        assert "chrome" in families
        assert "safari" in families
        assert "firefox" in families
        assert "edge" in families

    def test_profile_is_frozen(self):
        p = PROFILES["chrome_120"]
        with pytest.raises(AttributeError):
            p.name = "changed"


# =========================================================================
# _detect_challenge
# =========================================================================


class TestDetectChallenge:
    def test_no_challenge_on_200(self):
        is_chal, system = _detect_challenge(200, {}, "")
        assert is_chal is False

    def test_cloudflare_403_with_cf_ray(self):
        is_chal, system = _detect_challenge(403, {"cf-ray": "abc123"}, "")
        assert is_chal is True
        assert system == "Cloudflare"

    def test_cloudflare_server_header(self):
        is_chal, system = _detect_challenge(
            403, {"server": "cloudflare"}, "Access denied"
        )
        assert is_chal is True
        assert system == "Cloudflare"

    def test_datadome_header(self):
        is_chal, system = _detect_challenge(
            403, {"x-datadome": "1"}, "blocked"
        )
        assert is_chal is True
        assert system == "DataDome"

    def test_datadome_captcha_delivery(self):
        is_chal, system = _detect_challenge(
            200,
            {"x-datadome": "1"},
            '{"url":"https://geo.captcha-delivery.com/captcha/"}',
        )
        assert is_chal is True
        assert system == "DataDome"

    def test_akamai_server_header(self):
        _, system = _detect_challenge(200, {"server": "AkamaiGHost"}, "")
        assert system == "Akamai Bot Manager"

    def test_perimeterx_header_with_403(self):
        is_chal, system = _detect_challenge(
            403, {"x-px-mid": "abc"}, "blocked"
        )
        assert is_chal is True
        assert system == "PerimeterX"

    def test_body_signature_cloudflare(self):
        is_chal, system = _detect_challenge(
            503,
            {},
            "Attention Required! | Cloudflare",
        )
        assert is_chal is True
        assert system == "Cloudflare"

    def test_body_signature_challenges_cloudflare(self):
        is_chal, system = _detect_challenge(
            403,
            {},
            '<script src="https://challenges.cloudflare.com/..."></script>',
        )
        assert is_chal is True
        assert system == "Cloudflare"

    def test_no_challenge_clean_200(self):
        is_chal, system = _detect_challenge(
            200,
            {"content-type": "application/json"},
            '{"data": []}',
        )
        assert is_chal is False
        assert system is None

    def test_generic_blocked_body_with_403(self):
        is_chal, system = _detect_challenge(403, {}, "You have been blocked")
        assert is_chal is True

    def test_429_with_protection_header(self):
        is_chal, system = _detect_challenge(
            429, {"x-datadome-cid": "abc"}, ""
        )
        assert is_chal is True
        assert system == "DataDome"


# =========================================================================
# analyze_results
# =========================================================================


class TestAnalyzeResults:
    def _make_result(
        self,
        name: str,
        accepted: bool,
        status: int = 200,
        challenge: bool = False,
        headers: dict | None = None,
    ) -> ProbeResult:
        return ProbeResult(
            profile_name=name,
            accepted=accepted,
            status_code=status,
            challenge_detected=challenge,
            headers_received=headers or {},
        )

    def test_all_accepted(self):
        results = [
            self._make_result("chrome_120", True),
            self._make_result("safari_17_0", True),
        ]
        report = analyze_results("https://example.com", results)
        assert report.accepted_count == 2
        assert report.rejected_count == 0
        assert report.protection_system is None

    def test_all_rejected(self):
        results = [
            self._make_result(
                "chrome_120", False, status=403, challenge=True,
                headers={"cf-ray": "abc"},
            ),
            self._make_result(
                "safari_17_0", False, status=403, challenge=True,
                headers={"cf-ray": "def"},
            ),
        ]
        report = analyze_results("https://example.com", results)
        assert report.accepted_count == 0
        assert report.rejected_count == 2
        assert report.protection_system == "Cloudflare"

    def test_mixed_results(self):
        results = [
            self._make_result("chrome_120", True, headers={"cf-ray": "x"}),
            self._make_result(
                "python_requests", False, status=403, challenge=True,
                headers={"cf-ray": "y"},
            ),
        ]
        report = analyze_results("https://example.com", results)
        assert report.accepted_count == 1
        assert report.rejected_count == 1
        assert "chrome_120" in report.accepted_profiles
        assert "python_requests" in report.rejected_profiles

    def test_recommended_profile_is_impersonation(self):
        results = [
            self._make_result("chrome_120", True),
            self._make_result("chrome_131", True),
            self._make_result("python_requests", True),
        ]
        report = analyze_results("https://example.com", results)
        # Should recommend the newest Chrome with impersonation
        assert report.recommended_profile is not None
        assert "chrome" in report.recommended_profile

    def test_recommended_profile_none_when_all_rejected(self):
        results = [
            self._make_result("chrome_120", False, status=403, challenge=True),
        ]
        report = analyze_results("https://example.com", results)
        assert report.recommended_profile is None

    def test_datadome_detection(self):
        results = [
            self._make_result(
                "chrome_120", False, status=403, challenge=True,
                headers={"x-datadome": "1"},
            ),
        ]
        report = analyze_results("https://example.com", results)
        assert report.protection_system == "DataDome"

    def test_report_url(self):
        report = analyze_results("https://test.com", [])
        assert report.url == "https://test.com"
        assert report.total_tested == 0

    def test_details_included(self):
        results = [self._make_result("chrome_120", True)]
        report = analyze_results("https://example.com", results)
        assert len(report.details) == 1
        assert report.details[0].profile_name == "chrome_120"
