"""Tests for rekit.botwall — each detector's detect() method with mock response data."""

from __future__ import annotations


from rekit.botwall.detectors.base import Difficulty, ResponseData
from rekit.botwall.detectors.cloudflare import CloudflareDetector
from rekit.botwall.detectors.datadome import DataDomeDetector
from rekit.botwall.detectors.akamai import AkamaiDetector
from rekit.botwall.detectors.perimeterx import PerimeterXDetector
from rekit.botwall.detectors.incapsula import IncapsulaDetector
from rekit.botwall.detectors.generic import GenericDetector


def _resp(
    status: int = 200,
    headers: dict | None = None,
    body: str = "",
    cookies: dict | None = None,
    url: str = "https://example.com",
    redirect_chain: list | None = None,
) -> ResponseData:
    return ResponseData(
        url=url,
        status_code=status,
        headers=headers or {},
        body=body,
        cookies=cookies or {},
        redirect_chain=redirect_chain or [],
    )


# =========================================================================
# Difficulty enum
# =========================================================================


class TestDifficulty:
    def test_values(self):
        assert Difficulty.TRIVIAL.value == "trivial"
        assert Difficulty.EASY.value == "easy"
        assert Difficulty.MEDIUM.value == "medium"
        assert Difficulty.HARD.value == "hard"
        assert Difficulty.IMPRACTICAL.value == "impractical"

    def test_description(self):
        assert len(Difficulty.TRIVIAL.description) > 0
        assert len(Difficulty.HARD.description) > 0

    def test_color(self):
        assert Difficulty.TRIVIAL.color == "green"
        assert Difficulty.HARD.color == "red"


# =========================================================================
# CloudflareDetector
# =========================================================================


class TestCloudflareDetector:
    detector = CloudflareDetector()

    def test_name(self):
        assert self.detector.name == "Cloudflare"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {"Content-Type": "text/html"}, "<html>Hello</html>")
        assert self.detector.detect(resp) is None

    def test_detect_cf_ray_header(self):
        resp = _resp(200, {"cf-ray": "abc123-SJC"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.system_name == "Cloudflare"
        assert any("cf-ray" in e for e in det.evidence)

    def test_detect_server_cloudflare(self):
        resp = _resp(200, {"server": "cloudflare", "cf-ray": "x"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_cf_bm_cookie_hard(self):
        resp = _resp(200, {"cf-ray": "x"}, cookies={"__cf_bm": "abc"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD
        assert "Bot Management" in (det.system_version or "")

    def test_detect_cf_clearance_cookie(self):
        resp = _resp(200, {"cf-ray": "x"}, cookies={"cf_clearance": "token"})
        det = self.detector.detect(resp)
        assert det is not None
        assert any("cf_clearance" in e for e in det.evidence)

    def test_detect_turnstile(self):
        body = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
        resp = _resp(200, {"cf-ray": "x"}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_detect_under_attack_mode(self):
        body = '<script>var cf_chl_opt = {}; var jschl_vc = "abc";</script>'
        resp = _resp(503, {"cf-ray": "x"}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.IMPRACTICAL
        assert "Under Attack Mode" in (det.system_version or "")

    def test_cdn_only_trivial(self):
        resp = _resp(200, {"cf-ray": "abc", "cf-cache-status": "HIT"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.TRIVIAL
        assert "CDN only" in (det.system_version or "")

    def test_confidence_increases_with_evidence(self):
        resp_minimal = _resp(200, {"cf-ray": "x"})
        resp_rich = _resp(
            200,
            {"cf-ray": "x", "cf-cache-status": "HIT", "server": "cloudflare"},
            cookies={"__cf_bm": "abc"},
        )
        det1 = self.detector.detect(resp_minimal)
        det2 = self.detector.detect(resp_rich)
        assert det2.confidence >= det1.confidence

    def test_bypass_hints_present(self):
        resp = _resp(200, {"cf-ray": "x"}, cookies={"__cf_bm": "token"})
        det = self.detector.detect(resp)
        assert det is not None
        assert len(det.bypass_hints) > 0


# =========================================================================
# DataDomeDetector
# =========================================================================


class TestDataDomeDetector:
    detector = DataDomeDetector()

    def test_name(self):
        assert self.detector.name == "DataDome"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {}, "<html>Clean page</html>")
        assert self.detector.detect(resp) is None

    def test_detect_datadome_cookie(self):
        resp = _resp(200, {}, cookies={"datadome": "abc123"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.system_name == "DataDome"

    def test_detect_datadome_header(self):
        resp = _resp(200, {"x-datadome": "1"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_dd_b_header(self):
        resp = _resp(200, {"x-dd-b": "1"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_captcha_delivery_body(self):
        body = '<script src="https://captcha-delivery.com/js/captcha.js"></script>'
        resp = _resp(403, {}, body, cookies={"datadome": "x"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_detect_datadome_js(self):
        body = '<script src="https://datadome.co/tags.js"></script>'
        resp = _resp(200, {}, body, cookies={"datadome": "x"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_redirect_chain(self):
        resp = _resp(
            200,
            {},
            "",
            cookies={"datadome": "x"},
            redirect_chain=["https://example.com?dd=abcdef"],
        )
        det = self.detector.detect(resp)
        assert det is not None
        assert any("Redirect" in e for e in det.evidence)

    def test_confidence_min(self):
        resp = _resp(200, {}, cookies={"datadome": "x"})
        det = self.detector.detect(resp)
        assert det.confidence >= 0.4

    def test_bypass_hints(self):
        resp = _resp(200, {}, cookies={"datadome": "x"})
        det = self.detector.detect(resp)
        assert len(det.bypass_hints) > 0


# =========================================================================
# AkamaiDetector
# =========================================================================


class TestAkamaiDetector:
    detector = AkamaiDetector()

    def test_name(self):
        assert self.detector.name == "Akamai"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {}, "")
        assert self.detector.detect(resp) is None

    def test_detect_abck_cookie(self):
        resp = _resp(200, {}, cookies={"_abck": "sensor_data_value"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.system_name == "Akamai"
        assert det.difficulty == Difficulty.HARD
        assert "Bot Manager" in (det.system_version or "")

    def test_detect_ak_bmsc_cookie(self):
        resp = _resp(200, {}, cookies={"ak_bmsc": "value"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_detect_bm_sz_cookie(self):
        resp = _resp(200, {}, cookies={"bm_sz": "value"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_akamai_server_header(self):
        resp = _resp(200, {"server": "AkamaiGHost"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.TRIVIAL
        assert "CDN only" in (det.system_version or "")

    def test_detect_sensor_data_body(self):
        body = "sensor_data={...encrypted...}"
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_detect_bmak_body(self):
        body = "<script>bmak.init()</script>"
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_bm_verify(self):
        body = '<div id="bm-verify">Challenge</div>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_cdn_only_trivial(self):
        resp = _resp(200, {"x-akamai-transformed": "9 - 0 pmb=mRUM"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.TRIVIAL


# =========================================================================
# PerimeterXDetector
# =========================================================================


class TestPerimeterXDetector:
    detector = PerimeterXDetector()

    def test_name(self):
        assert self.detector.name == "PerimeterX (HUMAN)"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {}, "")
        assert self.detector.detect(resp) is None

    def test_detect_px_cookies(self):
        resp = _resp(200, {}, cookies={"_px3": "value", "_pxvid": "vid"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.system_name == "PerimeterX (HUMAN)"

    def test_detect_px_header(self):
        resp = _resp(200, {"x-px-mid": "abc123"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_captcha_body(self):
        body = '<div class="px-captcha">Solve challenge</div>'
        resp = _resp(403, {}, body, cookies={"_px3": "x"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.IMPRACTICAL

    def test_detect_perimeterx_net_body(self):
        body = '<script src="https://client.perimeterx.net/..."></script>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None

    def test_no_challenge_body_hard(self):
        resp = _resp(200, {}, cookies={"_px3": "value"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_bypass_hints(self):
        resp = _resp(200, {}, cookies={"_px3": "x"})
        det = self.detector.detect(resp)
        assert len(det.bypass_hints) > 0


# =========================================================================
# IncapsulaDetector
# =========================================================================


class TestIncapsulaDetector:
    detector = IncapsulaDetector()

    def test_name(self):
        assert self.detector.name == "Incapsula (Imperva)"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {}, "")
        assert self.detector.detect(resp) is None

    def test_detect_incap_session_cookie(self):
        resp = _resp(200, {}, cookies={"incap_ses_12345": "value"})
        det = self.detector.detect(resp)
        assert det is not None
        assert det.system_name == "Incapsula (Imperva)"

    def test_detect_visid_cookie(self):
        resp = _resp(200, {}, cookies={"visid_incap_12345": "value"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_x_iinfo_header(self):
        resp = _resp(200, {"x-iinfo": "1-2-3"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_x_cdn_incapsula(self):
        resp = _resp(200, {"x-cdn": "Incapsula"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_imperva_body(self):
        body = "<html><body>Powered by Imperva</body></html>"
        resp = _resp(200, {}, body, cookies={"incap_ses_1": "x"})
        det = self.detector.detect(resp)
        assert det is not None

    def test_challenge_403_is_hard(self):
        body = "<html><body>_Incapsula_Resource blocked</body></html>"
        resp = _resp(403, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.HARD

    def test_challenge_200_is_medium(self):
        body = "<html><body>_Incapsula_Resource loaded</body></html>"
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert det.difficulty == Difficulty.MEDIUM

    def test_bypass_hints(self):
        resp = _resp(200, {}, cookies={"incap_ses_1": "x"})
        det = self.detector.detect(resp)
        assert len(det.bypass_hints) > 0


# =========================================================================
# GenericDetector
# =========================================================================


class TestGenericDetector:
    detector = GenericDetector()

    def test_name(self):
        assert self.detector.name == "Generic Protection"

    def test_no_detection_clean_response(self):
        resp = _resp(200, {}, "<html>Normal page</html>")
        assert self.detector.detect(resp) is None

    def test_detect_recaptcha(self):
        body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert "reCAPTCHA" in det.system_name
        assert det.difficulty == Difficulty.HARD

    def test_detect_hcaptcha(self):
        body = '<script src="https://hcaptcha.com/1/api.js"></script>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert "hCaptcha" in det.system_name

    def test_detect_arkose(self):
        body = '<script src="https://client-api.arkoselabs.com/v2/123/api.js"></script>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert "Arkose" in det.system_name or "FunCaptcha" in det.system_name

    def test_detect_waf_headers(self):
        resp = _resp(200, {"x-waf-rule": "blocked"})
        det = self.detector.detect(resp)
        assert det is not None
        assert "WAF" in det.system_name
        assert det.difficulty == Difficulty.EASY

    def test_detect_rate_limiting(self):
        resp = _resp(429, {"x-ratelimit-remaining": "0", "retry-after": "60"})
        det = self.detector.detect(resp)
        assert det is not None
        assert "Rate Limiting" in det.system_name

    def test_detect_challenge_status_with_body(self):
        body = "<html><script>challenge('verify')</script></html>"
        resp = _resp(403, {}, body)
        det = self.detector.detect(resp)
        assert det is not None

    def test_detect_redirect_to_challenge(self):
        resp = _resp(302, {"location": "https://example.com/bot-check"})
        det = self.detector.detect(resp)
        assert det is not None
        assert any("Redirect" in e for e in det.evidence)

    def test_multiple_captcha_systems(self):
        body = (
            '<script src="https://www.google.com/recaptcha/api.js"></script>'
            '<script src="https://hcaptcha.com/1/api.js"></script>'
        )
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None
        assert "reCAPTCHA" in det.system_name
        assert "hCaptcha" in det.system_name

    def test_g_recaptcha_element(self):
        body = '<div class="g-recaptcha" data-sitekey="abc"></div>'
        resp = _resp(200, {}, body)
        det = self.detector.detect(resp)
        assert det is not None

    def test_access_denied_bot_body(self):
        body = "<html><body>Access denied. Automated bot detected.</body></html>"
        resp = _resp(403, {}, body)
        det = self.detector.detect(resp)
        assert det is not None

    def test_waf_plus_rate_limit(self):
        resp = _resp(429, {"x-waf-status": "active", "x-ratelimit-remaining": "0"})
        det = self.detector.detect(resp)
        assert det is not None
        assert "WAF" in det.system_name
        assert "Rate Limiting" in det.system_name


# =========================================================================
# ResponseData
# =========================================================================


class TestResponseData:
    def test_defaults(self):
        rd = ResponseData(
            url="https://example.com",
            status_code=200,
            headers={},
            body="",
            cookies={},
        )
        assert rd.redirect_chain == []
        assert rd.response_time_ms == 0.0
