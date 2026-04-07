"""Generic / catch-all heuristic detector for CAPTCHAs, WAFs, and rate limits."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class GenericDetector(Detector):
    """Catch-all detector for reCAPTCHA, hCaptcha, Arkose, generic WAFs, and rate limits."""

    @property
    def name(self) -> str:
        return "Generic Protection"

    # ── CAPTCHA patterns ────────────────────────────────────────────────
    _CAPTCHA_PATTERNS = [
        (re.compile(r"google\.com/recaptcha", re.I), "reCAPTCHA", "reCAPTCHA"),
        (
            re.compile(r"www\.recaptcha\.net", re.I),
            "reCAPTCHA (recaptcha.net)",
            "reCAPTCHA",
        ),
        (re.compile(r"g-recaptcha", re.I), "g-recaptcha element", "reCAPTCHA"),
        (re.compile(r"hcaptcha\.com", re.I), "hCaptcha script", "hCaptcha"),
        (re.compile(r"h-captcha", re.I), "h-captcha element", "hCaptcha"),
        (
            re.compile(r"arkoselabs\.com", re.I),
            "Arkose Labs (FunCaptcha)",
            "Arkose/FunCaptcha",
        ),
        (re.compile(r"funcaptcha", re.I), "FunCaptcha reference", "Arkose/FunCaptcha"),
        (
            re.compile(r"client-api\.arkoselabs", re.I),
            "Arkose client API",
            "Arkose/FunCaptcha",
        ),
    ]

    # ── generic WAF headers ─────────────────────────────────────────────
    _WAF_HEADER_PREFIXES = ("x-waf-", "x-security-", "x-firewall-")

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        body = response_data.body
        status = response_data.status_code

        captcha_systems: set[str] = set()
        has_waf = False
        has_rate_limit = False
        has_challenge_status = False

        # ── CAPTCHA detection ───────────────────────────────────────────
        for pat, desc, system in self._CAPTCHA_PATTERNS:
            if pat.search(body):
                evidence.append(desc)
                captcha_systems.add(system)

        # ── generic WAF headers ─────────────────────────────────────────
        for hdr_name, hdr_val in headers.items():
            for prefix in self._WAF_HEADER_PREFIXES:
                if hdr_name.startswith(prefix):
                    evidence.append(f"WAF header: {hdr_name} = {hdr_val}")
                    has_waf = True

        # ── rate limit detection ────────────────────────────────────────
        for hdr_name, hdr_val in headers.items():
            if hdr_name.startswith("x-ratelimit-") or hdr_name == "retry-after":
                evidence.append(f"Rate limit header: {hdr_name} = {hdr_val}")
                has_rate_limit = True

        # ── challenge-like HTTP status codes ────────────────────────────
        if status in (403, 429, 503):
            # Check if the body looks like a challenge rather than a normal error
            challenge_indicators = [
                re.compile(
                    r"<script[^>]*>.*?(challenge|captcha|verify|check)", re.I | re.S
                ),
                re.compile(r"access.denied.*bot", re.I),
                re.compile(r"blocked.*automated", re.I),
                re.compile(r"please.complete.*security.*check", re.I),
                re.compile(r"suspicious.activity", re.I),
            ]
            for pat in challenge_indicators:
                if pat.search(body):
                    evidence.append(f"HTTP {status} with challenge-like body content")
                    has_challenge_status = True
                    break

        # ── JS redirect to challenge page ───────────────────────────────
        if status == 302 or status == 301:
            location = headers.get("location", "")
            challenge_url_patterns = ["challenge", "captcha", "verify", "bot-check"]
            for pattern in challenge_url_patterns:
                if pattern in location.lower():
                    evidence.append(f"Redirect to challenge URL: {location}")
                    has_challenge_status = True

        if not evidence:
            return None

        # ── determine difficulty ────────────────────────────────────────
        if captcha_systems:
            difficulty = Difficulty.HARD
        elif has_challenge_status:
            difficulty = Difficulty.MEDIUM
        elif has_waf:
            difficulty = Difficulty.EASY
        elif has_rate_limit:
            difficulty = Difficulty.EASY
        else:
            difficulty = Difficulty.MEDIUM

        # ── build system name ───────────────────────────────────────────
        parts: list[str] = []
        if captcha_systems:
            parts.append(", ".join(sorted(captcha_systems)))
        if has_waf:
            parts.append("Generic WAF")
        if has_rate_limit:
            parts.append("Rate Limiting")
        if has_challenge_status and not captcha_systems:
            parts.append("Challenge Page")
        system_name = " + ".join(parts) if parts else "Unknown Protection"

        # ── bypass hints ────────────────────────────────────────────────
        hints: list[str] = []
        if "reCAPTCHA" in captcha_systems:
            hints.append(
                "reCAPTCHA v2/v3 requires token solving — use a CAPTCHA solving service."
            )
        if "hCaptcha" in captcha_systems:
            hints.append(
                "hCaptcha requires visual challenge solving — consider a solving service."
            )
        if "Arkose/FunCaptcha" in captcha_systems:
            hints.append(
                "Arkose FunCaptcha is particularly difficult — requires specialized solvers."
            )
        if has_rate_limit:
            hints.append(
                "Rate limiting detected — implement request throttling and IP rotation."
            )
        if has_waf:
            hints.append("Generic WAF detected — vary User-Agent and request patterns.")

        confidence = min(1.0, len(evidence) * 0.15)
        if confidence < 0.3:
            confidence = 0.3

        return Detection(
            system_name=system_name,
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=hints,
        )
