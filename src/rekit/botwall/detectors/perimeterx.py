"""PerimeterX (HUMAN Security) detection."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class PerimeterXDetector(Detector):
    """Detect PerimeterX / HUMAN bot protection."""

    @property
    def name(self) -> str:
        return "PerimeterX (HUMAN)"

    _PX_COOKIES = ("_px3", "_pxvid", "_pxhd", "_px2", "_pxde", "_pxff")

    _BODY_PATTERNS = [
        (re.compile(r"captcha\.px-cdn\.net", re.I), "PerimeterX captcha CDN reference"),
        (re.compile(r"perimeterx\.net", re.I), "perimeterx.net domain reference"),
        (re.compile(r"px-captcha", re.I), "px-captcha element"),
        (re.compile(r"_pxAppId", re.I), "PerimeterX app ID variable"),
        (re.compile(r"human\.com/px", re.I), "HUMAN Security PX reference"),
        (re.compile(r"px-block", re.I), "PerimeterX block page element"),
    ]

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        cookies = {k.lower(): v for k, v in response_data.cookies.items()}
        body = response_data.body

        challenge_in_body = False

        # ── cookie signals ──────────────────────────────────────────────
        for ck_name in self._PX_COOKIES:
            if ck_name in cookies:
                evidence.append(f"{ck_name} cookie present")

        # ── header signals ──────────────────────────────────────────────
        for hdr_name, hdr_val in headers.items():
            if hdr_name.startswith("x-px-"):
                evidence.append(f"{hdr_name} header ({hdr_val})")

        # ── body signals ────────────────────────────────────────────────
        for pat, desc in self._BODY_PATTERNS:
            if pat.search(body):
                evidence.append(desc)
                challenge_in_body = True

        if not evidence:
            return None

        # PerimeterX uses advanced fingerprinting; challenge pages are impractical
        difficulty = Difficulty.IMPRACTICAL if challenge_in_body else Difficulty.HARD

        confidence = min(1.0, len(evidence) * 0.2)
        if confidence < 0.4:
            confidence = 0.4

        return Detection(
            system_name="PerimeterX (HUMAN)",
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=[
                "PerimeterX uses advanced browser fingerprinting (canvas, WebGL, fonts).",
                "_px3 cookie must be obtained from a legitimate browser session.",
                "JS sensor data is POSTed to /api/v2/collector — replay is non-trivial.",
                "Consider Playwright/Puppeteer with stealth plugins for challenge solving.",
                "TLS fingerprint is validated — ensure JA3 matches a real browser.",
            ],
        )
