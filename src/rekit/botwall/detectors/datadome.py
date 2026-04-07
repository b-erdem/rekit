"""DataDome detection."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class DataDomeDetector(Detector):
    """Detect DataDome bot protection."""

    @property
    def name(self) -> str:
        return "DataDome"

    _BODY_PATTERNS = [
        (re.compile(r"datadome\.co", re.I), "Reference to datadome.co JS"),
        (
            re.compile(r"captcha-delivery\.com", re.I),
            "captcha-delivery.com challenge domain",
        ),
        (re.compile(r"dd\.js", re.I), "DataDome dd.js script tag"),
        (re.compile(r"window\.ddjskey", re.I), "DataDome JS key variable"),
        (re.compile(r"x-]datadome", re.I), "DataDome meta reference"),
    ]

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        cookies = {k.lower(): v for k, v in response_data.cookies.items()}
        body = response_data.body

        # ── cookie signals ──────────────────────────────────────────────
        if "datadome" in cookies:
            evidence.append("datadome cookie present")

        if "x-datadome-cid" in cookies:
            evidence.append("x-datadome-cid cookie present")

        # ── header signals ──────────────────────────────────────────────
        for hdr in ("x-datadome", "x-datadome-cid"):
            if hdr in headers:
                evidence.append(f"{hdr} response header ({headers[hdr]})")

        if "x-dd-b" in headers:
            evidence.append(f"x-dd-b header ({headers['x-dd-b']})")

        if "x-dd-type" in headers:
            evidence.append(f"x-dd-type header ({headers['x-dd-type']})")

        # ── redirect chain signals ──────────────────────────────────────
        for url in response_data.redirect_chain:
            if "dd=" in url or "datadome" in url.lower():
                evidence.append(f"Redirect through DataDome URL: {url}")

        # ── body signals ────────────────────────────────────────────────
        challenge_in_body = False
        for pat, desc in self._BODY_PATTERNS:
            if pat.search(body):
                evidence.append(desc)
                challenge_in_body = True

        if not evidence:
            return None

        # DataDome is generally hard — JS challenge + device fingerprinting
        difficulty = Difficulty.HARD
        if challenge_in_body:
            difficulty = Difficulty.HARD  # challenge page actively served

        confidence = min(1.0, len(evidence) * 0.25)
        if confidence < 0.4:
            confidence = 0.4

        return Detection(
            system_name="DataDome",
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=[
                "Requires solving DataDome JS challenge.",
                "x-d-token must be generated client-side via DataDome's JS SDK.",
                "datadome cookie is validated server-side on every request.",
                "TLS fingerprint is checked — use curl_cffi with browser impersonation.",
                "Device fingerprint (canvas, WebGL, fonts) is collected.",
            ],
        )
