"""Incapsula / Imperva detection."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class IncapsulaDetector(Detector):
    """Detect Incapsula (Imperva) bot protection."""

    @property
    def name(self) -> str:
        return "Incapsula (Imperva)"

    _BODY_PATTERNS = [
        (re.compile(r"incapsula", re.I), "Incapsula reference in body"),
        (re.compile(r"_Incapsula_Resource", re.I), "_Incapsula_Resource script reference"),
        (re.compile(r"imperva", re.I), "Imperva reference in body"),
    ]

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        cookies = {k.lower(): v for k, v in response_data.cookies.items()}
        body = response_data.body

        has_challenge = False

        # ── cookie signals ──────────────────────────────────────────────
        for ck_name in cookies:
            if ck_name.startswith("incap_ses_"):
                evidence.append(f"{ck_name} cookie (Incapsula session)")
            elif ck_name.startswith("visid_incap_"):
                evidence.append(f"{ck_name} cookie (Incapsula visitor ID)")
            elif ck_name == "nlbi_" or ck_name.startswith("nlbi_"):
                evidence.append(f"{ck_name} cookie (Incapsula load balancer)")

        # ── header signals ──────────────────────────────────────────────
        if "x-iinfo" in headers:
            evidence.append(f"x-iinfo header ({headers['x-iinfo']})")

        x_cdn = headers.get("x-cdn", "")
        if "incapsula" in x_cdn.lower() or "imperva" in x_cdn.lower():
            evidence.append(f"x-cdn header contains '{x_cdn}'")

        # Imperva-specific headers
        for hdr_name in ("x-incap-sess", "x-incap-req-id"):
            if hdr_name in headers:
                evidence.append(f"{hdr_name} header present")

        # ── body signals ────────────────────────────────────────────────
        for pat, desc in self._BODY_PATTERNS:
            if pat.search(body):
                evidence.append(desc)
                has_challenge = True

        if not evidence:
            return None

        # Incapsula ranges from medium (cookie validation) to hard (JS challenge)
        if has_challenge and response_data.status_code in (403, 429, 503):
            difficulty = Difficulty.HARD
        elif has_challenge:
            difficulty = Difficulty.MEDIUM
        else:
            difficulty = Difficulty.MEDIUM

        confidence = min(1.0, len(evidence) * 0.2)
        if confidence < 0.3:
            confidence = 0.3

        return Detection(
            system_name="Incapsula (Imperva)",
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=[
                "Incapsula sets cookies via JS — initial request returns a script.",
                "Evaluate the _Incapsula_Resource JS to get valid cookies.",
                "Some sites only require replaying the incap_ses_ cookie.",
                "TLS fingerprint can be checked — use curl_cffi for safety.",
            ],
        )
