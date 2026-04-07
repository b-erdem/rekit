"""Akamai Bot Manager detection."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class AkamaiDetector(Detector):
    """Detect Akamai CDN and Bot Manager."""

    @property
    def name(self) -> str:
        return "Akamai"

    _SENSOR_PATTERNS = [
        (re.compile(r"_cf_chl", re.I), False),  # avoid false positive with CF
        (re.compile(r"sensor_data", re.I), "sensor_data field in body"),
        (re.compile(r"bmak\.", re.I), "Akamai bmak JS object"),
        (re.compile(r"akamai.*bot.*manager", re.I), "Akamai Bot Manager reference"),
    ]

    _BM_VERIFY_PATTERN = re.compile(r"bm-verify", re.I)

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        cookies = {k.lower(): v for k, v in response_data.cookies.items()}
        body = response_data.body

        is_bot_manager = False

        # ── cookie signals ──────────────────────────────────────────────
        if "_abck" in cookies:
            evidence.append("_abck cookie (Akamai Bot Manager)")
            is_bot_manager = True

        if "ak_bmsc" in cookies:
            evidence.append("ak_bmsc cookie (Akamai Bot Manager session)")
            is_bot_manager = True

        if "bm_sz" in cookies:
            evidence.append("bm_sz cookie (Akamai Bot Manager sizing)")
            is_bot_manager = True

        # ── header signals ──────────────────────────────────────────────
        if "akamai-x-cache-on" in headers:
            evidence.append("akamai-x-cache-on header")

        if "x-akamai-transformed" in headers:
            evidence.append(f"x-akamai-transformed header ({headers['x-akamai-transformed']})")

        # Akamai edge headers
        for hdr_name in ("x-akamai-request-id", "x-akamai-session-info"):
            if hdr_name in headers:
                evidence.append(f"{hdr_name} header present")

        # Generic Akamai CDN detection via server header
        server = headers.get("server", "")
        if "akamaighost" in server.lower() or "akamai" in server.lower():
            evidence.append(f"server header is '{server}'")

        # ── body signals ────────────────────────────────────────────────
        for pat, desc in self._SENSOR_PATTERNS:
            if desc and pat.search(body):
                evidence.append(desc)
                is_bot_manager = True

        if self._BM_VERIFY_PATTERN.search(body):
            evidence.append("bm-verify challenge reference in body")
            is_bot_manager = True

        if not evidence:
            return None

        difficulty = Difficulty.HARD if is_bot_manager else Difficulty.TRIVIAL
        version = "Bot Manager" if is_bot_manager else "CDN only"

        confidence = min(1.0, len(evidence) * 0.2)
        if confidence < 0.3:
            confidence = 0.3

        hints: list[str] = []
        if is_bot_manager:
            hints = [
                "TLS fingerprint matters — use curl_cffi with browser impersonation.",
                "sensor_data generation required for full bypass.",
                "_abck cookie must contain a valid sensor payload.",
                "Akamai checks mouse movements, keyboard events, and device orientation.",
            ]
        else:
            hints = ["Akamai CDN only — no active bot protection detected."]

        return Detection(
            system_name="Akamai",
            system_version=version,
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=hints,
        )
