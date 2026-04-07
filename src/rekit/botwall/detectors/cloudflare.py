"""Cloudflare detection — CDN, WAF, Bot Management, Turnstile, Under Attack Mode."""

from __future__ import annotations

import re
from typing import Optional

from rekit.botwall.detectors.base import Detection, Detector, Difficulty, ResponseData


class CloudflareDetector(Detector):
    """Detect Cloudflare and distinguish protection tiers."""

    @property
    def name(self) -> str:
        return "Cloudflare"

    # ── body patterns that indicate active challenge pages ──────────────
    _CHALLENGE_PATTERNS = [
        (
            re.compile(r"cf-browser-verification", re.I),
            "cf-browser-verification page element",
        ),
        (
            re.compile(r"challenge-platform", re.I),
            "challenge-platform script reference",
        ),
        (
            re.compile(r"Checking your browser", re.I),
            "'Checking your browser' interstitial text",
        ),
        (re.compile(r"cf-chl-bypass", re.I), "cf-chl-bypass token reference"),
        (
            re.compile(r"managed_checking_msg", re.I),
            "Managed Challenge checking message",
        ),
    ]

    _TURNSTILE_PATTERNS = [
        (
            re.compile(r"challenges\.cloudflare\.com/turnstile", re.I),
            "Turnstile widget script",
        ),
        (re.compile(r"cf-turnstile", re.I), "cf-turnstile element"),
    ]

    _UNDER_ATTACK_PATTERNS = [
        (re.compile(r"jschl_vc", re.I), "JS challenge value (jschl_vc)"),
        (re.compile(r"jschl_answer", re.I), "JS challenge answer field"),
        (re.compile(r"cf_chl_opt", re.I), "Cloudflare challenge options object"),
        (re.compile(r"__cf_chl_rt_tk", re.I), "Cloudflare challenge runtime token"),
    ]

    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        evidence: list[str] = []
        headers = {k.lower(): v for k, v in response_data.headers.items()}
        cookies = {k.lower(): v for k, v in response_data.cookies.items()}
        body = response_data.body

        # ── header signals ──────────────────────────────────────────────
        if "cf-ray" in headers:
            evidence.append(f"cf-ray header present ({headers['cf-ray']})")

        if "cf-cache-status" in headers:
            evidence.append(f"cf-cache-status header ({headers['cf-cache-status']})")

        server = headers.get("server", "")
        if "cloudflare" in server.lower():
            evidence.append(f"server header is '{server}'")

        if "cf-mitigated" in headers:
            evidence.append(f"cf-mitigated header ({headers['cf-mitigated']})")

        # ── cookie signals ──────────────────────────────────────────────
        if "__cf_bm" in cookies:
            evidence.append("__cf_bm cookie (Bot Management)")

        if "cf_clearance" in cookies:
            evidence.append("cf_clearance cookie (challenge passed)")

        for ck in cookies:
            if ck.startswith("__cflb"):
                evidence.append(f"{ck} cookie (Cloudflare load balancer)")

        # bail early if nothing found
        if not evidence:
            return None

        # ── body signals (challenge pages) ──────────────────────────────
        challenge_evidence: list[str] = []
        turnstile_evidence: list[str] = []
        under_attack_evidence: list[str] = []

        for pat, desc in self._CHALLENGE_PATTERNS:
            if pat.search(body):
                challenge_evidence.append(desc)

        for pat, desc in self._TURNSTILE_PATTERNS:
            if pat.search(body):
                turnstile_evidence.append(desc)

        for pat, desc in self._UNDER_ATTACK_PATTERNS:
            if pat.search(body):
                under_attack_evidence.append(desc)

        evidence.extend(challenge_evidence)
        evidence.extend(turnstile_evidence)
        evidence.extend(under_attack_evidence)

        # ── classify tier ───────────────────────────────────────────────
        difficulty, version = self._classify(
            evidence,
            challenge_evidence,
            turnstile_evidence,
            under_attack_evidence,
            cookies,
            headers,
        )

        confidence = min(1.0, len(evidence) * 0.2)
        if confidence < 0.3:
            confidence = 0.3  # at least one header matched

        bypass_hints = self._hints_for(difficulty)

        return Detection(
            system_name="Cloudflare",
            system_version=version,
            confidence=round(confidence, 2),
            difficulty=difficulty,
            evidence=evidence,
            bypass_hints=bypass_hints,
        )

    # ── private helpers ─────────────────────────────────────────────────

    def _classify(
        self,
        evidence: list[str],
        challenge_ev: list[str],
        turnstile_ev: list[str],
        under_attack_ev: list[str],
        cookies: dict[str, str],
        headers: dict[str, str],
    ) -> tuple[Difficulty, str]:
        """Return (difficulty, version_label)."""
        if under_attack_ev:
            return Difficulty.IMPRACTICAL, "Under Attack Mode"

        if turnstile_ev or ("__cf_bm" in cookies and challenge_ev):
            return Difficulty.HARD, "Bot Management / Turnstile"

        if challenge_ev:
            return Difficulty.HARD, "Bot Management"

        if "__cf_bm" in cookies:
            return Difficulty.HARD, "Bot Management"

        if "cf-mitigated" in headers:
            return Difficulty.EASY, "WAF"

        # Just CDN headers, no active protection
        return Difficulty.TRIVIAL, "CDN only"

    @staticmethod
    def _hints_for(difficulty: Difficulty) -> list[str]:
        if difficulty == Difficulty.TRIVIAL:
            return ["Cloudflare CDN only — no active bot protection detected."]
        if difficulty == Difficulty.EASY:
            return [
                "Basic WAF rules only; proper User-Agent and TLS fingerprint should suffice.",
                "Use curl_cffi with browser impersonation for safer TLS.",
            ]
        if difficulty in (Difficulty.HARD, Difficulty.IMPRACTICAL):
            return [
                "Requires solving Cloudflare JS challenge or Turnstile CAPTCHA.",
                "cf_clearance cookie must be obtained through a real browser session.",
                "Consider using browser automation (Playwright/Puppeteer with stealth plugins).",
                "TLS fingerprint matters — use curl_cffi with chrome impersonation.",
            ]
        return []
