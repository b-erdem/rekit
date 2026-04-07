"""
Analyse a client's HTTP fingerprint against known browser profiles.

Provides header-order similarity scoring (longest common subsequence),
HTTP/2 SETTINGS comparison, pseudo-header order matching, and anomaly
detection for non-browser indicators.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from rekit.hargen.parser import HttpExchange
from rekit.headerprint.profiles import PROFILES, HeaderProfile


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class HeaderFingerprint:
    """Observed HTTP fingerprint extracted from traffic."""

    header_order: List[str]
    pseudo_header_order: Optional[List[str]] = None
    h2_settings: Optional[Dict[str, int]] = None
    user_agent: Optional[str] = None
    extra_headers: List[str] = field(default_factory=list)
    missing_headers: List[str] = field(default_factory=list)


@dataclass
class FingerprintMatch:
    """Result of comparing an observed fingerprint to a known profile."""

    profile_name: str
    similarity: float  # 0-1 overall
    header_order_match: float  # 0-1
    pseudo_header_match: float  # 0-1
    h2_settings_match: float  # 0-1
    differences: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Header-order similarity
# ---------------------------------------------------------------------------


def _lcs_length(a: List[str], b: List[str]) -> int:
    """Length of the longest common subsequence of *a* and *b*."""
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0
    # Space-optimized DP (two rows).
    prev = [0] * (n + 1)
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev, curr = curr, [0] * (n + 1)
    return prev[n]


def analyze_header_order(observed: List[str], profile: HeaderProfile) -> float:
    """Compare header order similarity using longest common subsequence.

    Returns a float in [0, 1] where 1.0 means identical order.
    """
    profile_order = list(profile.header_order)
    if not observed or not profile_order:
        return 0.0
    lcs = _lcs_length(observed, profile_order)
    max_len = max(len(observed), len(profile_order))
    return lcs / max_len


def _compare_pseudo_headers(
    observed: Optional[List[str]], profile: HeaderProfile
) -> float:
    """Compare pseudo-header order.  Returns 1.0 on exact match, 0.0 on
    no match or missing data."""
    profile_order = list(profile.pseudo_header_order)
    if not observed or not profile_order:
        # If both are empty, that's a match (e.g. non-browser profiles).
        if not observed and not profile_order:
            return 1.0
        return 0.0
    return 1.0 if observed == profile_order else 0.0


def _compare_h2_settings(
    observed: Optional[Dict[str, int]], profile: HeaderProfile
) -> float:
    """Compare HTTP/2 SETTINGS frames.  Returns fraction of matching keys."""
    profile_settings = profile.h2_settings
    if not observed and not profile_settings:
        return 1.0
    if not observed or not profile_settings:
        return 0.0
    all_keys = set(observed) | set(profile_settings)
    if not all_keys:
        return 1.0
    matches = sum(1 for k in all_keys if observed.get(k) == profile_settings.get(k))
    return matches / len(all_keys)


# ---------------------------------------------------------------------------
# Profile comparison
# ---------------------------------------------------------------------------


def compare_to_profiles(
    fingerprint: HeaderFingerprint,
) -> List[FingerprintMatch]:
    """Compare an observed fingerprint against all known profiles.

    Returns a list sorted by similarity (best match first).
    """
    results: List[FingerprintMatch] = []

    for name, profile in PROFILES.items():
        header_score = analyze_header_order(fingerprint.header_order, profile)
        pseudo_score = _compare_pseudo_headers(fingerprint.pseudo_header_order, profile)
        h2_score = _compare_h2_settings(fingerprint.h2_settings, profile)

        # Weighted overall score:
        #   header order is the strongest signal (50 %),
        #   pseudo-header order (25 %), h2 settings (25 %).
        overall = 0.50 * header_score + 0.25 * pseudo_score + 0.25 * h2_score

        # Collect human-readable differences.
        diffs: List[str] = []
        if header_score < 1.0:
            diffs.append(f"Header order differs (similarity {header_score:.0%})")
        if pseudo_score < 1.0:
            observed_pseudo = fingerprint.pseudo_header_order or []
            diffs.append(
                f"Pseudo-header order: observed {observed_pseudo} "
                f"vs profile {list(profile.pseudo_header_order)}"
            )
        if h2_score < 1.0:
            diffs.append(f"H2 settings differ (match {h2_score:.0%})")

        results.append(
            FingerprintMatch(
                profile_name=name,
                similarity=round(overall, 4),
                header_order_match=round(header_score, 4),
                pseudo_header_match=round(pseudo_score, 4),
                h2_settings_match=round(h2_score, 4),
                differences=diffs,
            )
        )

    results.sort(key=lambda m: m.similarity, reverse=True)
    return results


# ---------------------------------------------------------------------------
# HAR extraction
# ---------------------------------------------------------------------------


def extract_fingerprint_from_har(
    exchanges: List[HttpExchange],
) -> HeaderFingerprint:
    """Extract the header fingerprint from captured HTTP exchanges.

    Uses the first few requests to determine the consistent header order.
    """
    if not exchanges:
        return HeaderFingerprint(header_order=[])

    # Use the first exchange for the primary fingerprint.
    first = exchanges[0]
    header_order = list(first.request_headers.keys())
    # Normalise to lowercase.
    header_order = [h.lower() for h in header_order]

    user_agent = first.request_headers.get(
        "User-Agent", first.request_headers.get("user-agent")
    )

    # Separate pseudo-headers (HTTP/2) if present.
    pseudo_headers = [h for h in header_order if h.startswith(":")]
    regular_headers = [h for h in header_order if not h.startswith(":")]

    return HeaderFingerprint(
        header_order=regular_headers,
        pseudo_header_order=pseudo_headers if pseudo_headers else None,
        h2_settings=None,  # Not extractable from HAR format
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

_SEC_FETCH_HEADERS = {
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
}

_CHROMIUM_HINT_HEADERS = {
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
}

_NON_BROWSER_UA_PATTERNS = [
    "python",
    "java",
    "go-http-client",
    "okhttp",
    "axios",
    "node-fetch",
    "curl",
    "wget",
    "httpx",
    "aiohttp",
    "requests",
    "scrapy",
    "urllib",
]


def detect_anomalies(fingerprint: HeaderFingerprint) -> List[str]:
    """Detect indicators that a client is not a real browser.

    Returns a list of human-readable anomaly descriptions.
    """
    anomalies: List[str] = []
    lower_headers = {h.lower() for h in fingerprint.header_order}
    ua_lower = (fingerprint.user_agent or "").lower()

    # 1. Missing sec-fetch-* headers (all modern browsers send these).
    missing_sec_fetch = _SEC_FETCH_HEADERS - lower_headers
    if missing_sec_fetch:
        anomalies.append(
            f"Missing sec-fetch headers: {', '.join(sorted(missing_sec_fetch))}. "
            "All modern browsers send these."
        )

    # 2. Chromium UA but missing sec-ch-ua headers.
    is_chromium_ua = any(
        tok in ua_lower for tok in ("chrome", "chromium", "edg/", "edge")
    )
    if is_chromium_ua:
        missing_hints = _CHROMIUM_HINT_HEADERS - lower_headers
        if missing_hints:
            anomalies.append(
                f"Chromium User-Agent but missing client hint headers: "
                f"{', '.join(sorted(missing_hints))}"
            )

    # 3. Non-browser User-Agent pattern.
    for pattern in _NON_BROWSER_UA_PATTERNS:
        if pattern in ua_lower:
            anomalies.append(f"Non-browser User-Agent detected (contains '{pattern}')")
            break

    # 4. Very short header list (browsers typically send 8+ headers).
    if len(fingerprint.header_order) < 5:
        anomalies.append(
            f"Unusually few headers ({len(fingerprint.header_order)}). "
            "Browsers typically send 8 or more."
        )

    # 5. Missing Accept-Language (all browsers send this).
    if "accept-language" not in lower_headers:
        anomalies.append("Missing accept-language header.")

    # 6. Missing or unusual Accept-Encoding.
    if "accept-encoding" not in lower_headers:
        anomalies.append("Missing accept-encoding header.")

    return anomalies
