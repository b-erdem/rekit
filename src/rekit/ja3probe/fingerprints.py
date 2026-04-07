"""
TLS fingerprint profile database.

Each profile maps to a curl_cffi impersonate string (where available) and
carries metadata about the browser/client it emulates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class FingerprintProfile:
    """A TLS fingerprint profile used for probing."""

    name: str
    description: str
    impersonate_str: Optional[str]
    user_agent: str
    browser_family: str
    version: str

    @property
    def has_impersonation(self) -> bool:
        return self.impersonate_str is not None


# ---------------------------------------------------------------------------
# Profile registry
# ---------------------------------------------------------------------------

PROFILES: Dict[str, FingerprintProfile] = {}


def _reg(p: FingerprintProfile) -> None:
    PROFILES[p.name] = p


# ── Chrome ─────────────────────────────────────────────────────────────────

_reg(FingerprintProfile(
    name="chrome_99",
    description="Chrome 99 (Windows)",
    impersonate_str="chrome99",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    browser_family="chrome",
    version="99",
))

_reg(FingerprintProfile(
    name="chrome_100",
    description="Chrome 100 (Windows)",
    impersonate_str="chrome100",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    browser_family="chrome",
    version="100",
))

_reg(FingerprintProfile(
    name="chrome_104",
    description="Chrome 104 (Windows)",
    impersonate_str="chrome104",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="104",
))

_reg(FingerprintProfile(
    name="chrome_107",
    description="Chrome 107 (Windows)",
    impersonate_str="chrome107",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="107",
))

_reg(FingerprintProfile(
    name="chrome_110",
    description="Chrome 110 (Windows)",
    impersonate_str="chrome110",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="110",
))

_reg(FingerprintProfile(
    name="chrome_116",
    description="Chrome 116 (Windows)",
    impersonate_str="chrome116",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="116",
))

_reg(FingerprintProfile(
    name="chrome_119",
    description="Chrome 119 (Windows)",
    impersonate_str="chrome119",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="119",
))

_reg(FingerprintProfile(
    name="chrome_120",
    description="Chrome 120 (Windows)",
    impersonate_str="chrome120",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="120",
))

_reg(FingerprintProfile(
    name="chrome_123",
    description="Chrome 123 (Windows)",
    impersonate_str="chrome123",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="123",
))

_reg(FingerprintProfile(
    name="chrome_124",
    description="Chrome 124 (Windows)",
    impersonate_str="chrome124",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="124",
))

_reg(FingerprintProfile(
    name="chrome_131",
    description="Chrome 131 (Windows)",
    impersonate_str="chrome131",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    browser_family="chrome",
    version="131",
))

# ── Safari ─────────────────────────────────────────────────────────────────

_reg(FingerprintProfile(
    name="safari_15_3",
    description="Safari 15.3 (macOS)",
    impersonate_str="safari15_3",
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
    browser_family="safari",
    version="15.3",
))

_reg(FingerprintProfile(
    name="safari_15_5",
    description="Safari 15.5 (macOS)",
    impersonate_str="safari15_5",
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    browser_family="safari",
    version="15.5",
))

_reg(FingerprintProfile(
    name="safari_17_0",
    description="Safari 17.0 (macOS)",
    impersonate_str="safari17_0",
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    browser_family="safari",
    version="17.0",
))

_reg(FingerprintProfile(
    name="safari_17_2",
    description="Safari 17.2 (iOS)",
    impersonate_str="safari17_2_ios",
    user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    browser_family="safari",
    version="17.2",
))

_reg(FingerprintProfile(
    name="safari_18_0",
    description="Safari 18.0 (macOS)",
    impersonate_str="safari18_0",
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    browser_family="safari",
    version="18.0",
))

# ── Firefox ────────────────────────────────────────────────────────────────

_reg(FingerprintProfile(
    name="firefox_102",
    description="Firefox 102 (Windows) -- no curl_cffi impersonation",
    impersonate_str=None,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    browser_family="firefox",
    version="102",
))

_reg(FingerprintProfile(
    name="firefox_110",
    description="Firefox 110 (Windows) -- no curl_cffi impersonation",
    impersonate_str=None,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
    browser_family="firefox",
    version="110",
))

_reg(FingerprintProfile(
    name="firefox_117",
    description="Firefox 117 (Windows) -- no curl_cffi impersonation",
    impersonate_str=None,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
    browser_family="firefox",
    version="117",
))

_reg(FingerprintProfile(
    name="firefox_120",
    description="Firefox 120 (Windows) -- no curl_cffi impersonation",
    impersonate_str=None,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    browser_family="firefox",
    version="120",
))

_reg(FingerprintProfile(
    name="firefox_133",
    description="Firefox 133 (Windows)",
    impersonate_str="firefox133",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    browser_family="firefox",
    version="133",
))

# ── Edge ───────────────────────────────────────────────────────────────────

_reg(FingerprintProfile(
    name="edge_99",
    description="Edge 99 (Windows)",
    impersonate_str="edge99",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30",
    browser_family="edge",
    version="99",
))

_reg(FingerprintProfile(
    name="edge_101",
    description="Edge 101 (Windows)",
    impersonate_str="edge101",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
    browser_family="edge",
    version="101",
))

# ── Non-browser clients ───────────────────────────────────────────────────

_reg(FingerprintProfile(
    name="dart_3_9",
    description="Dart/3.9 (Flutter apps) -- no curl_cffi impersonation",
    impersonate_str=None,
    user_agent="Dart/3.9 (dart:io)",
    browser_family="dart",
    version="3.9",
))

_reg(FingerprintProfile(
    name="python_requests",
    description="Python requests (default, no TLS impersonation)",
    impersonate_str=None,
    user_agent="python-requests/2.31.0",
    browser_family="python",
    version="requests",
))

_reg(FingerprintProfile(
    name="curl_default",
    description="curl default (no TLS impersonation)",
    impersonate_str=None,
    user_agent="curl/8.4.0",
    browser_family="curl",
    version="default",
))
