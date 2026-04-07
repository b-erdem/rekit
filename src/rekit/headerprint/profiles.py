"""
Known browser HTTP/2 and header fingerprint profiles.

Each profile captures the characteristic header order, HTTP/2 SETTINGS,
pseudo-header order, and other HTTP-layer signals that distinguish one
browser from another (and from non-browser clients).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class HeaderProfile:
    """A known browser/client HTTP header fingerprint."""

    name: str
    header_order: Tuple[str, ...]
    pseudo_header_order: Tuple[str, ...]
    h2_settings: Dict[str, int]
    h2_window_update: Optional[int]
    h2_priority: Optional[str]
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    connection_type: str  # "h2" or "http/1.1"


# ---------------------------------------------------------------------------
# Profile registry
# ---------------------------------------------------------------------------

PROFILES: Dict[str, HeaderProfile] = {}


def _reg(p: HeaderProfile) -> None:
    PROFILES[p.name] = p


# -- Chrome 120 -------------------------------------------------------------

_reg(
    HeaderProfile(
        name="chrome_120",
        pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
        h2_settings={
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 262144,
        },
        h2_window_update=15663105,
        h2_priority="EXCLUSIVE:1:256",
        header_order=(
            "host",
            "connection",
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
        ),
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        connection_type="h2",
    )
)

# -- Firefox 133 ------------------------------------------------------------

_reg(
    HeaderProfile(
        name="firefox_133",
        pseudo_header_order=(":method", ":path", ":authority", ":scheme"),
        h2_settings={
            "HEADER_TABLE_SIZE": 65536,
            "INITIAL_WINDOW_SIZE": 131072,
            "MAX_FRAME_SIZE": 16384,
        },
        h2_window_update=12517377,
        h2_priority=None,
        header_order=(
            "host",
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "connection",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority",
        ),
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br, zstd",
        connection_type="h2",
    )
)

# -- Safari 18 --------------------------------------------------------------

_reg(
    HeaderProfile(
        name="safari_18",
        pseudo_header_order=(":method", ":scheme", ":path", ":authority"),
        h2_settings={
            "HEADER_TABLE_SIZE": 4096,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 100,
            "INITIAL_WINDOW_SIZE": 2097152,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 8000,
        },
        h2_window_update=10485760,
        h2_priority=None,
        header_order=(
            "host",
            "accept",
            "sec-fetch-site",
            "accept-language",
            "sec-fetch-mode",
            "user-agent",
            "accept-encoding",
            "sec-fetch-dest",
        ),
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Safari/605.1.15"
        ),
        accept=("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        connection_type="h2",
    )
)

# -- Edge 131 ---------------------------------------------------------------

_reg(
    HeaderProfile(
        name="edge_131",
        pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
        h2_settings={
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 262144,
        },
        h2_window_update=15663105,
        h2_priority="EXCLUSIVE:1:256",
        header_order=(
            "host",
            "connection",
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "sec-ch-ua-full-version-list",
        ),
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        connection_type="h2",
    )
)

# -- Python requests --------------------------------------------------------

_reg(
    HeaderProfile(
        name="python_requests",
        pseudo_header_order=(),
        h2_settings={},
        h2_window_update=None,
        h2_priority=None,
        header_order=(
            "user-agent",
            "accept-encoding",
            "accept",
            "connection",
        ),
        user_agent="python-requests/2.31.0",
        accept="*/*",
        accept_language="",
        accept_encoding="gzip, deflate",
        connection_type="http/1.1",
    )
)

# -- curl default -----------------------------------------------------------

_reg(
    HeaderProfile(
        name="curl_default",
        pseudo_header_order=(),
        h2_settings={},
        h2_window_update=None,
        h2_priority=None,
        header_order=(
            "host",
            "user-agent",
            "accept",
        ),
        user_agent="curl/8.4.0",
        accept="*/*",
        accept_language="",
        accept_encoding="",
        connection_type="http/1.1",
    )
)
