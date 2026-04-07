"""
ratelim -- Systematically probe API rate limits.

Sends controlled bursts of requests to detect rate limiting behavior,
parse rate limit headers, measure cooldown periods, and recommend safe
request rates.
"""

from rekit.ratelim.prober import (
    RateLimitInfo,
    ProbeResult,
    parse_rate_limit_headers,
    probe_rate_limit,
    binary_search_limit,
    measure_cooldown,
    detect_limit_type,
)

__all__ = [
    "RateLimitInfo",
    "ProbeResult",
    "parse_rate_limit_headers",
    "probe_rate_limit",
    "binary_search_limit",
    "measure_cooldown",
    "detect_limit_type",
]
