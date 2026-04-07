"""ratelim.prober -- Systematically probe API rate limits."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Dict, Optional

import requests


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RateLimitInfo:
    """Parsed rate limit information from response headers or detection."""

    limit: Optional[int] = None
    remaining: Optional[int] = None
    reset_seconds: Optional[float] = None
    window_seconds: Optional[float] = None
    limit_type: str = "unknown"
    source: str = "headers"


@dataclass
class ProbeResult:
    """Aggregated result of a rate limit probing session."""

    url: str
    total_requests: int = 0
    successful: int = 0
    rate_limited: int = 0
    errors: int = 0
    first_429_at: Optional[int] = None
    rate_limit_info: Optional[RateLimitInfo] = None
    cooldown_seconds: Optional[float] = None
    safe_rps: Optional[float] = None
    headers_seen: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

_RATE_LIMIT_HEADER_KEYS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-retry-after",
    "cf-rate-limit",
]


def _get_header_ci(headers: Dict[str, str], *keys: str) -> Optional[str]:
    """Case-insensitive header lookup, trying multiple key variants."""
    lower_map = {k.lower(): v for k, v in headers.items()}
    for key in keys:
        val = lower_map.get(key.lower())
        if val is not None:
            return val
    return None


def _parse_retry_after(value: str) -> Optional[float]:
    """Parse a Retry-After value (seconds integer or HTTP date)."""
    try:
        return float(value)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
        delta = dt.timestamp() - time.time()
        return max(delta, 0.0)
    except Exception:
        return None


def parse_rate_limit_headers(headers: Dict[str, str]) -> Optional[RateLimitInfo]:
    """Parse standard and common rate limit headers.

    Recognises:
    - X-RateLimit-Limit / X-Rate-Limit-Limit / RateLimit-Limit
    - X-RateLimit-Remaining / X-Rate-Limit-Remaining / RateLimit-Remaining
    - X-RateLimit-Reset / X-Rate-Limit-Reset / RateLimit-Reset
    - Retry-After (seconds or HTTP date)
    - X-Retry-After
    - CF-Rate-Limit (Cloudflare)

    Returns ``None`` when no recognised rate limit headers are present.
    """
    limit_val = _get_header_ci(
        headers,
        "x-ratelimit-limit",
        "x-rate-limit-limit",
        "ratelimit-limit",
    )
    remaining_val = _get_header_ci(
        headers,
        "x-ratelimit-remaining",
        "x-rate-limit-remaining",
        "ratelimit-remaining",
    )
    reset_val = _get_header_ci(
        headers,
        "x-ratelimit-reset",
        "x-rate-limit-reset",
        "ratelimit-reset",
    )
    retry_after_val = _get_header_ci(headers, "retry-after", "x-retry-after")
    cf_val = _get_header_ci(headers, "cf-rate-limit")

    # Nothing found at all?
    if all(
        v is None
        for v in [limit_val, remaining_val, reset_val, retry_after_val, cf_val]
    ):
        return None

    info = RateLimitInfo(source="headers")

    if limit_val is not None:
        try:
            info.limit = int(limit_val)
        except ValueError:
            pass

    if remaining_val is not None:
        try:
            info.remaining = int(remaining_val)
        except ValueError:
            pass

    if reset_val is not None:
        try:
            info.reset_seconds = float(reset_val)
        except ValueError:
            pass

    if retry_after_val is not None:
        parsed = _parse_retry_after(retry_after_val)
        if parsed is not None:
            info.reset_seconds = parsed

    if cf_val is not None:
        try:
            info.limit = int(cf_val)
        except ValueError:
            pass

    return info


# ---------------------------------------------------------------------------
# Collect rate-limit-related headers from a response
# ---------------------------------------------------------------------------


def _collect_rl_headers(resp_headers: Dict[str, str]) -> Dict[str, str]:
    """Return only rate-limit-related headers from a response."""
    out: Dict[str, str] = {}
    for k, v in resp_headers.items():
        kl = k.lower()
        if any(
            tok in kl
            for tok in ("ratelimit", "rate-limit", "retry-after", "cf-rate-limit")
        ):
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Core probing
# ---------------------------------------------------------------------------


def probe_rate_limit(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    max_requests: int = 100,
    rps: float = 10.0,
    timeout: float = 10.0,
) -> ProbeResult:
    """Send requests at a controlled rate and detect rate limiting.

    Sends up to *max_requests* at *rps* requests-per-second, tracking status
    codes and parsing rate limit headers.  Stops early after 3 consecutive 429
    responses and then measures cooldown.
    """
    result = ProbeResult(url=url)
    interval = 1.0 / rps if rps > 0 else 0.0
    consecutive_429 = 0
    req_headers = headers or {}

    for i in range(1, max_requests + 1):
        start = time.monotonic()
        try:
            resp = requests.request(
                method, url, headers=req_headers, timeout=timeout, allow_redirects=False
            )
        except requests.RequestException:
            result.total_requests = i
            result.errors += 1
            consecutive_429 = 0
            _sleep_remaining(start, interval)
            continue

        result.total_requests = i
        status = resp.status_code

        if 200 <= status < 400:
            result.successful += 1
            consecutive_429 = 0
        elif status == 429:
            result.rate_limited += 1
            consecutive_429 += 1
            if result.first_429_at is None:
                result.first_429_at = i
        elif status >= 500:
            result.errors += 1
            consecutive_429 = 0
        else:
            result.successful += 1
            consecutive_429 = 0

        # Collect headers from every response; last one wins
        rl_headers = _collect_rl_headers(dict(resp.headers))
        if rl_headers:
            result.headers_seen.update(rl_headers)

        info = parse_rate_limit_headers(dict(resp.headers))
        if info is not None:
            result.rate_limit_info = info

        # Early stop on 3 consecutive 429s
        if consecutive_429 >= 3:
            break

        _sleep_remaining(start, interval)

    # Measure cooldown if we were rate limited
    if result.rate_limited > 0:
        cd = measure_cooldown(url, method=method, headers=headers)
        result.cooldown_seconds = cd

    # Calculate safe RPS recommendation
    if result.first_429_at is not None and result.first_429_at > 1:
        # Leave 20% headroom below the detected threshold
        result.safe_rps = round(
            (result.first_429_at - 1) * rps / result.first_429_at * 0.8, 2
        )
    elif result.rate_limited == 0 and result.successful > 0:
        # No rate limit hit -- the tested RPS appears safe
        result.safe_rps = rps

    return result


def _sleep_remaining(start: float, interval: float) -> None:
    """Sleep for the remaining portion of *interval* since *start*."""
    elapsed = time.monotonic() - start
    remaining = interval - elapsed
    if remaining > 0:
        time.sleep(remaining)


# ---------------------------------------------------------------------------
# Binary search
# ---------------------------------------------------------------------------


def binary_search_limit(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    low_rps: float = 1.0,
    high_rps: float = 50.0,
    timeout: float = 10.0,
) -> ProbeResult:
    """Binary search for the rate limit threshold between *low_rps* and *high_rps*."""
    best_result: Optional[ProbeResult] = None
    iterations = 0
    max_iterations = 8

    while high_rps - low_rps > 0.5 and iterations < max_iterations:
        mid = (low_rps + high_rps) / 2.0
        result = probe_rate_limit(
            url,
            method=method,
            headers=headers,
            max_requests=20,
            rps=mid,
            timeout=timeout,
        )
        best_result = result
        iterations += 1

        if result.rate_limited > 0:
            high_rps = mid
        else:
            low_rps = mid

    if best_result is None:
        best_result = ProbeResult(url=url)

    best_result.safe_rps = round(low_rps * 0.8, 2)
    return best_result


# ---------------------------------------------------------------------------
# Cooldown measurement
# ---------------------------------------------------------------------------


def measure_cooldown(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    max_wait: float = 120.0,
) -> Optional[float]:
    """After being rate limited, measure seconds until requests succeed again.

    Polls every 5 seconds.  Returns ``None`` if the endpoint does not recover
    within *max_wait* seconds.
    """
    req_headers = headers or {}
    start = time.monotonic()

    while (time.monotonic() - start) < max_wait:
        try:
            resp = requests.request(
                method, url, headers=req_headers, timeout=10.0, allow_redirects=False
            )
            if resp.status_code != 429:
                return round(time.monotonic() - start, 2)
        except requests.RequestException:
            pass
        time.sleep(5.0)

    return None


# ---------------------------------------------------------------------------
# Limit type detection (heuristic)
# ---------------------------------------------------------------------------


def detect_limit_type(url: str, method: str = "GET") -> str:
    """Heuristic to guess what the rate limit is keyed on.

    Sends a small burst with different User-Agent strings and checks whether
    both sets are limited at the same point.
    """
    ua_a = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestAgentA/1.0"
    ua_b = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) TestAgentB/1.0"

    result_a = probe_rate_limit(
        url, method=method, headers={"User-Agent": ua_a}, max_requests=30, rps=10.0
    )
    result_b = probe_rate_limit(
        url, method=method, headers={"User-Agent": ua_b}, max_requests=30, rps=10.0
    )

    if result_a.first_429_at and result_b.first_429_at:
        diff = abs(result_a.first_429_at - result_b.first_429_at)
        if diff <= 2:
            return "per_ip"
        else:
            return "per_user_agent"

    return "unknown"
