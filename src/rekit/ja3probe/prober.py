"""
TLS fingerprint probing engine.

Sends requests with different TLS fingerprint profiles and analyses
which ones are accepted, rejected, or challenged by bot protection.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from rekit.ja3probe.fingerprints import FingerprintProfile, PROFILES


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Outcome of probing a single fingerprint profile against a target."""

    profile_name: str
    accepted: bool
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    error: Optional[str] = None
    redirect_url: Optional[str] = None
    headers_received: Dict[str, str] = field(default_factory=dict)
    challenge_detected: bool = False


@dataclass
class AnalysisReport:
    """Aggregated analysis of all probe results."""

    url: str
    total_tested: int
    accepted_count: int
    rejected_count: int
    accepted_profiles: List[str]
    rejected_profiles: List[str]
    protection_system: Optional[str]
    recommended_profile: Optional[str]
    details: List[ProbeResult]


# ---------------------------------------------------------------------------
# Challenge / protection detection
# ---------------------------------------------------------------------------

_CHALLENGE_INDICATORS = {
    # Header-based
    "x-datadome": "DataDome",
    "x-datadome-cid": "DataDome",
    "x-dd-b": "DataDome",
    "cf-mitigated": "Cloudflare",
    "cf-ray": None,  # presence alone is not a challenge, but combined with 403 it is
    "x-akamai-session": "Akamai Bot Manager",
    "x-px-mid": "PerimeterX",
    "x-distil-cs": "Distil Networks",
    "server": None,  # checked via value below
}

_BODY_SIGNATURES = [
    ("datadome", "DataDome"),
    ('"url":"https://geo.captcha-delivery.com', "DataDome"),
    ("Attention Required! | Cloudflare", "Cloudflare"),
    ("cf-browser-verification", "Cloudflare"),
    ("challenges.cloudflare.com", "Cloudflare"),
    ("_cf_chl_opt", "Cloudflare"),
    ("managed by Akamai", "Akamai Bot Manager"),
    ("ak_bmsc", "Akamai Bot Manager"),
    ("perimeterx", "PerimeterX"),
    ("px-captcha", "PerimeterX"),
    ("distil_r_captcha", "Distil Networks"),
    ("imperva", "Imperva"),
    ("incapsula", "Imperva"),
    ("blocked", None),  # generic
    ("access denied", None),
]


def _detect_challenge(
    status_code: int,
    headers: Dict[str, str],
    body: str,
) -> tuple[bool, Optional[str]]:
    """Return (is_challenge, protection_system_name)."""
    detected_system: Optional[str] = None

    # Status codes that strongly suggest a challenge
    challenge_statuses = {403, 429, 503}

    # Check headers
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for hdr, system in _CHALLENGE_INDICATORS.items():
        if hdr in lower_headers:
            if hdr == "server":
                val = lower_headers[hdr].lower()
                if "cloudflare" in val:
                    detected_system = "Cloudflare"
                elif "akamaighost" in val or "akamai" in val:
                    detected_system = "Akamai Bot Manager"
            elif system:
                detected_system = system

    # Check body signatures
    body_lower = body.lower() if body else ""
    for sig, system in _BODY_SIGNATURES:
        if sig.lower() in body_lower:
            if system:
                detected_system = system
            if status_code in challenge_statuses:
                return True, detected_system

    # Cloudflare-specific: 403 + cf-ray header
    if status_code in challenge_statuses and "cf-ray" in lower_headers:
        detected_system = detected_system or "Cloudflare"
        return True, detected_system

    # DataDome JSON redirect pattern (200 with JSON containing captcha URL)
    if detected_system == "DataDome" and "captcha-delivery.com" in body_lower:
        return True, "DataDome"

    # If we found a known protection header and got a block status, it's a challenge
    if detected_system and status_code in challenge_statuses:
        return True, detected_system

    return False, detected_system


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

def _ensure_curl_cffi():
    """Import curl_cffi or raise a helpful error."""
    try:
        from curl_cffi.requests import Session
        return Session
    except ImportError:
        raise ImportError(
            "curl_cffi is required for TLS fingerprint probing.\n"
            "Install it with:  pip install rekit[tls]\n"
            "Or directly:      pip install curl_cffi"
        )


def probe_fingerprint(
    url: str,
    profile: FingerprintProfile,
    timeout: int = 10,
) -> ProbeResult:
    """Probe a single fingerprint profile against *url*."""
    Session = _ensure_curl_cffi()

    start = time.monotonic()
    try:
        if profile.has_impersonation:
            # Use curl_cffi with TLS impersonation
            with Session(impersonate=profile.impersonate_str) as s:
                resp = s.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": profile.user_agent},
                )
        else:
            # Fallback: plain curl_cffi request with only the UA set
            with Session() as s:
                resp = s.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": profile.user_agent},
                )

        elapsed_ms = (time.monotonic() - start) * 1000

        headers_dict = {k: v for k, v in resp.headers.items()}
        body_text = ""
        try:
            body_text = resp.text[:8192]  # limit to avoid huge allocations
        except Exception:
            pass

        challenge, protection = _detect_challenge(
            resp.status_code, headers_dict, body_text,
        )

        # Determine redirect
        redirect_url: Optional[str] = None
        if resp.url and str(resp.url) != url:
            redirect_url = str(resp.url)

        # Accepted = 2xx/3xx and no challenge
        accepted = (200 <= resp.status_code < 400) and not challenge

        return ProbeResult(
            profile_name=profile.name,
            accepted=accepted,
            status_code=resp.status_code,
            response_time_ms=round(elapsed_ms, 1),
            redirect_url=redirect_url,
            headers_received=headers_dict,
            challenge_detected=challenge,
        )

    except ImportError:
        raise
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return ProbeResult(
            profile_name=profile.name,
            accepted=False,
            response_time_ms=round(elapsed_ms, 1),
            error=f"{type(exc).__name__}: {exc}",
        )


def probe_all(
    url: str,
    profiles: Optional[Sequence[FingerprintProfile]] = None,
    timeout: int = 10,
    workers: int = 5,
) -> List[ProbeResult]:
    """Probe all (or selected) profiles concurrently."""
    if profiles is None:
        profiles = list(PROFILES.values())

    results: List[ProbeResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_fingerprint, url, p, timeout): p
            for p in profiles
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Sort by profile name for consistent output
    results.sort(key=lambda r: r.profile_name)
    return results


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_results(url: str, results: List[ProbeResult]) -> AnalysisReport:
    """Build an analysis report from probe results."""
    accepted = [r for r in results if r.accepted]
    rejected = [r for r in results if not r.accepted]

    # Determine protection system by majority vote
    systems: Dict[str, int] = {}
    for r in results:
        if r.challenge_detected:
            # Look up what _detect_challenge found -- re-derive from headers
            _, sys_name = _detect_challenge(
                r.status_code or 0,
                r.headers_received,
                "",  # we don't store the body
            )
            if sys_name:
                systems[sys_name] = systems.get(sys_name, 0) + 1

    # Also check the headers for protection hints even when no challenge
    for r in results:
        lower_h = {k.lower(): v for k, v in r.headers_received.items()}
        if "x-datadome" in lower_h or "x-datadome-cid" in lower_h:
            systems["DataDome"] = systems.get("DataDome", 0) + 1
        if "cf-ray" in lower_h:
            systems["Cloudflare"] = systems.get("Cloudflare", 0) + 1

    protection_system = max(systems, key=systems.get) if systems else None

    # Recommend the newest Chrome with impersonation that was accepted
    recommended: Optional[str] = None
    for r in sorted(accepted, key=lambda r: r.profile_name, reverse=True):
        profile = PROFILES.get(r.profile_name)
        if profile and profile.has_impersonation:
            recommended = profile.impersonate_str
            break

    return AnalysisReport(
        url=url,
        total_tested=len(results),
        accepted_count=len(accepted),
        rejected_count=len(rejected),
        accepted_profiles=[r.profile_name for r in accepted],
        rejected_profiles=[r.profile_name for r in rejected],
        protection_system=protection_system,
        recommended_profile=recommended,
        details=results,
    )
