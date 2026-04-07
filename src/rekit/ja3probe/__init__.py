"""
ja3probe -- Test which TLS fingerprints (JA3/JA4) a target URL accepts or rejects.

Probes a target with multiple browser TLS fingerprint profiles using curl_cffi,
identifies bot protection systems, and recommends the best impersonation profile.
"""

from rekit.ja3probe.fingerprints import FingerprintProfile, PROFILES
from rekit.ja3probe.prober import (
    ProbeResult,
    AnalysisReport,
    probe_fingerprint,
    probe_all,
    analyze_results,
)

__all__ = [
    "FingerprintProfile",
    "PROFILES",
    "ProbeResult",
    "AnalysisReport",
    "probe_fingerprint",
    "probe_all",
    "analyze_results",
]
