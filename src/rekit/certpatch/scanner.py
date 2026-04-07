"""
Certificate pinning scanner.

Scans decompiled APK source for all known certificate pinning implementations
and returns structured detections with domains, hashes, and bypass difficulty.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class PinningType(Enum):
    """Known certificate pinning implementation types."""

    OKHTTP_CERT_PINNER = "okhttp_cert_pinner"
    NETWORK_SECURITY_CONFIG = "network_security_config"
    CUSTOM_TRUST_MANAGER = "custom_trust_manager"
    TRUSTKIT = "trustkit"
    FLUTTER_SSL = "flutter_ssl"
    REACT_NATIVE_SSL = "react_native_ssl"
    XAMARIN_SSL = "xamarin_ssl"
    PUBLIC_KEY_PINNING = "public_key_pinning"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    UNKNOWN = "unknown"


@dataclass
class PinningDetection:
    """A single certificate pinning detection in a decompiled APK."""

    pinning_type: PinningType
    file_path: str  # relative path in decompiled source
    line_number: Optional[int] = None
    code_snippet: str = ""
    pinned_domains: List[str] = field(default_factory=list)
    pin_hashes: List[str] = field(default_factory=list)
    confidence: float = 0.5
    bypass_difficulty: str = "medium"  # easy, medium, hard


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# OkHttp CertificatePinner
_CERT_PINNER_BUILDER_RE = re.compile(r"CertificatePinner\.Builder\(\)")
_CERT_PINNER_RE = re.compile(r"CertificatePinner")
_CERT_PIN_ADD_RE = re.compile(
    r'\.add\s*\(\s*"([^"]+)"\s*,\s*"(sha256/[A-Za-z0-9+/=]+)"'
)

# Network security config XML
_PIN_SET_RE = re.compile(r"<pin-set", re.IGNORECASE)
_PIN_DIGEST_RE = re.compile(r'<pin\s+digest="SHA-256"\s*>([^<]+)</pin>', re.IGNORECASE)
_DOMAIN_RE = re.compile(r"<domain[^>]*>([^<]+)</domain>", re.IGNORECASE)

# Custom X509TrustManager
_TRUST_MANAGER_IMPL_RE = re.compile(
    r"class\s+(\w+)\s+implements\s+[\w,\s]*X509TrustManager"
)
_TRUST_MANAGER_KOTLIN_RE = re.compile(
    r"class\s+(\w+)\s*(?:\([^)]*\))?\s*:\s*[\w,\s]*X509TrustManager"
)
_CHECK_SERVER_TRUSTED_RE = re.compile(r"checkServerTrusted")

# TrustKit
_TRUSTKIT_INIT_RE = re.compile(
    r"TrustKit\.initializeWithNetworkSecurityConfiguration", re.IGNORECASE
)
_TRUSTKIT_IMPORT_RE = re.compile(r"com\.datatheorem\.android\.trustkit")

# Flutter/Dart SSL
_FLUTTER_SECURITY_CONTEXT_RE = re.compile(r"SecurityContext")
_FLUTTER_BAD_CERT_RE = re.compile(r"[Bb]ad[Cc]ertificate[Cc]allback")
_FLUTTER_HTTP_CLIENT_RE = re.compile(r"HttpClient\s*\.\s*badCertificateCallback")

# React Native SSL
_RN_SSL_PINNING_RE = re.compile(r"react-native-ssl-pinning", re.IGNORECASE)
_RN_SSL_CONFIG_RE = re.compile(r"RNSSLPinning", re.IGNORECASE)
_RN_OKHTTP_FACTORY_RE = re.compile(r"OkHttpClientFactory")

# Xamarin
_XAMARIN_CERT_RE = re.compile(
    r"ServicePointManager\s*\.\s*ServerCertificateValidationCallback"
)

# Certificate Transparency
_CT_CHECKER_RE = re.compile(r"CertificateTransparencyChecker", re.IGNORECASE)
_CT_LOG_RE = re.compile(r"ct-log|certificate.transparency", re.IGNORECASE)

# Public Key Pinning (generic)
_PUBLIC_KEY_RE = re.compile(r"getPublicKey\s*\(\s*\)")
_GET_ENCODED_RE = re.compile(r"getEncoded\s*\(\s*\)")
_SHA256_DIGEST_RE = re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-256"\s*\)')
_X509_CERT_RE = re.compile(r"X509Certificate")

# Max file size to scan (5 MB)
_MAX_FILE_SIZE = 5 * 1024 * 1024

# File extensions to scan
_SCAN_EXTENSIONS = {
    ".java",
    ".kt",
    ".smali",
    ".xml",
    ".json",
    ".dart",
    ".cs",
    ".properties",
    ".yaml",
    ".yml",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_for_pinning(source_dir: Path) -> List[PinningDetection]:
    """Scan decompiled APK source for all pinning implementations."""
    detections: List[PinningDetection] = []
    source_dir = source_dir.resolve()

    # Scan network_security_config.xml specifically
    for xml_path in source_dir.rglob("network_security_config.xml"):
        detections.extend(_scan_network_security_config(xml_path, source_dir))

    # Scan source files
    for fpath in source_dir.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in _SCAN_EXTENSIONS:
            continue
        # Skip network_security_config.xml (already handled)
        if fpath.name == "network_security_config.xml":
            continue
        try:
            size = fpath.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_SIZE or size == 0:
            continue

        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            continue

        rel = str(fpath.relative_to(source_dir))
        detections.extend(_scan_okhttp(text, rel))
        detections.extend(_scan_custom_trust_manager(text, rel))
        detections.extend(_scan_trustkit(text, rel))
        detections.extend(_scan_flutter_ssl(text, rel))
        detections.extend(_scan_react_native_ssl(text, rel))
        detections.extend(_scan_xamarin(text, rel))
        detections.extend(_scan_certificate_transparency(text, rel))
        detections.extend(_scan_public_key_pinning(text, rel))

    return detections


# ---------------------------------------------------------------------------
# Per-type scanners
# ---------------------------------------------------------------------------


def _scan_okhttp(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect OkHttp CertificatePinner usage."""
    detections: List[PinningDetection] = []

    for m in _CERT_PINNER_BUILDER_RE.finditer(text):
        line_no = text[: m.start()].count("\n") + 1
        chunk = text[m.start() : m.start() + 1500]
        domains: List[str] = []
        hashes: List[str] = []

        for pm in _CERT_PIN_ADD_RE.finditer(chunk):
            domain = pm.group(1)
            pin_hash = pm.group(2)
            if domain not in domains:
                domains.append(domain)
            if pin_hash not in hashes:
                hashes.append(pin_hash)

        snippet_end = min(len(chunk), 400)
        semi = chunk.find(";", 0, snippet_end)
        if semi != -1:
            snippet_end = semi + 1

        detections.append(
            PinningDetection(
                pinning_type=PinningType.OKHTTP_CERT_PINNER,
                file_path=rel_path,
                line_number=line_no,
                code_snippet=chunk[:snippet_end].strip(),
                pinned_domains=domains,
                pin_hashes=hashes,
                confidence=0.95 if domains else 0.7,
                bypass_difficulty="easy",
            )
        )

    # Also catch plain CertificatePinner references without .Builder()
    if not detections and _CERT_PINNER_RE.search(text):
        for m in _CERT_PINNER_RE.finditer(text):
            if "Builder" in text[m.start() : m.start() + 30]:
                continue
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())
            detections.append(
                PinningDetection(
                    pinning_type=PinningType.OKHTTP_CERT_PINNER,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=0.6,
                    bypass_difficulty="easy",
                )
            )
            break  # one is enough

    return detections


def _scan_network_security_config(
    xml_path: Path, source_dir: Path
) -> List[PinningDetection]:
    """Parse network_security_config.xml for pin-set elements."""
    detections: List[PinningDetection] = []
    rel = str(xml_path.relative_to(source_dir))

    try:
        text = xml_path.read_text(errors="replace")
    except OSError:
        return detections

    # Try XML parsing first
    domains: List[str] = []
    hashes: List[str] = []

    try:
        root = ET.fromstring(text)
        for domain_config in root.iter("domain-config"):
            config_domains: List[str] = []
            config_hashes: List[str] = []
            for domain_el in domain_config.iter("domain"):
                if domain_el.text:
                    config_domains.append(domain_el.text.strip())
            for pin_el in domain_config.iter("pin"):
                if pin_el.text:
                    config_hashes.append(pin_el.text.strip())

            if config_domains or config_hashes:
                domains.extend(config_domains)
                hashes.extend(config_hashes)
    except ET.ParseError:
        # Fall back to regex
        for m in _DOMAIN_RE.finditer(text):
            domains.append(m.group(1).strip())
        for m in _PIN_DIGEST_RE.finditer(text):
            hashes.append(m.group(1).strip())

    if _PIN_SET_RE.search(text) or hashes:
        line_no = 1
        pin_match = _PIN_SET_RE.search(text)
        if pin_match:
            line_no = text[: pin_match.start()].count("\n") + 1

        detections.append(
            PinningDetection(
                pinning_type=PinningType.NETWORK_SECURITY_CONFIG,
                file_path=rel,
                line_number=line_no,
                code_snippet=text[:500].strip(),
                pinned_domains=domains,
                pin_hashes=hashes,
                confidence=0.95,
                bypass_difficulty="easy",
            )
        )

    return detections


def _scan_custom_trust_manager(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect custom X509TrustManager implementations."""
    detections: List[PinningDetection] = []

    for pattern in (_TRUST_MANAGER_IMPL_RE, _TRUST_MANAGER_KOTLIN_RE):
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            chunk = text[m.start() : m.start() + 2000]

            # Check if checkServerTrusted is present
            has_check = bool(_CHECK_SERVER_TRUSTED_RE.search(chunk))
            confidence = 0.9 if has_check else 0.6

            detections.append(
                PinningDetection(
                    pinning_type=PinningType.CUSTOM_TRUST_MANAGER,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=chunk[:400].strip(),
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=confidence,
                    bypass_difficulty="medium",
                )
            )

    return detections


def _scan_trustkit(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect TrustKit usage."""
    detections: List[PinningDetection] = []

    for pattern in (_TRUSTKIT_INIT_RE, _TRUSTKIT_IMPORT_RE):
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())

            detections.append(
                PinningDetection(
                    pinning_type=PinningType.TRUSTKIT,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=0.9,
                    bypass_difficulty="easy",
                )
            )
            return detections  # one per file is enough

    return detections


def _scan_flutter_ssl(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect Flutter/Dart SSL pinning."""
    detections: List[PinningDetection] = []

    for pattern in (
        _FLUTTER_BAD_CERT_RE,
        _FLUTTER_HTTP_CLIENT_RE,
        _FLUTTER_SECURITY_CONTEXT_RE,
    ):
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())

            detections.append(
                PinningDetection(
                    pinning_type=PinningType.FLUTTER_SSL,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=0.8,
                    bypass_difficulty="hard",
                )
            )
            return detections  # one per file is enough

    return detections


def _scan_react_native_ssl(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect React Native SSL pinning."""
    detections: List[PinningDetection] = []

    for pattern in (_RN_SSL_PINNING_RE, _RN_SSL_CONFIG_RE, _RN_OKHTTP_FACTORY_RE):
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())

            detections.append(
                PinningDetection(
                    pinning_type=PinningType.REACT_NATIVE_SSL,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=0.85,
                    bypass_difficulty="medium",
                )
            )
            return detections  # one per file is enough

    return detections


def _scan_xamarin(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect Xamarin SSL pinning."""
    detections: List[PinningDetection] = []

    for m in _XAMARIN_CERT_RE.finditer(text):
        line_no = text[: m.start()].count("\n") + 1
        snippet = _snippet_around(text, m.start())

        detections.append(
            PinningDetection(
                pinning_type=PinningType.XAMARIN_SSL,
                file_path=rel_path,
                line_number=line_no,
                code_snippet=snippet,
                pinned_domains=[],
                pin_hashes=[],
                confidence=0.9,
                bypass_difficulty="medium",
            )
        )

    return detections


def _scan_certificate_transparency(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect Certificate Transparency checks."""
    detections: List[PinningDetection] = []

    for pattern in (_CT_CHECKER_RE, _CT_LOG_RE):
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())

            detections.append(
                PinningDetection(
                    pinning_type=PinningType.CERTIFICATE_TRANSPARENCY,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=0.8,
                    bypass_difficulty="easy",
                )
            )
            return detections  # one per file is enough

    return detections


def _scan_public_key_pinning(text: str, rel_path: str) -> List[PinningDetection]:
    """Detect generic public key pinning patterns."""
    # Require at least two of the indicators to be present
    indicators = [
        bool(_PUBLIC_KEY_RE.search(text)),
        bool(_GET_ENCODED_RE.search(text)),
        bool(_SHA256_DIGEST_RE.search(text)),
        bool(_X509_CERT_RE.search(text)),
    ]
    count = sum(indicators)

    if count < 2:
        return []

    # Find the first indicator match for location
    for pattern in (_SHA256_DIGEST_RE, _PUBLIC_KEY_RE, _GET_ENCODED_RE, _X509_CERT_RE):
        m = pattern.search(text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            snippet = _snippet_around(text, m.start())

            difficulty = "hard" if count >= 3 else "medium"
            confidence = min(0.5 + count * 0.15, 0.95)

            return [
                PinningDetection(
                    pinning_type=PinningType.PUBLIC_KEY_PINNING,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    pinned_domains=[],
                    pin_hashes=[],
                    confidence=confidence,
                    bypass_difficulty=difficulty,
                )
            ]

    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snippet_around(text: str, pos: int, context_lines: int = 3) -> str:
    """Return a few lines of context around *pos*."""
    line_start = text.rfind("\n", 0, pos)
    if line_start == -1:
        line_start = 0
    for _ in range(context_lines - 1):
        prev = text.rfind("\n", 0, line_start)
        if prev == -1:
            break
        line_start = prev

    line_end = pos
    for _ in range(context_lines):
        nxt = text.find("\n", line_end + 1)
        if nxt == -1:
            line_end = len(text)
            break
        line_end = nxt

    return text[line_start:line_end].strip()
