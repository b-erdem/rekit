"""
Frida bypass script generator for certificate pinning.

Takes pinning detections from the scanner and produces targeted Frida
JavaScript that disables each detected pinning mechanism.
"""

from __future__ import annotations

from typing import List

from rekit.certpatch.scanner import PinningDetection, PinningType


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_bypass(detections: List[PinningDetection]) -> str:
    """Generate a single Frida JS file that bypasses ALL detected pinning."""
    sections: List[str] = []

    # Header
    sections.append(_HEADER)

    # Collect unique types
    seen_types: set[PinningType] = set()

    for det in detections:
        if det.pinning_type not in seen_types:
            seen_types.add(det.pinning_type)
            bypass_code = generate_bypass_for_type(det)
            if bypass_code:
                sections.append(bypass_code)

    if not seen_types:
        sections.append(
            '    console.log("[certpatch] No pinning detections — nothing to bypass.");'
        )

    # Footer
    sections.append(_FOOTER)

    return "\n".join(sections)


def generate_bypass_for_type(detection: PinningDetection) -> str:
    """Generate a bypass snippet for a specific detection."""
    generators = {
        PinningType.OKHTTP_CERT_PINNER: _bypass_okhttp,
        PinningType.NETWORK_SECURITY_CONFIG: _bypass_network_security_config,
        PinningType.CUSTOM_TRUST_MANAGER: _bypass_custom_trust_manager,
        PinningType.TRUSTKIT: _bypass_trustkit,
        PinningType.FLUTTER_SSL: _bypass_flutter_ssl,
        PinningType.REACT_NATIVE_SSL: _bypass_react_native_ssl,
        PinningType.XAMARIN_SSL: _bypass_xamarin_ssl,
        PinningType.PUBLIC_KEY_PINNING: _bypass_public_key_pinning,
        PinningType.CERTIFICATE_TRANSPARENCY: _bypass_certificate_transparency,
        PinningType.UNKNOWN: _bypass_unknown,
    }

    gen = generators.get(detection.pinning_type, _bypass_unknown)
    return gen(detection)


def generate_network_security_config() -> str:
    """Generate a permissive network_security_config.xml that trusts user CAs."""
    return _PERMISSIVE_NSC


# ---------------------------------------------------------------------------
# Bypass generators per type
# ---------------------------------------------------------------------------


def _bypass_okhttp(det: PinningDetection) -> str:
    domains_comment = ""
    if det.pinned_domains:
        domains_comment = f"    //   Pinned domains: {', '.join(det.pinned_domains)}\n"
    hashes_comment = ""
    if det.pin_hashes:
        hashes_comment = f"    //   Pin hashes: {', '.join(det.pin_hashes)}\n"

    return f"""\
    // --- OkHttp CertificatePinner bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
{domains_comment}{hashes_comment}\
    try {{
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {{
            console.log("[certpatch] Bypassing OkHttp CertificatePinner for: " + hostname);
        }};
        // Also bypass the check$ variant (Kotlin coroutines)
        try {{
            CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function(hostname, fn) {{
                console.log("[certpatch] Bypassing OkHttp CertificatePinner (check$) for: " + hostname);
            }};
        }} catch (e2) {{
            // check$okhttp may not exist in all versions
        }}
        console.log("[certpatch] OkHttp CertificatePinner bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] OkHttp CertificatePinner not found: " + e.message);
    }}"""


def _bypass_network_security_config(det: PinningDetection) -> str:
    domains_comment = ""
    if det.pinned_domains:
        domains_comment = f"    //   Pinned domains: {', '.join(det.pinned_domains)}\n"

    return f"""\
    // --- Network Security Config bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
{domains_comment}\
    // Cannot hook XML directly, but can hook the config loader
    try {{
        var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NetworkSecurityTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(certs, authType) {{
            console.log("[certpatch] Bypassing NetworkSecurityConfig check for authType: " + authType);
        }};
        console.log("[certpatch] NetworkSecurityConfig bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] NetworkSecurityConfig bypass not available: " + e.message);
    }}"""


def _bypass_custom_trust_manager(det: PinningDetection) -> str:
    return f"""\
    // --- Custom TrustManager bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        // Replace all TrustManagers with a permissive one
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var PermissiveTrustManager = Java.registerClass({{
            name: "com.rekit.PermissiveTrustManager",
            implements: [X509TrustManager],
            methods: {{
                checkClientTrusted: function(chain, authType) {{}},
                checkServerTrusted: function(chain, authType) {{
                    console.log("[certpatch] Bypassing custom TrustManager checkServerTrusted");
                }},
                getAcceptedIssuers: function() {{
                    return [];
                }}
            }}
        }});

        var TrustManagers = [PermissiveTrustManager.$new()];
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);

        // Also hook SSLContext.init to always inject our TrustManager
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {{
            console.log("[certpatch] Replacing TrustManagers in SSLContext.init");
            this.init(km, TrustManagers, sr);
        }};

        console.log("[certpatch] Custom TrustManager bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] Custom TrustManager bypass failed: " + e.message);
    }}"""


def _bypass_trustkit(det: PinningDetection) -> str:
    return f"""\
    // --- TrustKit bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        var PinningTrustManager = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
        PinningTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(chain, authType) {{
            console.log("[certpatch] Bypassing TrustKit PinningTrustManager");
        }};
        console.log("[certpatch] TrustKit bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] TrustKit not found: " + e.message);
    }}"""


def _bypass_flutter_ssl(det: PinningDetection) -> str:
    return f"""\
    // --- Flutter/BoringSSL bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    // Flutter uses BoringSSL internally, need native hooks
    try {{
        var flutter_lib = Module.findBaseAddress("libflutter.so");
        if (flutter_lib) {{
            // Hook ssl_crypto_x509_session_verify_cert_chain
            var verify_func = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
            if (verify_func) {{
                Interceptor.attach(verify_func, {{
                    onLeave: function(retval) {{
                        retval.replace(0x1);
                        console.log("[certpatch] Bypassing Flutter SSL cert verification");
                    }}
                }});
                console.log("[certpatch] Flutter BoringSSL bypass applied (exported symbol).");
            }} else {{
                // Try pattern scanning for the verify function
                console.log("[certpatch] Flutter verify function not exported, try pattern scan.");
            }}
        }} else {{
            console.log("[certpatch] libflutter.so not loaded yet, waiting...");
        }}
    }} catch (e) {{
        console.log("[certpatch] Flutter SSL bypass failed: " + e.message);
    }}"""


def _bypass_react_native_ssl(det: PinningDetection) -> str:
    return f"""\
    // --- React Native SSL Pinning bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        // Bypass OkHttpClientFactory custom TrustManager
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClient.sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory", "javax.net.ssl.X509TrustManager").implementation = function(factory, trustManager) {{
            console.log("[certpatch] Bypassing React Native SSL pinning (sslSocketFactory)");
            return this;
        }};
        console.log("[certpatch] React Native SSL bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] React Native SSL bypass failed: " + e.message);
    }}"""


def _bypass_xamarin_ssl(det: PinningDetection) -> str:
    return f"""\
    // --- Xamarin SSL bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        // Hook Mono's ServerCertificateValidationCallback
        var ServicePointManager = Java.use("mono.net.security.LegacyTlsProvider");
        // Xamarin typically wraps .NET's certificate callback; this varies by version
        console.log("[certpatch] Xamarin SSL bypass: manual patching may be required.");
        console.log("[certpatch] Consider using Frida's Mono bridge for .NET hooks.");
    }} catch (e) {{
        console.log("[certpatch] Xamarin SSL bypass failed: " + e.message);
    }}"""


def _bypass_public_key_pinning(det: PinningDetection) -> str:
    return f"""\
    // --- Generic Public Key Pinning bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        // Hook MessageDigest to return expected hashes
        var MessageDigest = Java.use("java.security.MessageDigest");
        var original_digest = MessageDigest.digest.overload("[B");
        // Note: Generic public key pinning requires app-specific analysis.
        // The class at {det.file_path} likely compares certificate hashes.
        // Consider hooking the specific comparison method instead.
        console.log("[certpatch] Generic public key pinning detected — manual review recommended.");
        console.log("[certpatch] File: {det.file_path}:{det.line_number or "?"}");
    }} catch (e) {{
        console.log("[certpatch] Public key pinning bypass failed: " + e.message);
    }}"""


def _bypass_certificate_transparency(det: PinningDetection) -> str:
    return f"""\
    // --- Certificate Transparency bypass ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    try {{
        // Try common CT checker classes
        try {{
            var CTChecker = Java.use("okhttp3.internal.tls.CertificateTransparencyChecker");
            CTChecker.verifyCertificateTransparency.implementation = function() {{
                console.log("[certpatch] Bypassing CertificateTransparency check");
            }};
        }} catch (e2) {{
            // Try alternative CT implementations
            try {{
                var CTInterceptor = Java.use("com.babylon.certificatetransparency.CTInterceptorBuilder");
                console.log("[certpatch] CT interceptor found — consider removing from interceptor chain.");
            }} catch (e3) {{
                // CT implementation not found via known classes
            }}
        }}
        console.log("[certpatch] Certificate Transparency bypass applied.");
    }} catch (e) {{
        console.log("[certpatch] CT bypass failed: " + e.message);
    }}"""


def _bypass_unknown(det: PinningDetection) -> str:
    return f"""\
    // --- Unknown pinning type ---
    // Detected in: {det.file_path}:{det.line_number or "?"}
    // Manual analysis required for this pinning implementation.
    console.log("[certpatch] Unknown pinning detected at {det.file_path}:{det.line_number or "?"}");"""


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_HEADER = """\
/**
 * certpatch — Frida SSL Pinning Bypass Script
 *
 * Generated by rekit certpatch.
 * Usage: frida -U -f <package> -l bypass.js --no-pause
 */

'use strict';

Java.perform(function() {
    console.log("[certpatch] Starting SSL pinning bypass...");
"""

_FOOTER = """\

    console.log("[certpatch] All bypasses applied.");
});"""

_PERMISSIVE_NSC = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>"""
