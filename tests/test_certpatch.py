"""
Tests for rekit.certpatch — certificate pinning scanner and bypass generator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rekit.certpatch.generator import (
    generate_bypass,
    generate_bypass_for_type,
    generate_network_security_config,
)
from rekit.certpatch.scanner import (
    PinningDetection,
    PinningType,
    scan_for_pinning,
)


# ---------------------------------------------------------------------------
# Test data — inline code snippets
# ---------------------------------------------------------------------------

OKHTTP_PINNER = """\
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("cdn.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build();
"""

NETWORK_SECURITY_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set>
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
    </domain-config>
</network-security-config>"""

CUSTOM_TRUST_MANAGER = """\
public class CustomTrustManager implements X509TrustManager {
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // Custom pinning logic
        if (!verifyPin(chain)) {
            throw new CertificateException("Pin verification failed");
        }
    }
}
"""

TRUSTKIT_CODE = """\
import com.datatheorem.android.trustkit.TrustKit;

public class AppInit {
    public void init(Context context) {
        TrustKit.initializeWithNetworkSecurityConfiguration(context);
    }
}
"""

FLUTTER_SSL_CODE = """\
import 'dart:io';

void setupHttp() {
    HttpClient client = HttpClient();
    client.badCertificateCallback = (X509Certificate cert, String host, int port) {
        return false;
    };
}
"""

REACT_NATIVE_SSL_CODE = """\
import { fetch } from 'react-native-ssl-pinning';

const response = await fetch('https://api.example.com/data', {
    method: 'GET',
    sslPinning: {
        certs: ['cert1']
    }
});
"""

XAMARIN_CODE = """\
using System.Net;

ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => {
    return ValidateCertificate(certificate);
};
"""

CT_CODE = """\
OkHttpClient client = new OkHttpClient.Builder()
    .addInterceptor(new CertificateTransparencyChecker())
    .build();
"""

PUBLIC_KEY_PINNING_CODE = """\
public boolean verifyServerCert(X509Certificate cert) {
    byte[] publicKey = cert.getPublicKey().getEncoded();
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(publicKey);
    return Arrays.equals(hash, expectedHash);
}
"""


# ---------------------------------------------------------------------------
# Helper to write files into a fake decompiled source tree
# ---------------------------------------------------------------------------


def _write_source(tmp_path: Path, rel_path: str, content: str) -> None:
    full = tmp_path / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)


# ---------------------------------------------------------------------------
# Scanner tests
# ---------------------------------------------------------------------------


class TestOkHttpDetection:
    def test_detects_cert_pinner_builder(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        assert len(detections) >= 1
        det = detections[0]
        assert det.pinning_type == PinningType.OKHTTP_CERT_PINNER
        assert det.bypass_difficulty == "easy"

    def test_extracts_domains(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        det = detections[0]
        assert "api.example.com" in det.pinned_domains
        assert "cdn.example.com" in det.pinned_domains

    def test_extracts_hashes(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        det = detections[0]
        assert len(det.pin_hashes) == 2
        assert any("AAAA" in h for h in det.pin_hashes)
        assert any("BBBB" in h for h in det.pin_hashes)

    def test_high_confidence_with_domains(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        assert detections[0].confidence >= 0.9


class TestNetworkSecurityConfig:
    def test_detects_pin_set(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        detections = scan_for_pinning(tmp_path)
        assert len(detections) >= 1
        det = detections[0]
        assert det.pinning_type == PinningType.NETWORK_SECURITY_CONFIG
        assert det.bypass_difficulty == "easy"

    def test_extracts_domains(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        detections = scan_for_pinning(tmp_path)
        det = detections[0]
        assert "api.example.com" in det.pinned_domains

    def test_extracts_pin_hashes(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        detections = scan_for_pinning(tmp_path)
        det = detections[0]
        assert len(det.pin_hashes) >= 1
        assert any("AAAA" in h for h in det.pin_hashes)


class TestCustomTrustManager:
    def test_detects_trust_manager(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "com/example/CustomTrustManager.java", CUSTOM_TRUST_MANAGER
        )
        detections = scan_for_pinning(tmp_path)
        assert len(detections) >= 1
        det = [
            d for d in detections if d.pinning_type == PinningType.CUSTOM_TRUST_MANAGER
        ]
        assert len(det) >= 1
        assert det[0].bypass_difficulty == "medium"

    def test_high_confidence_with_check_server(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "com/example/CustomTrustManager.java", CUSTOM_TRUST_MANAGER
        )
        detections = scan_for_pinning(tmp_path)
        trust_det = [
            d for d in detections if d.pinning_type == PinningType.CUSTOM_TRUST_MANAGER
        ]
        assert trust_det[0].confidence >= 0.8


class TestTrustKit:
    def test_detects_trustkit(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/AppInit.java", TRUSTKIT_CODE)
        detections = scan_for_pinning(tmp_path)
        trustkit_det = [d for d in detections if d.pinning_type == PinningType.TRUSTKIT]
        assert len(trustkit_det) >= 1
        assert trustkit_det[0].bypass_difficulty == "easy"


class TestFlutterSSL:
    def test_detects_flutter_ssl(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "lib/http_client.dart", FLUTTER_SSL_CODE)
        detections = scan_for_pinning(tmp_path)
        flutter_det = [
            d for d in detections if d.pinning_type == PinningType.FLUTTER_SSL
        ]
        assert len(flutter_det) >= 1
        assert flutter_det[0].bypass_difficulty == "hard"


class TestReactNativeSSL:
    def test_detects_react_native_ssl(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "src/api/client.json", REACT_NATIVE_SSL_CODE)
        detections = scan_for_pinning(tmp_path)
        rn_det = [
            d for d in detections if d.pinning_type == PinningType.REACT_NATIVE_SSL
        ]
        assert len(rn_det) >= 1
        assert rn_det[0].bypass_difficulty == "medium"


class TestGenericPublicKeyPinning:
    def test_detects_public_key_pinning(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "com/example/CertVerifier.java", PUBLIC_KEY_PINNING_CODE
        )
        detections = scan_for_pinning(tmp_path)
        pk_det = [
            d for d in detections if d.pinning_type == PinningType.PUBLIC_KEY_PINNING
        ]
        assert len(pk_det) >= 1
        assert pk_det[0].bypass_difficulty in ("medium", "hard")


class TestCertificateTransparency:
    def test_detects_ct(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/HttpSetup.java", CT_CODE)
        detections = scan_for_pinning(tmp_path)
        ct_det = [
            d
            for d in detections
            if d.pinning_type == PinningType.CERTIFICATE_TRANSPARENCY
        ]
        assert len(ct_det) >= 1
        assert ct_det[0].bypass_difficulty == "easy"


class TestScanMultipleTypes:
    def test_multiple_types_in_source_tree(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        _write_source(
            tmp_path,
            "com/example/CustomTrustManager.java",
            CUSTOM_TRUST_MANAGER,
        )
        _write_source(tmp_path, "com/example/AppInit.java", TRUSTKIT_CODE)

        detections = scan_for_pinning(tmp_path)
        types_found = {d.pinning_type for d in detections}

        assert PinningType.OKHTTP_CERT_PINNER in types_found
        assert PinningType.NETWORK_SECURITY_CONFIG in types_found
        assert PinningType.CUSTOM_TRUST_MANAGER in types_found
        assert PinningType.TRUSTKIT in types_found


class TestEmptySource:
    def test_no_pinning_found(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path,
            "com/example/Main.java",
            "public class Main { public static void main(String[] args) {} }",
        )
        detections = scan_for_pinning(tmp_path)
        assert detections == []


class TestConfidenceLevels:
    def test_okhttp_high_confidence(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Net.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        assert detections[0].confidence >= 0.9

    def test_nsc_high_confidence(self, tmp_path: Path) -> None:
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        detections = scan_for_pinning(tmp_path)
        assert detections[0].confidence >= 0.9


# ---------------------------------------------------------------------------
# Generator tests
# ---------------------------------------------------------------------------


class TestGenerateBypass:
    def test_produces_valid_javascript(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        script = generate_bypass(detections)

        assert "Java.perform" in script
        assert "function()" in script
        assert script.strip().endswith("});")

    def test_includes_all_detected_types(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        _write_source(
            tmp_path, "res/xml/network_security_config.xml", NETWORK_SECURITY_XML
        )
        _write_source(
            tmp_path,
            "com/example/CustomTrustManager.java",
            CUSTOM_TRUST_MANAGER,
        )

        detections = scan_for_pinning(tmp_path)
        script = generate_bypass(detections)

        assert "CertificatePinner" in script
        assert "NetworkSecurity" in script
        assert "TrustManager" in script

    def test_wraps_in_try_catch(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        script = generate_bypass(detections)

        assert "try {" in script
        assert "} catch (e)" in script

    def test_has_logging(self, tmp_path: Path) -> None:
        _write_source(tmp_path, "com/example/Network.java", OKHTTP_PINNER)
        detections = scan_for_pinning(tmp_path)
        script = generate_bypass(detections)

        assert "console.log" in script
        assert "[certpatch]" in script

    def test_empty_detections(self) -> None:
        script = generate_bypass([])
        assert "Java.perform" in script
        assert "nothing to bypass" in script.lower()


class TestGenerateBypassForType:
    @pytest.mark.parametrize(
        "pinning_type,expected_snippet",
        [
            (PinningType.OKHTTP_CERT_PINNER, "CertificatePinner"),
            (PinningType.NETWORK_SECURITY_CONFIG, "NetworkSecurity"),
            (PinningType.CUSTOM_TRUST_MANAGER, "PermissiveTrustManager"),
            (PinningType.TRUSTKIT, "PinningTrustManager"),
            (PinningType.FLUTTER_SSL, "libflutter.so"),
            (PinningType.REACT_NATIVE_SSL, "React Native"),
            (PinningType.XAMARIN_SSL, "Xamarin"),
            (PinningType.PUBLIC_KEY_PINNING, "MessageDigest"),
            (PinningType.CERTIFICATE_TRANSPARENCY, "CertificateTransparency"),
            (PinningType.UNKNOWN, "Unknown pinning"),
        ],
    )
    def test_bypass_for_each_type(
        self, pinning_type: PinningType, expected_snippet: str
    ) -> None:
        det = PinningDetection(
            pinning_type=pinning_type,
            file_path="com/example/Test.java",
            line_number=42,
        )
        snippet = generate_bypass_for_type(det)
        assert expected_snippet in snippet

    def test_each_bypass_has_try_catch(self) -> None:
        for pt in PinningType:
            if pt == PinningType.UNKNOWN:
                continue
            det = PinningDetection(
                pinning_type=pt,
                file_path="com/example/Test.java",
                line_number=1,
            )
            snippet = generate_bypass_for_type(det)
            assert "try {" in snippet, f"{pt.value} bypass missing try/catch"


class TestGenerateNetworkSecurityConfig:
    def test_produces_valid_xml(self) -> None:
        xml = generate_network_security_config()
        assert '<?xml version="1.0"' in xml
        assert "<network-security-config>" in xml
        assert 'cleartextTrafficPermitted="true"' in xml
        assert '<certificates src="system" />' in xml
        assert '<certificates src="user" />' in xml

    def test_contains_trust_anchors(self) -> None:
        xml = generate_network_security_config()
        assert "<trust-anchors>" in xml
        assert "</trust-anchors>" in xml
