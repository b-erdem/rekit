"""
Comprehensive tests for the jsbundle tool.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from rekit.apkmap.scanners.base import EndpointInfo, ScanResult
from rekit.jsbundle.analyzer import (
    JSAnalysis,
    analyze_bundle,
    mask_secret,
    merge_with_apkmap,
)
from rekit.jsbundle.decompiler import is_hermes_bytecode, try_beautify
from rekit.jsbundle.extractor import extract_bundle, find_bundles

# ---------------------------------------------------------------------------
# Sample JS content
# ---------------------------------------------------------------------------

SAMPLE_BUNDLE = """
import React from 'react';
const API_BASE = "https://api.myapp.com/v2";
const API_KEY = "sk_fake_abc123def456ghi789";

export async function fetchUsers() {
  const response = await fetch(`${API_BASE}/users`, {
    headers: {
      'Authorization': `Bearer ${getToken()}`,
      'X-API-Key': API_KEY,
    },
  });
  return response.json();
}

const client = axios.create({
  baseURL: 'https://api.myapp.com/v2',
  timeout: 5000,
});

const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) {
      name
      email
    }
  }
`;

const CREATE_POST = gql`
  mutation CreatePost($title: String!, $body: String!) {
    createPost(title: $title, body: $body) {
      id
      title
    }
  }
`;

const config = {
  apiUrl: "https://api.staging.myapp.com",
  environment: "staging",
};

const firebaseConfig = {
  apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0KlMnOpQrStUv",
  authDomain: "myapp-12345.firebaseapp.com",
  projectId: "myapp-12345",
};

process.env.REACT_APP_API_URL || "https://api.prod.myapp.com";
process.env.REACT_APP_ENV || "production";

axios.get('https://api.myapp.com/v2/posts');
axios.post('https://api.myapp.com/v2/comments');

const ws = new WebSocket("wss://ws.myapp.com/realtime");
"""

MINIFIED_BUNDLE = (
    'var n="https://api.example-app.com/v1";'
    'fetch(n+"/users",{method:"POST",headers:{"X-Api-Key":"AKIA1234567890ABCDEF"}});'
    'fetch("https://api.example-app.com/v1/orders",{method:"GET"});'
    'var s="sk_fake_abcdefghijklmnopqrstuvwx";'
)

BUNDLE_WITH_XHR = """
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://api.myapp.com/v1/upload");
xhr.setRequestHeader("Authorization", "Bearer token123");
xhr.send(data);
"""

BUNDLE_WITH_JWT = """
const DEFAULT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
"""

BUNDLE_WITH_NAVIGATION = """
Screen: "UserProfile",
component: function() {
  fetch("https://api.myapp.com/v1/profile", {method: "GET"});
  fetch("https://api.myapp.com/v1/settings", {method: "GET"});
}

Screen: "Dashboard",
component: function() {
  fetch("https://api.myapp.com/v1/stats", {method: "GET"});
}
"""

BUNDLE_WITH_AWS = """
const AWS_KEY = "AKIA1234567890ABCDEF";
const SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
"""

BUNDLE_WITH_ENV = """
const apiEndpoint = process.env.REACT_APP_API_URL || "https://api.default.com";
const debug = process.env.NODE_ENV;
const expoStuff = Constants.expoConfig;
const cfg = {
  apiBaseUrl: "https://api.config.myapp.com/v3",
  BASE_URL: "https://base.myapp.com",
};
"""


# ---------------------------------------------------------------------------
# Extractor tests
# ---------------------------------------------------------------------------


class TestFindBundlesInDirectory:
    def test_finds_react_native_bundle(self, tmp_path: Path):
        bundle_dir = tmp_path / "assets"
        bundle_dir.mkdir()
        bundle = bundle_dir / "index.android.bundle"
        bundle.write_text("var x = 1;")

        results = find_bundles(tmp_path)
        assert len(results) >= 1
        found = [b for b in results if b.path.name == "index.android.bundle"]
        assert len(found) == 1
        assert found[0].bundle_type == "react_native"
        assert found[0].is_bytecode is False

    def test_finds_ios_bundle(self, tmp_path: Path):
        bundle_dir = tmp_path / "assets"
        bundle_dir.mkdir()
        bundle = bundle_dir / "main.jsbundle"
        bundle.write_text("var y = 2;")

        results = find_bundles(tmp_path)
        found = [b for b in results if b.path.name == "main.jsbundle"]
        assert len(found) == 1
        assert found[0].bundle_type == "react_native"

    def test_finds_hermes_bytecode(self, tmp_path: Path):
        bundle_dir = tmp_path / "assets"
        bundle_dir.mkdir()
        bundle = bundle_dir / "index.android.bundle.hbc"
        # Write Hermes magic bytes
        bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 100)

        results = find_bundles(tmp_path)
        found = [b for b in results if b.path.name == "index.android.bundle.hbc"]
        assert len(found) == 1
        assert found[0].bundle_type == "hermes"
        assert found[0].is_bytecode is True

    def test_finds_expo_bundle(self, tmp_path: Path):
        bundle_dir = tmp_path / "assets"
        bundle_dir.mkdir()
        bundle = bundle_dir / "app.bundle"
        bundle.write_text("expo-constants something something")

        results = find_bundles(tmp_path)
        found = [b for b in results if b.path.name == "app.bundle"]
        assert len(found) == 1
        assert found[0].bundle_type == "expo"

    def test_no_bundles_in_empty_dir(self, tmp_path: Path):
        results = find_bundles(tmp_path)
        assert results == []

    def test_finds_custom_bundle_extensions(self, tmp_path: Path):
        bundle_dir = tmp_path / "assets"
        bundle_dir.mkdir()
        bundle = bundle_dir / "custom.jsbundle"
        bundle.write_text("// custom bundle")

        results = find_bundles(tmp_path)
        assert len(results) >= 1


class TestFindBundlesInZip:
    def test_finds_bundle_in_apk(self, tmp_path: Path):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("assets/index.android.bundle", "var z = 3;")

        results = find_bundles(apk_path)
        assert len(results) == 1
        assert results[0].bundle_type == "react_native"
        assert results[0].is_bytecode is False

    def test_finds_hermes_bundle_in_apk(self, tmp_path: Path):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr(
                "assets/index.android.bundle.hbc",
                b"\xc6\x1f\xbc\x03" + b"\x00" * 100,
            )

        results = find_bundles(apk_path)
        assert len(results) == 1
        assert results[0].bundle_type == "hermes"
        assert results[0].is_bytecode is True

    def test_finds_bundle_in_ipa(self, tmp_path: Path):
        ipa_path = tmp_path / "test.ipa"
        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr("Payload/App.app/assets/main.jsbundle", "var w = 4;")

        results = find_bundles(ipa_path)
        assert len(results) >= 1

    def test_extract_bundle_from_apk(self, tmp_path: Path):
        apk_path = tmp_path / "test.apk"
        content = "var extracted = true;"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("assets/index.android.bundle", content)

        output_dir = tmp_path / "output"
        extracted = extract_bundle(apk_path, output_dir)
        assert len(extracted) == 1
        assert extracted[0].read_text() == content


# ---------------------------------------------------------------------------
# Hermes bytecode tests
# ---------------------------------------------------------------------------


class TestHermesBytecode:
    def test_hermes_magic_bytes(self):
        data = b"\xc6\x1f\xbc\x03" + b"\x00" * 100
        assert is_hermes_bytecode(data) is True

    def test_hermes_ascii_prefix(self):
        data = b"HBC" + b"\x00" * 100
        assert is_hermes_bytecode(data) is True

    def test_non_hermes_data(self):
        data = b"var x = 1; function foo() {}"
        assert is_hermes_bytecode(data) is False

    def test_empty_data(self):
        assert is_hermes_bytecode(b"") is False

    def test_short_data(self):
        assert is_hermes_bytecode(b"\xc6\x1f") is False


# ---------------------------------------------------------------------------
# Analyzer tests
# ---------------------------------------------------------------------------


class TestAnalyzeBundle:
    def test_url_extraction(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        urls = [ep.path for ep in result.endpoints]
        assert any("api.myapp.com/v2/posts" in u for u in urls)
        assert any("api.myapp.com/v2/comments" in u for u in urls)

    def test_api_key_detection(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "sk_fake_abc123def456ghi789" in secret_values

    def test_graphql_query_extraction(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        gql_names = [op["name"] for op in result.graphql_operations]
        assert "GetUser" in gql_names

    def test_graphql_mutation_extraction(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        mutations = [op for op in result.graphql_operations if op["type"] == "mutation"]
        assert any(op["name"] == "CreatePost" for op in mutations)

    def test_axios_create_baseurl(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        assert "https://api.myapp.com/v2" in result.api_base_urls

    def test_websocket_detection(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        ws_endpoints = [ep for ep in result.endpoints if ep.method == "WS"]
        assert any("ws.myapp.com" in ep.path for ep in ws_endpoints)

    def test_firebase_config_detection(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert any(v.startswith("AIza") for v in secret_values)

    def test_env_config_detection(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        env_keys = [cfg["key"] for cfg in result.env_configs]
        assert "REACT_APP_API_URL" in env_keys
        assert "REACT_APP_ENV" in env_keys

    def test_config_object_detection(self):
        result = analyze_bundle(SAMPLE_BUNDLE)
        config_keys = [cfg["key"] for cfg in result.env_configs]
        assert "apiUrl" in config_keys


class TestMinifiedBundle:
    def test_url_extraction_minified(self):
        result = analyze_bundle(MINIFIED_BUNDLE)
        urls = [ep.path for ep in result.endpoints]
        assert any("api.example-app.com/v1/orders" in u for u in urls)

    def test_fetch_call_minified(self):
        result = analyze_bundle(MINIFIED_BUNDLE)
        fetch_urls = [f["url"] for f in result.fetch_calls]
        assert "https://api.example-app.com/v1/orders" in fetch_urls

    def test_aws_key_minified(self):
        result = analyze_bundle(MINIFIED_BUNDLE)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "AKIA1234567890ABCDEF" in secret_values

    def test_stripe_key_minified(self):
        result = analyze_bundle(MINIFIED_BUNDLE)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "sk_fake_abcdefghijklmnopqrstuvwx" in secret_values


class TestFetchAxiosExtraction:
    def test_fetch_with_method(self):
        js = """fetch("https://api.myapp.com/v1/data", {method: "POST", headers: {"Content-Type": "application/json"}});"""
        result = analyze_bundle(js)
        assert len(result.fetch_calls) >= 1
        call = result.fetch_calls[0]
        assert call["method"] == "POST"
        assert call["url"] == "https://api.myapp.com/v1/data"

    def test_fetch_get_default(self):
        js = """fetch("https://api.myapp.com/v1/items");"""
        result = analyze_bundle(js)
        assert len(result.fetch_calls) >= 1
        assert result.fetch_calls[0]["method"] == "GET"

    def test_axios_get(self):
        js = """axios.get('https://api.myapp.com/v1/users');"""
        result = analyze_bundle(js)
        urls = [ep.path for ep in result.endpoints]
        assert any("api.myapp.com/v1/users" in u for u in urls)

    def test_axios_post(self):
        js = """axios.post('https://api.myapp.com/v1/create');"""
        result = analyze_bundle(js)
        endpoints = [ep for ep in result.endpoints if ep.method == "POST"]
        assert any("api.myapp.com/v1/create" in ep.path for ep in endpoints)

    def test_axios_delete(self):
        js = """axios.delete('https://api.myapp.com/v1/item/123');"""
        result = analyze_bundle(js)
        endpoints = [ep for ep in result.endpoints if ep.method == "DELETE"]
        assert any("api.myapp.com/v1/item/123" in ep.path for ep in endpoints)


class TestXHR:
    def test_xhr_open(self):
        result = analyze_bundle(BUNDLE_WITH_XHR)
        endpoints = [ep for ep in result.endpoints if ep.method == "POST"]
        assert any("api.myapp.com/v1/upload" in ep.path for ep in endpoints)


class TestSecretDetection:
    def test_aws_access_key(self):
        result = analyze_bundle(BUNDLE_WITH_AWS)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "AKIA1234567890ABCDEF" in secret_values

    def test_generic_secret_key(self):
        result = analyze_bundle(BUNDLE_WITH_AWS)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in secret_values

    def test_jwt_token(self):
        result = analyze_bundle(BUNDLE_WITH_JWT)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert any(v.startswith("eyJ") for v in secret_values)

    def test_stripe_live_key(self):
        js = """const STRIPE_KEY = "sk_fake_1234567890abcdefghijklmn";"""
        result = analyze_bundle(js)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert "sk_fake_1234567890abcdefghijklmn" in secret_values

    def test_google_maps_key(self):
        js = """const MAPS_KEY = "AIzaSyB1C2D3E4F5G6H7I8J9K0LmNoPqRsTuVwX";"""
        result = analyze_bundle(js)
        secret_values = [s["value"] for s in result.hardcoded_secrets]
        assert any(v.startswith("AIza") for v in secret_values)


class TestSecretMasking:
    def test_mask_long_secret(self):
        # mask_secret shows first 4 + (len-8) stars + last 4
        value = "sk_fake_abc123def456"
        masked = mask_secret(value)
        assert masked.startswith("sk_f")
        assert masked.endswith("f456")
        assert "*" in masked

    def test_mask_short_secret(self):
        result = mask_secret("abc123")
        assert result.startswith("ab")
        assert "*" in result

    def test_mask_medium_secret(self):
        result = mask_secret("0123456789")
        assert result.startswith("01")


class TestGraphQL:
    def test_gql_template_literal(self):
        js = """
        const Q = gql`
          query FetchItems($limit: Int!) {
            items(limit: $limit) {
              id
              name
            }
          }
        `;
        """
        result = analyze_bundle(js)
        assert len(result.graphql_operations) >= 1
        assert result.graphql_operations[0]["name"] == "FetchItems"
        assert result.graphql_operations[0]["type"] == "query"

    def test_mutation_detection(self):
        js = """
        const M = gql`
          mutation DeleteItem($id: ID!) {
            deleteItem(id: $id) {
              success
            }
          }
        `;
        """
        result = analyze_bundle(js)
        assert len(result.graphql_operations) >= 1
        assert result.graphql_operations[0]["type"] == "mutation"

    def test_subscription_detection(self):
        js = """
        const S = gql`
          subscription OnMessage($channel: String!) {
            onMessage(channel: $channel) {
              text
            }
          }
        `;
        """
        result = analyze_bundle(js)
        assert len(result.graphql_operations) >= 1
        assert result.graphql_operations[0]["type"] == "subscription"


class TestEnvConfig:
    def test_process_env_vars(self):
        result = analyze_bundle(BUNDLE_WITH_ENV)
        env_keys = [cfg["key"] for cfg in result.env_configs]
        assert "REACT_APP_API_URL" in env_keys
        assert "NODE_ENV" in env_keys

    def test_process_env_default_value(self):
        result = analyze_bundle(BUNDLE_WITH_ENV)
        api_cfg = [c for c in result.env_configs if c["key"] == "REACT_APP_API_URL"]
        assert len(api_cfg) >= 1
        assert api_cfg[0]["value"] == "https://api.default.com"

    def test_config_object_baseurl(self):
        result = analyze_bundle(BUNDLE_WITH_ENV)
        config_keys = [cfg["key"] for cfg in result.env_configs]
        assert "apiBaseUrl" in config_keys
        assert "BASE_URL" in config_keys


class TestNavigationApiMap:
    def test_screen_endpoint_mapping(self):
        result = analyze_bundle(BUNDLE_WITH_NAVIGATION)
        assert len(result.navigation_api_map) >= 1
        screens = {entry["screen"] for entry in result.navigation_api_map}
        assert "UserProfile" in screens or "Dashboard" in screens


class TestMergeWithApkmap:
    def test_merge_deduplicates_endpoints(self):
        js_analysis = JSAnalysis(
            endpoints=[
                EndpointInfo(method="GET", path="https://api.myapp.com/v1/users"),
                EndpointInfo(method="POST", path="https://api.myapp.com/v1/create"),
            ],
            api_base_urls=["https://api.myapp.com/v1"],
        )

        scan_result = ScanResult(
            endpoints=[
                EndpointInfo(method="GET", path="https://api.myapp.com/v1/users"),
            ],
            base_urls=[{"url": "https://api.myapp.com/v1", "source": "apkmap"}],
        )

        merged = merge_with_apkmap(js_analysis, scan_result)
        # Should have 2 endpoints (GET /users deduplicated, POST /create added)
        assert len(merged.endpoints) == 2
        # Base URL should not be duplicated
        assert len(merged.base_urls) == 1


class TestTryBeautify:
    def test_basic_beautification(self):
        minified = "var x=1;var y=2;function foo(){return x+y;}"
        result = try_beautify(minified)
        lines = result.strip().split("\n")
        assert len(lines) > 1  # Should have multiple lines now

    def test_preserves_strings(self):
        code = 'var url="https://api.myapp.com/v1";'
        result = try_beautify(code)
        assert "https://api.myapp.com/v1" in result

    def test_handles_empty_content(self):
        assert try_beautify("") == ""

    def test_indentation(self):
        code = "function foo(){var x=1;}"
        result = try_beautify(code)
        # Should have indentation inside braces
        lines = [line for line in result.split("\n") if line.strip()]
        assert any(line.startswith("  ") for line in lines)


class TestEmptyAndNonJS:
    def test_empty_content(self):
        result = analyze_bundle("")
        assert result.endpoints == []
        assert result.hardcoded_secrets == []
        assert result.graphql_operations == []

    def test_non_js_content(self):
        result = analyze_bundle("This is just plain text with no JS patterns at all.")
        assert result.endpoints == []
        assert result.hardcoded_secrets == []

    def test_binary_like_content(self):
        # Should not crash on weird content
        result = analyze_bundle("\x00\x01\x02\x03 some text \xff\xfe")
        assert isinstance(result, JSAnalysis)


class TestBearerAuthPattern:
    def test_bearer_in_headers(self):
        js = """
        fetch("https://api.myapp.com/v1/data", {
          headers: {
            "Authorization": "Bearer my_token_here"
          }
        });
        """
        result = analyze_bundle(js)
        auth_types = [a.type for a in result.auth_patterns]
        assert "bearer" in auth_types


class TestSingleBundleFile:
    def test_find_single_bundle_file(self, tmp_path: Path):
        bundle = tmp_path / "app.bundle"
        bundle.write_text("var x = 1;")
        results = find_bundles(bundle)
        assert len(results) == 1

    def test_extract_single_file(self, tmp_path: Path):
        bundle = tmp_path / "app.bundle"
        bundle.write_text("var x = 1;")
        output = tmp_path / "out"
        extracted = extract_bundle(bundle, output)
        assert len(extracted) == 1
        assert extracted[0].read_text() == "var x = 1;"
