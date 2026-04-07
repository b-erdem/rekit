# Changelog

## 0.2.0 (2026-04-07)

Added 8 new tools, bringing the total to 14:

- **mockapi** — Generate and run a mock HTTP server from captured HAR traffic (sequential/random replay, error injection, latency simulation, stateful mode, hot reload)
- **tokendump** — Extract and decode authentication tokens from HAR traffic (JWT decoding, OAuth token chains, token lifecycle analysis)
- **authmap** — Map authentication flows from captured traffic (OAuth2, PKCE, custom login, API key, session cookie, HMAC detection) and generate reusable Python auth modules
- **protorev** — Decode raw protobuf/gRPC without a schema, extract from HAR traffic, infer .proto definitions, generate Python stubs
- **jsbundle** — Analyze React Native / Hermes / JS bundles from APK/IPA for API endpoints, hardcoded secrets, GraphQL operations, and environment configs
- **ratelim** — Systematically probe API rate limits with controlled bursts and binary search, parse rate limit headers, measure cooldowns
- **certpatch** — Scan decompiled APKs for certificate pinning (OkHttp, network_security_config, custom TrustManager, TrustKit, Flutter, React Native) and generate targeted Frida bypass scripts
- **headerprint** — Analyze HTTP/2 fingerprints and header-order fingerprints, compare against known browser profiles, detect non-browser anomalies

## 0.1.0 (2026-04-07)

Initial release with 6 tools:

- **hargen** — Generate typed Python API clients from HAR / mitmproxy traffic captures
- **apktap** — Capture Android app HTTP traffic via Frida hooks (OkHttp, Dio, URLConnection, WebView)
- **apkmap** — Scan decompiled APK source for API endpoints, models, interceptors, and auth patterns
- **ja3probe** — Test 26 TLS fingerprint profiles against a target URL
- **botwall** — Detect bot protection systems (Cloudflare, DataDome, Akamai, PerimeterX, Incapsula)
- **schemadiff** — Compare API response schemas and generate unified Python dataclasses
