"""
rekit — Reverse Engineering Toolkit for Mobile APIs
=====================================================

14 tools for the mobile API reverse engineering pipeline:

Core Pipeline:
- **hargen**      — Generate typed Python API clients from captured HTTP traffic
- **apktap**      — Hook into Android app HTTP layer, capture traffic without proxy
- **apkmap**      — Scan decompiled APKs, map all API endpoints and models
- **schemadiff**  — Compare API response schemas, generate unified models

Security & Fingerprinting:
- **ja3probe**    — Test which TLS fingerprints a target accepts
- **botwall**     — Identify bot protection systems and rate difficulty
- **headerprint** — Analyze HTTP/2 and header-order fingerprints
- **certpatch**   — Scan for cert pinning, generate Frida bypass scripts

Traffic Analysis:
- **tokendump**   — Extract and decode auth tokens (JWT, OAuth, session)
- **authmap**     — Map authentication flows, generate Python auth modules
- **mockapi**     — Replay captured traffic as a local mock server
- **ratelim**     — Probe rate limits with binary search

App Analysis:
- **jsbundle**    — Scan React Native / JS bundles for endpoints and secrets
- **protorev**    — Decode protobuf/gRPC, infer .proto schemas
"""

__version__ = "0.2.0"
