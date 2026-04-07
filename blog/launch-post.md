# I Reverse Engineered 25 Mobile APIs. Here Are the Tools I Wish Existed (So I Built Them)

Over the past few months, I reverse engineered 25 real estate platform APIs across Europe — Funda, Idealista, Rightmove, SeLoger, and many more. The goal was to build a unified search backend that could query all of them through a single interface.

The individual tools were great. mitmproxy captured traffic. jadx decompiled APKs. Frida hooked into apps. But the *gaps between tools* — that's where I lost most of my time.

So I built **rekit**: a reverse engineering toolkit for mobile APIs with 14 focused tools that fill those gaps.

GitHub: [https://github.com/b-erdem/rekit](https://github.com/b-erdem/rekit)

## The Pain Points

### 1. "Why am I getting 403s?"

Every other API returned 403 Forbidden with my Python requests. Was it a TLS fingerprint check? A WAF? Rate limiting? A missing header? I had to manually test each possibility.

**Now:** `rekit botwall detect` identifies the bot protection system. `rekit ja3probe probe` tests 26 TLS fingerprints. `rekit headerprint analyze` checks if your HTTP/2 fingerprint gives you away.

### 2. "I have a HAR file. Now what?"

After capturing traffic with mitmproxy, I'd spend hours manually translating HTTP exchanges into Python code.

**Now:** `rekit hargen generate traffic.har` generates a typed Python client with dataclasses. `rekit tokendump extract traffic.har` decodes every JWT and OAuth token in the capture. `rekit authmap detect traffic.har` maps the full authentication flow and generates a reusable auth module.

### 3. "I can't keep hitting the live API during development"

Every request risks getting your IP banned. But you need to develop and test your client code against something.

**Now:** `rekit mockapi serve traffic.har` spins up a local server that replays captured responses — with latency simulation, error injection, and stateful mode.

### 4. "Did I miss any endpoints?"

After decompiling an APK with jadx, I'd grep through 40,000+ files looking for API URLs.

**Now:** `rekit apkmap scan ./decompiled/` finds Retrofit annotations, OkHttp interceptors, and Flutter patterns. `rekit jsbundle scan app.apk` analyzes React Native bundles for endpoints, hardcoded secrets, and GraphQL operations.

### 5. "The API uses protobuf, not JSON"

Increasingly, mobile APIs use Protocol Buffers instead of JSON. Captured traffic is binary gibberish.

**Now:** `rekit protorev extract traffic.har` decodes protobuf messages without a schema. `rekit protorev infer traffic.har` reconstructs the .proto definitions.

### 6. "Cert pinning keeps blocking my proxy"

Setting up mitmproxy with cert pinning bypass for every app was a recurring headache.

**Now:** `rekit apktap capture com.example.app` hooks above TLS (no proxy needed). For when you do need a proxy, `rekit certpatch bypass ./decompiled/` generates a targeted Frida script that bypasses exactly the pinning implementations found in the app.

### 7. "How fast can I hit this API?"

Everyone discovers rate limits by accident.

**Now:** `rekit ratelim probe` systematically finds the threshold with binary search, parses rate limit headers, and measures cooldown periods.

### 8. "These 5 APIs return the same data in different shapes"

**Now:** `rekit schemadiff compare api1.json api2.json api3.json` builds a comparison matrix and generates a unified Python dataclass.

## The 14 Tools

### Core Pipeline
| Tool | What it does |
|------|-------------|
| **hargen** | Generate typed Python API client from HAR files |
| **apktap** | Capture Android HTTP traffic via Frida (no proxy needed) |
| **apkmap** | Scan decompiled APK for API surface |
| **schemadiff** | Compare and unify API schemas |

### Security & Fingerprinting
| Tool | What it does |
|------|-------------|
| **ja3probe** | Test TLS fingerprint acceptance (26 profiles) |
| **botwall** | Detect bot protection systems |
| **headerprint** | HTTP/2 and header-order fingerprinting |
| **certpatch** | Generate cert pinning bypass scripts |

### Traffic Analysis
| Tool | What it does |
|------|-------------|
| **tokendump** | Extract and decode all auth tokens |
| **authmap** | Map auth flows, generate auth modules |
| **mockapi** | Replay traffic as a local mock server |
| **ratelim** | Probe rate limits with binary search |

### App Analysis
| Tool | What it does |
|------|-------------|
| **jsbundle** | Scan React Native / JS bundles |
| **protorev** | Decode protobuf/gRPC, infer schemas |

## Quick Start

```bash
pip install rekit

# Detect bot protection
rekit botwall detect https://www.example.com

# Test TLS fingerprints
rekit ja3probe probe https://api.example.com

# Generate client from captured traffic
rekit hargen generate traffic.har -o ./client/

# Run mock server
rekit mockapi serve traffic.har --port 8080

# Extract tokens
rekit tokendump extract traffic.har

# Map auth flows
rekit authmap detect traffic.har

# Scan decompiled APK
rekit apkmap scan ./decompiled/

# Scan React Native bundle
rekit jsbundle scan app.apk

# Decode protobuf traffic
rekit protorev extract traffic.har

# Probe rate limits
rekit ratelim probe https://api.example.com/v1/search

# Generate cert pinning bypass
rekit certpatch bypass ./decompiled/ -o bypass.js
```

## What's Next

rekit is MIT-licensed and open for contributions. Some things I'd love help with:

- iOS equivalent of apktap (Frida hooks for NSURLSession/Alamofire)
- More bot protection detectors (Kasada, Shape Security)
- HAR import from Charles Proxy and Proxyman formats
- OpenAPI spec generation from hargen
- Hermes bytecode decompilation support in jsbundle

If you reverse engineer mobile APIs, I'd love to hear what tools *you* wish existed.

**GitHub:** [https://github.com/b-erdem/rekit](https://github.com/b-erdem/rekit)

---

*Tags: python, reverse-engineering, api, mobile, security, open-source, protobuf, frida, tls-fingerprinting*
