# I Reverse Engineered 25 Mobile APIs. Here Are the Tools I Wish Existed (So I Built Them)

Over the past few months, I reverse engineered 25 real estate platform APIs across Europe — Funda, Idealista, Rightmove, SeLoger, and many more. The goal was to build a unified search backend that could query all of them through a single interface.

The individual tools were great. mitmproxy captured traffic. jadx decompiled APKs. Frida hooked into apps. But the *gaps between tools* — that's where I lost most of my time.

So I built **rekit**: a reverse engineering toolkit for mobile APIs with six focused tools that fill those gaps.

GitHub: [https://github.com/b-erdem/rekit](https://github.com/b-erdem/rekit)

## The Pain Points

### 1. "Why am I getting 403s?"

Every other API returned 403 Forbidden with my Python requests. Was it a TLS fingerprint check? A WAF? Rate limiting? A missing header? I had to manually test each possibility.

**Now:** `rekit botwall detect https://api.example.com` tells you exactly which bot protection system is running and how hard it is to bypass. `rekit ja3probe probe https://api.example.com` tests 26 different TLS fingerprints and shows you which ones the server accepts.

### 2. "I have a HAR file. Now what?"

After capturing traffic with mitmproxy, I'd spend hours manually translating HTTP exchanges into Python code. Copy the URL, copy the headers, figure out which headers are static vs. dynamic, parse the response schema, write dataclasses...

**Now:** `rekit hargen generate traffic.har -o ./client/` does all of that automatically. It groups endpoints, detects path parameters, classifies headers, infers response schemas, and generates a typed Python client with dataclasses.

### 3. "Did I miss any endpoints?"

After decompiling an APK with jadx, I'd grep through 40,000+ files looking for API URLs, auth patterns, and interceptors. Easy to miss things.

**Now:** `rekit apkmap scan ./decompiled/` finds Retrofit annotations, OkHttp interceptors, Flutter/Dart HTTP patterns, hardcoded URLs, auth tokens, and GraphQL queries. Outputs a clean report.

### 4. "These 5 APIs return the same data in different shapes"

When normalizing responses from multiple platforms, I'd manually compare JSON structures field by field. Which fields overlap? Which are unique? What are the type differences?

**Now:** `rekit schemadiff compare api1.json api2.json api3.json` builds a comparison matrix and can generate a unified Python dataclass with `from_source()` classmethods.

### 5. "Proxy setup is painful"

Setting up mitmproxy with cert pinning bypass for every app was a recurring headache. Some apps use OkHttp, some use Dio, some use raw URLConnection.

**Now:** `rekit apktap capture com.example.app` hooks directly into the HTTP layer via Frida — above TLS, so no proxy or cert pinning bypass needed. It outputs standard HAR files that feed directly into hargen.

## The Six Tools

| Tool | What it does |
|------|-------------|
| **hargen** | Generate typed Python API client from HAR files |
| **apktap** | Capture Android HTTP traffic via Frida (no proxy needed) |
| **apkmap** | Scan decompiled APK for API surface |
| **ja3probe** | Test TLS fingerprint acceptance |
| **botwall** | Detect bot protection systems |
| **schemadiff** | Compare and unify API schemas |

## The Pipeline

These tools connect into a pipeline:

```
apktap --> hargen --> working Python client
  |          |
  v          v
apkmap    ja3probe + botwall  (debugging)
  |
  v
schemadiff  (normalizing multiple APIs)
```

1. **Capture** traffic with apktap (or mitmproxy)
2. **Generate** a typed client with hargen
3. **Discover** missed endpoints with apkmap
4. **Debug** 403s with ja3probe and botwall
5. **Normalize** across APIs with schemadiff

## Quick Start

```bash
pip install rekit

# Detect bot protection
rekit botwall detect https://www.example.com

# Test TLS fingerprints
rekit ja3probe probe https://api.example.com

# Generate client from captured traffic
rekit hargen generate traffic.har -o ./client/

# Scan decompiled APK
rekit apkmap scan ./decompiled/
```

## What's Next

rekit is MIT-licensed and open for contributions. Some things I'd love help with:

- iOS equivalent of apktap (Frida hooks for NSURLSession/Alamofire)
- More bot protection detectors (Kasada, Shape Security)
- HAR import from Charles Proxy and Proxyman formats
- OpenAPI spec generation from hargen

If you reverse engineer mobile APIs, I'd love to hear what tools *you* wish existed.

**GitHub:** [https://github.com/b-erdem/rekit](https://github.com/b-erdem/rekit)

---

*Tags: python, reverse-engineering, api, mobile, security, open-source*
