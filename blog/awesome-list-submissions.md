# Awesome List Submissions

Submit PRs to these repositories to add rekit:

---

## 1. awesome-python (vinta/awesome-python)
**Section:** Network / HTTP / Web Crawling
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit for mobile APIs with 14 tools: traffic capture via Frida, HAR-to-client generation, APK/JS bundle scanning, TLS/HTTP2 fingerprint testing, bot protection detection, protobuf decoding, token analysis, auth flow mapping, mock servers, rate limit probing, cert pinning bypass, and schema comparison.
```

---

## 2. awesome-reverse-engineering (alphaSeclab/awesome-reverse-engineering)
**Section:** Android / Tools
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Python toolkit with 14 tools for mobile API reverse engineering. Includes Frida-based traffic capture, APK endpoint scanning, React Native bundle analysis, protobuf/gRPC decoding, TLS/HTTP2 fingerprint testing, bot protection detection, token extraction, auth flow mapping, cert pinning bypass generation, and API client generation from HAR files.
```

---

## 3. Awesome-Android-Reverse-Engineering (user1342/Awesome-Android-Reverse-Engineering)
**Section:** Tools
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit with 14 tools for mobile APIs. Captures Android HTTP traffic via Frida hooks (OkHttp, Dio, URLConnection, WebView), scans decompiled APKs and React Native bundles for API endpoints, generates cert pinning bypass scripts, decodes protobuf/gRPC, and generates typed Python clients from captured traffic.
```

---

## 4. awesome-frida (dweinstein/awesome-frida)
**Section:** Tools / Libraries
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Mobile API reverse engineering toolkit with 14 tools. Frida-based HTTP traffic capture hooking into OkHttp3, Dio/BoringSSL, URLConnection, and WebView (above TLS, no proxy needed). Also generates targeted Frida cert pinning bypass scripts from APK analysis.
```

---

## 5. awesome-web-scraping (lorien/awesome-web-scraping)
**Section:** Python / Other
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit for mobile APIs with 14 tools. Tests TLS and HTTP/2 fingerprints, detects bot protection (Cloudflare, DataDome, Akamai, PerimeterX, Incapsula), probes rate limits, generates Python API clients from captured traffic, and decodes protobuf/gRPC.
```

---

## 6. Awesome-Reversing (ReversingID/Awesome-Reversing)
**Section:** Mobile / Android
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Python toolkit with 14 tools for mobile API reverse engineering: Frida traffic capture, APK/JS bundle scanning, protobuf decoding, TLS/HTTP2 fingerprinting, bot detection, token analysis, auth flow mapping, cert pinning bypass, rate limit probing, mock servers, and client code generation.
```

---

## Reddit Posts

### r/reverseengineering
**Title:** rekit — Open-source toolkit for mobile API reverse engineering (14 tools)
**Body:** Link to blog post

### r/Python
**Title:** I built rekit — 14 Python tools for reverse engineering mobile APIs
**Body:** Link to blog post

### r/netsec
**Title:** rekit — Detect bot protection, test TLS/HTTP2 fingerprints, decode protobuf, and more (14 tools)
**Body:** Link to blog post

### r/androiddev
**Title:** rekit — Frida-based HTTP capture + APK/JS bundle analysis + cert pinning bypass (14 tools)
**Body:** Link to blog post

---

## Hacker News

**Title:** Show HN: Rekit – 14-tool reverse engineering toolkit for mobile APIs
**URL:** https://github.com/b-erdem/rekit

---

## Twitter/X Thread

Post 1:
I spent months reverse engineering 25 mobile APIs across Europe.

The hardest part wasn't the code — it was the gaps between tools.

So I built rekit: 14 focused tools for the mobile API RE pipeline. Open source, MIT licensed.

github.com/b-erdem/rekit

Post 2:
Getting blocked? Three tools to figure out why:

botwall — detect what bot protection a site uses
ja3probe — test 26 TLS fingerprints
headerprint — check if your HTTP/2 fingerprint gives you away

Post 3:
Captured traffic? Four tools to analyze it:

hargen — generate a typed Python API client
tokendump — decode every JWT and OAuth token
authmap — map the full auth flow and generate auth code
mockapi — replay traffic as a local mock server

Post 4:
Analyzing the app? Three tools:

apkmap — scan decompiled APK for API endpoints
jsbundle — scan React Native/JS bundles for secrets and endpoints
certpatch — generate targeted Frida cert pinning bypass scripts

Post 5:
Working with binary protocols?

protorev — decode protobuf/gRPC without a schema, infer .proto definitions, generate Python stubs

Post 6:
Scaling up?

ratelim — find exact rate limit thresholds with binary search
schemadiff — compare and unify schemas across multiple APIs

Post 7:
14 tools, 646 tests, Python 3.9-3.13, MIT licensed.

Every tool born from real pain points reverse engineering 25 real APIs.

github.com/b-erdem/rekit
