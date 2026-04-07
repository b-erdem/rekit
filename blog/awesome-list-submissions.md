# Awesome List Submissions

Submit PRs to these repositories to add rekit:

---

## 1. awesome-python (vinta/awesome-python)
**Section:** Network / HTTP / Web Crawling
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit for mobile APIs with 6 tools: traffic capture via Frida, HAR-to-client generation, APK endpoint scanning, TLS fingerprint testing, bot protection detection, and schema comparison.
```

---

## 2. awesome-reverse-engineering (alphaSeclab/awesome-reverse-engineering)
**Section:** Android / Tools
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Python toolkit for mobile API reverse engineering. Includes Frida-based traffic capture (OkHttp/Dio/URLConnection hooks), APK endpoint scanning, TLS fingerprint testing, bot protection detection, and automatic API client generation from HAR files.
```

---

## 3. Awesome-Android-Reverse-Engineering (user1342/Awesome-Android-Reverse-Engineering)
**Section:** Tools
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit for mobile APIs. Captures Android HTTP traffic via Frida hooks (OkHttp, Dio, URLConnection, WebView), scans decompiled APKs for API endpoints, and generates typed Python clients from captured traffic.
```

---

## 4. awesome-frida (dweinstein/awesome-frida)
**Section:** Tools / Libraries
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Mobile API reverse engineering toolkit with Frida-based HTTP traffic capture. Hooks into OkHttp3, Dio/BoringSSL, URLConnection, and WebView at the app layer (above TLS, no proxy needed). Outputs standard HAR files.
```

---

## 5. awesome-web-scraping (lorien/awesome-web-scraping)
**Section:** Python / Other
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Reverse engineering toolkit for mobile APIs. Detects bot protection systems (Cloudflare, DataDome, Akamai, PerimeterX, Incapsula), tests TLS fingerprint acceptance, and generates Python API clients from captured traffic.
```

---

## 6. Awesome-Reversing (ReversingID/Awesome-Reversing)
**Section:** Mobile / Android
**PR text:**
```
- [rekit](https://github.com/b-erdem/rekit) - Python toolkit for mobile API reverse engineering pipeline: Frida-based traffic capture, APK endpoint scanning, TLS fingerprint testing, bot protection detection, schema comparison, and client code generation.
```

---

## Reddit Posts

### r/reverseengineering
**Title:** rekit — Open-source toolkit for mobile API reverse engineering (6 tools)
**Body:** Link to blog post

### r/Python
**Title:** I built rekit — a Python toolkit for reverse engineering mobile APIs
**Body:** Link to blog post

### r/netsec
**Title:** rekit — Detect bot protection, test TLS fingerprints, and reverse engineer mobile APIs
**Body:** Link to blog post

### r/androiddev
**Title:** rekit — Frida-based HTTP capture + APK analysis toolkit for API reverse engineering
**Body:** Link to blog post

---

## Hacker News

**Title:** Show HN: Rekit – Reverse engineering toolkit for mobile APIs
**URL:** https://github.com/b-erdem/rekit

---

## Twitter/X Thread

Post 1:
I spent months reverse engineering 25 mobile APIs across Europe.

The hardest part wasn't the code — it was the gaps between tools.

So I built rekit: 6 focused tools for the mobile API RE pipeline. Open source, MIT licensed.

github.com/b-erdem/rekit

🧵

Post 2:
Tool 1: botwall — detect what bot protection a site uses in one command.

Supports Cloudflare, DataDome, Akamai, PerimeterX, Incapsula. Tells you the difficulty level and gives bypass hints.

Post 3:
Tool 2: ja3probe — test 26 TLS fingerprints against any URL.

Instantly see which browser fingerprints are accepted vs rejected. No more guessing why you're getting 403s.

Post 4:
Tool 3: hargen — generate a typed Python API client from a HAR file.

Groups endpoints, detects path params, classifies headers, infers schemas, outputs dataclasses. No more manual HAR-to-code translation.

Post 5:
Tool 4: apktap — capture Android HTTP traffic via Frida.

Hooks into OkHttp, Dio, URLConnection, WebView — above TLS, no proxy needed. Outputs standard HAR files.

Post 6:
Tools 5 & 6:

apkmap — scan decompiled APK for API endpoints, auth patterns, interceptors

schemadiff — compare response schemas across multiple APIs, generate unified Python models

Post 7:
The tools connect into a pipeline:

capture (apktap) → generate (hargen) → debug (ja3probe + botwall) → discover (apkmap) → normalize (schemadiff)

MIT licensed, contributions welcome.

github.com/b-erdem/rekit
