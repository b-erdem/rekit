# rekit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/b-erdem/rekit/actions/workflows/ci.yml/badge.svg)](https://github.com/b-erdem/rekit/actions/workflows/ci.yml)
[![Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

Reverse Engineering Toolkit for Mobile APIs.

14 focused tools for the mobile API reverse engineering pipeline: capture traffic, map endpoints, test fingerprints, detect bot protection, compare schemas, generate clients, mock servers, analyze tokens, map auth flows, decode protobuf, scan JS bundles, probe rate limits, bypass cert pinning, and fingerprint HTTP/2.

## Why rekit?

Reverse engineering mobile APIs is a multi-step process with lots of manual work between each step. Existing tools (mitmproxy, jadx, frida) are great at individual steps but nothing connects the pipeline. rekit fills the gaps:

- **No more manual HAR-to-client translation** — `hargen` generates typed Python clients automatically
- **No more proxy/cert pinning headaches** — `apktap` hooks at the app layer, above TLS; `certpatch` generates targeted bypass scripts
- **No more grepping through 40K decompiled files** — `apkmap` and `jsbundle` find the API surface for you
- **No more guessing why you're getting 403s** — `ja3probe`, `botwall`, and `headerprint` tell you exactly what's blocking you
- **No more hand-mapping 25 different response schemas** — `schemadiff` builds the unified model
- **No more copy-pasting JWTs into jwt.io** — `tokendump` decodes every token in your traffic
- **No more manually figuring out auth flows** — `authmap` maps OAuth2, session cookies, API keys, and generates auth modules
- **No more hitting live APIs during development** — `mockapi` replays captured traffic as a local server
- **No more binary protobuf gibberish** — `protorev` decodes and infers schemas from gRPC traffic
- **No more guessing rate limits** — `ratelim` finds the exact threshold

## Tools

### Core Pipeline

| Tool | What it does | Input | Output |
|------|-------------|-------|--------|
| **hargen** | Generate typed Python API client from captured traffic | HAR / mitmproxy dump | Python client + dataclasses |
| **apktap** | Hook into Android app HTTP layer via Frida | Package name | HAR file |
| **apkmap** | Scan decompiled APK for API endpoints and auth | APK or decompiled source | Endpoint map (table/JSON) |
| **schemadiff** | Compare API response schemas across sources | JSON files | Unified model + diff table |

### Security & Fingerprinting

| Tool | What it does | Input | Output |
|------|-------------|-------|--------|
| **ja3probe** | Test which TLS fingerprints a target accepts | URL | Accept/reject matrix |
| **botwall** | Identify bot protection system and difficulty | URL | Detection report |
| **headerprint** | Analyze HTTP/2 and header-order fingerprints | HAR file | Fingerprint match + anomalies |
| **certpatch** | Scan for cert pinning, generate Frida bypass | Decompiled source | Bypass script + config |

### Traffic Analysis

| Tool | What it does | Input | Output |
|------|-------------|-------|--------|
| **tokendump** | Extract and decode all auth tokens (JWT, OAuth, etc.) | HAR file | Token report + decoded JWTs |
| **authmap** | Map authentication flows, generate auth modules | HAR file | Flow diagram + Python auth code |
| **mockapi** | Replay captured traffic as a local mock server | HAR file | Running HTTP server |
| **ratelim** | Probe rate limits with binary search | URL | Limits table + safe RPS |

### App Analysis

| Tool | What it does | Input | Output |
|------|-------------|-------|--------|
| **jsbundle** | Scan React Native / JS bundles for API endpoints | APK / IPA / bundle | Endpoints + secrets + GraphQL |
| **protorev** | Decode protobuf/gRPC, infer .proto schemas | HAR file / raw bytes | Decoded messages + .proto file |

## Install

```bash
# From source
git clone https://github.com/b-erdem/rekit.git
cd rekit
pip install -e .

# With TLS fingerprint testing
pip install -e ".[tls]"

# With Frida hooking
pip install -e ".[frida]"

# Everything
pip install -e ".[all]"
```

## Quick Start

### Detect bot protection

```bash
$ rekit botwall detect https://www.example.com

╭──────────────── Cloudflare (Under Attack Mode) ────────────────╮
│ Confidence: 100%    Difficulty: IMPRACTICAL                    │
│                                                                │
│ Evidence:                                                      │
│   - cf-ray header present                                      │
│   - server header is 'cloudflare'                              │
│   - cf-mitigated header (challenge)                            │
│   - __cf_bm cookie (Bot Management)                            │
│                                                                │
│ Bypass hints:                                                  │
│   - Requires solving Cloudflare JS challenge or Turnstile.     │
│   - Use curl_cffi with chrome impersonation for TLS.           │
╰────────────────────────────────────────────────────────────────╯
```

### Test TLS fingerprints

```bash
$ rekit ja3probe probe https://api.example.com

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
┃ Profile      ┃  Status   ┃ HTTP ┃ Time (ms) ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━┩
│ chrome_120   │ ACCEPTED  │ 200  │        45 │
│ safari_15_5  │ ACCEPTED  │ 200  │        38 │
│ firefox_133  │ CHALLENGE │ 403  │        42 │
│ python_req   │ REJECTED  │ 403  │        29 │
└──────────────┴───────────┴──────┴───────────┘
3/26 accepted. Protection: Akamai. Recommended: chrome_120
```

### Generate API client from captured traffic

```bash
$ rekit hargen generate traffic.har -o ./client/ --name MyApiClient

Generated: client.py (3 endpoints), models.py (8 dataclasses)
```

### Run a mock server from captured traffic

```bash
$ rekit mockapi serve traffic.har --port 8080

Mock server running on http://127.0.0.1:8080
Endpoints:
  GET  /api/v1/users          (3 responses)
  POST /api/v1/users          (1 response)
  GET  /api/v1/users/{id}     (5 responses)
```

### Extract and decode tokens

```bash
$ rekit tokendump extract traffic.har

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Type           ┃ Source  ┃ Value                    ┃ Expires     ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ JWT            │ Bearer  │ eyJhbGci...kpXV         │ 2h from now │
│ OAUTH_REFRESH  │ body    │ dGhpcyBp...c2Vj         │ 30 days     │
│ SESSION_COOKIE │ cookie  │ sess_abc...xyz9          │ session     │
└────────────────┴─────────┴──────────────────────────┴─────────────┘
```

### Map authentication flows

```bash
$ rekit authmap detect traffic.har

OAuth2 Authorization Code + PKCE
  1. POST /oauth/authorize → redirect with code
  2. POST /oauth/token (code + code_verifier) → access_token + refresh_token
  3. GET /api/* (Bearer token) × 47 requests
  4. 401 → POST /oauth/token (refresh_token) → new access_token
```

### Scan JS bundles from React Native apps

```bash
$ rekit jsbundle scan ./app.apk

API Endpoints:     12 found
Hardcoded Secrets:  3 found (use --show-secrets to reveal)
GraphQL Operations: 5 queries, 2 mutations
```

### Decode protobuf traffic

```bash
$ rekit protorev extract traffic.har

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ gRPC Method                        ┃ Fields Found ┃ Type   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━┩
│ /user.UserService/GetUser          │ 5            │ gRPC   │
│ /feed.FeedService/GetFeed          │ 12           │ gRPC   │
└────────────────────────────────────┴──────────────┴────────┘
```

### Probe rate limits

```bash
$ rekit ratelim probe https://api.example.com/v1/search

Probed 50 requests at 5.0 rps
  Successful: 42  Rate-limited: 8  Errors: 0
  First 429 at request #43
  Rate limit: 100 req/min (from headers)
  Cooldown: 60s
  Recommended: 1.5 rps with 0.7s jitter
```

### Generate cert pinning bypass

```bash
$ rekit certpatch bypass ./decompiled/ -o bypass.js

Detected 3 pinning implementations:
  - OkHttp CertificatePinner (api.example.com) → easy bypass
  - network_security_config.xml (*.example.com) → easy bypass
  - Custom X509TrustManager → medium bypass

Generated: bypass.js (load with: frida -U -f com.example.app -l bypass.js)
```

## The Pipeline

```
                    ┌─────────┐
                    │ apktap  │──────────────┐
                    └────┬────┘              │
                         │ HAR               │
                         v                   v
┌─────────┐    ┌─────────────────┐    ┌────────────┐
│ apkmap  │    │     hargen      │    │  mockapi   │
│jsbundle │    │  (generate API  │    │ (mock srv) │
└────┬────┘    │    client)      │    └────────────┘
     │         └────────┬────────┘
     │                  │
     v                  v
┌─────────┐    ┌─────────────────┐    ┌────────────┐
│certpatch│    │ tokendump       │    │  ratelim   │
│         │    │ authmap         │    │            │
└─────────┘    └─────────────────┘    └────────────┘
                        │
     ┌──────────────────┼──────────────────┐
     v                  v                  v
┌─────────┐    ┌─────────────────┐    ┌────────────┐
│ja3probe │    │   schemadiff    │    │ protorev   │
│ botwall │    │                 │    │            │
│headerpr.│    └─────────────────┘    └────────────┘
└─────────┘
```

1. **Capture**: Use `apktap` to hook into the app and capture traffic, or use mitmproxy
2. **Analyze app**: Use `apkmap`, `jsbundle`, `certpatch` to understand the app
3. **Generate**: Feed the HAR file to `hargen` to get a typed Python client
4. **Understand auth**: Use `tokendump` and `authmap` to map the auth flow
5. **Debug blocks**: Use `ja3probe`, `botwall`, and `headerprint` when requests get blocked
6. **Mock & test**: Use `mockapi` to develop against captured traffic
7. **Normalize**: Use `schemadiff` when building a unified model across multiple APIs
8. **Decode binary**: Use `protorev` for protobuf/gRPC APIs
9. **Scale safely**: Use `ratelim` to find rate limit boundaries

## Requirements

- Python 3.9+
- `curl_cffi` for TLS fingerprint testing (`pip install curl_cffi`)
- `frida-tools` for app traffic capture (`pip install frida-tools`)
- `jadx` for APK decompilation (install separately)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT — see [LICENSE](LICENSE) for details.
