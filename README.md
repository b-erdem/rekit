# rekit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

Reverse Engineering Toolkit for Mobile APIs.

Six focused tools for the mobile API reverse engineering pipeline: capture traffic, map endpoints, test fingerprints, detect bot protection, compare schemas, and generate clients.

## Why rekit?

Reverse engineering mobile APIs is a multi-step process with lots of manual work between each step. Existing tools (mitmproxy, jadx, frida) are great at individual steps but nothing connects the pipeline. rekit fills the gaps:

- **No more manual HAR-to-client translation** — `hargen` generates typed Python clients automatically
- **No more proxy/cert pinning headaches** — `apktap` hooks at the app layer, above TLS
- **No more grepping through 40K decompiled files** — `apkmap` finds the API surface for you
- **No more guessing why you're getting 403s** — `ja3probe` and `botwall` tell you exactly what's blocking you
- **No more hand-mapping 25 different response schemas** — `schemadiff` builds the unified model

## Tools

| Tool | What it does | Input | Output |
|------|-------------|-------|--------|
| **hargen** | Generate typed Python API client from captured traffic | HAR / mitmproxy dump | Python client + dataclasses |
| **apktap** | Hook into Android app HTTP layer via Frida | Package name | HAR file |
| **apkmap** | Scan decompiled APK for API endpoints and auth | APK or decompiled source | Endpoint map (table/JSON) |
| **ja3probe** | Test which TLS fingerprints a target accepts | URL | Accept/reject matrix |
| **botwall** | Identify bot protection system and difficulty | URL | Detection report |
| **schemadiff** | Compare API response schemas across sources | JSON files | Unified model + diff table |

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
# Inspect captured traffic
$ rekit hargen inspect traffic.har

# Generate typed Python client
$ rekit hargen generate traffic.har -o ./client/ --name MyApiClient

Generated: client.py (3 endpoints), models.py (8 dataclasses)
```

### Capture traffic from Android app

```bash
# Hooks into OkHttp/Dio/URLConnection — no proxy needed
$ rekit apktap capture com.example.app -o traffic.har
```

### Scan decompiled APK

```bash
$ rekit apkmap scan ./decompiled/ --format json -o report.json
```

### Compare API schemas

```bash
$ rekit schemadiff compare api1.json api2.json api3.json --labels src1,src2,src3

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━┳━━━━━━┓
┃ Field        ┃ Type         ┃ src1 ┃ src2 ┃ src3 ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━╇━━━━━━┩
│ price        │ int          │  +   │  +   │  +   │
│ bedrooms     │ int          │  +   │  +   │  +   │
│ address      │ object       │  +   │  +   │  +   │
│ bathrooms    │ int          │  —   │  +   │  +   │
│ zestimate    │ int          │  —   │  —   │  +   │
└──────────────┴──────────────┴──────┴──────┴──────┘

# Generate unified Python dataclass
$ rekit schemadiff compare *.json --format python -o model.py
```

## The Pipeline

```
apktap ──> hargen ──> working Python client
  |           |
  v           v
apkmap    ja3probe + botwall  (for deeper analysis)
  |
  v
schemadiff  (when normalizing multiple APIs)
```

1. **Capture**: Use `apktap` to hook into the app and capture traffic, or use mitmproxy
2. **Generate**: Feed the HAR file to `hargen` to get a typed Python client
3. **Analyze**: Use `apkmap` to find endpoints you might have missed
4. **Debug**: Use `ja3probe` and `botwall` when requests get blocked
5. **Normalize**: Use `schemadiff` when building a unified model across multiple APIs

## Requirements

- Python 3.9+
- `curl_cffi` for TLS fingerprint testing (`pip install curl_cffi`)
- `frida-tools` for app traffic capture (`pip install frida-tools`)
- `jadx` for APK decompilation (install separately)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT — see [LICENSE](LICENSE) for details.
