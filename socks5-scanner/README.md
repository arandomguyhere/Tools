# SOCKS5 Proxy Scanner v2.1

[![Scan Status](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml/badge.svg)](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml)
[![GitHub Pages](https://github.com/arandomguyhere/Tools/actions/workflows/pages.yml/badge.svg)](https://arandomguyhere.github.io/Tools/socks5-scanner/)

A production-ready, high-performance SOCKS5 proxy scanner with automated updates, GeoIP enrichment, threat intelligence, and interactive web UI.

## Live Proxy List

### Web Interface
**[View Proxy List →](https://arandomguyhere.github.io/Tools/socks5-scanner/)**

### Raw URLs (for tools/scripts)
```
# Working proxies (fully tested)
https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/proxies_working.txt

# Valid SOCKS5 (handshake verified)
https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/proxies_valid.txt
```

### Quick Fetch
```bash
# Bash
curl -s https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/proxies_working.txt

# Python
import requests
proxies = requests.get("https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/proxies_working.txt").text.strip().split("\n")
```

---

## Features

### Automated Scanning
- **Runs every 6 hours** via GitHub Actions
- Scans **20+ public proxy sources**
- Auto-commits working proxies
- Web UI auto-updates

### Scanner Capabilities
| Feature | Description |
|---------|-------------|
| **Sync & Async modes** | Thread-pool or asyncio with semaphore |
| **Hybrid GeoIP** | Offline GeoLite2 (50K+/sec) + API fallback for ALL proxies |
| **Threat intelligence** | Multi-source: Feodo, SSLBL, URLhaus, OTX |
| **UDP ASSOCIATE Testing** | Tests RFC 1928 UDP relay support (unique feature) |
| **Structured results** | Full `ProxyResult` objects with geo + threat data |
| **Error classification** | 15+ error categories |
| **Configurable timeouts** | Per-stage (connect/read/write/http) |
| **Retry logic** | Exponential backoff |
| **Export formats** | JSON, CSV, TXT |
| **Pipeline hooks** | Callbacks, filters, webhooks |

### Web UI Features
- **List View** - Paginated table with all proxy data
- **Map View** - Interactive Leaflet map with proxy markers
- **Country flags** - Emoji flags from country codes
- **City names** - Geographic location display
- **ASN/Org info** - Network and organization data
- **Latency badges** - Color-coded (green < 200ms, yellow < 500ms, red > 500ms)
- **Threat badges** - Multi-source threat intel (Clean/Low/Risk with tooltips)
- **Search filter** - Filter by IP, country, city, ASN, or org
- **Copy buttons** - Copy individual proxy or entire list
- **Download** - Export working proxies as text file
- **XSS protection** - All user data properly escaped
- **SRI integrity** - CDN resources verified with hashes

---

## Installation

```bash
git clone https://github.com/arandomguyhere/Tools.git
cd Tools/socks5-scanner
pip install -r requirements.txt
```

## CLI Usage

```bash
# Scan proxies from file
python -m src.cli scan proxies.txt

# Async mode (faster) with 200 concurrent
python -m src.cli scan proxies.txt --async -c 200

# Test a single proxy
python -m src.cli test 1.2.3.4:1080 --verbose

# Fetch from default sources
python -m src.cli fetch --sources default --async
```

## Python API

### Sync Scanner
```python
from src import SyncScanner, ScanConfig

config = ScanConfig(
    connect_timeout=5.0,
    max_concurrent=50,
    max_retries=1
)

with SyncScanner(config) as scanner:
    result = scanner.scan_one("1.2.3.4:1080")
    print(result.to_dict())

    results = scanner.scan_many(proxy_list)
    print(f"Working: {results.working}/{results.total}")
```

### Async Scanner
```python
from src import AsyncScanner
import asyncio

async def scan():
    async with AsyncScanner() as scanner:
        results = await scanner.scan_many(proxies, concurrency=200)
        return results

results = asyncio.run(scan())
```

---

## Structured Results

Every scan returns structured `ProxyResult` objects with GeoIP data:

```json
{
    "proxy": "1.2.3.4:1080",
    "reachable": true,
    "socks5_valid": true,
    "tunnel_works": true,
    "http_works": true,
    "latency_ms": 85,
    "error": null,
    "error_category": null,
    "timing": {
        "connect_ms": 12,
        "handshake_ms": 8,
        "tunnel_ms": 15,
        "http_ms": 50
    },
    "geo": {
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "lat": 40.7128,
        "lon": -74.0060,
        "isp": "DigitalOcean LLC",
        "org": "DigitalOcean",
        "asn": "AS14061",
        "asn_org": "DIGITALOCEAN-ASN"
    },
    "threat": {
        "score": 0,
        "pulses": 0
    }
}
```

## Error Categories

| Category | Description |
|----------|-------------|
| `TIMEOUT_CONNECT` | Connection timeout |
| `TIMEOUT_READ` | Read/recv timeout |
| `DNS_FAILURE` | DNS resolution failed |
| `NETWORK_UNREACHABLE` | Network/host unreachable |
| `CONNECTION_REFUSED` | Connection refused |
| `CONNECTION_RESET` | Connection reset |
| `HANDSHAKE_FAILED` | SOCKS5 handshake rejected |
| `PROTOCOL_MISMATCH` | Not SOCKS5 |
| `AUTH_REQUIRED` | Authentication needed |
| `PROXY_ERROR` | Proxy returned error |
| `HTTP_ERROR` | HTTP test failed |

---

## Configuration

```python
from src import ScanConfig

config = ScanConfig(
    # Timeouts (seconds)
    connect_timeout=5.0,
    read_timeout=5.0,
    write_timeout=5.0,
    http_timeout=10.0,

    # Retry
    max_retries=1,
    retry_delay=0.5,

    # Concurrency
    max_concurrent=100,

    # Test targets
    test_host="httpbin.org",
    test_port=80,
    test_url="http://httpbin.org/ip",
)
```

---

## Export & Integration

### Export Formats
```python
from src import export_results

saved = export_results(
    results,
    output_dir="./results",
    formats=["json", "csv", "txt", "detailed"]
)
```

### Pipeline Hooks
```python
from src import ProxyPipeline, FilterHook, StreamingHook

pipeline = ProxyPipeline()
pipeline.add_hook(FilterHook(working_only=True, max_latency=1000))
pipeline.add_hook(StreamingHook("working_proxies.txt"))

for result in results.results:
    pipeline.process(result)
```

### Feed Interfaces
```python
from src import FileFeed, URLFeed, MultiFeed

feed = MultiFeed([
    FileFeed("local_proxies.txt"),
    URLFeed("https://example.com/proxies.txt"),
])
proxies = feed.fetch()
```

---

## CI/CD

### Automated Scanning
The scanner runs every 6 hours via GitHub Actions:

| Schedule | UTC Time |
|----------|----------|
| Run 1 | 00:00 |
| Run 2 | 06:00 |
| Run 3 | 12:00 |
| Run 4 | 18:00 |

### Manual Trigger
1. Go to **Actions** tab
2. Select **SOCKS5 Proxy Scan**
3. Click **Run workflow**
4. Configure concurrency/timeout if needed

### Output Files
| File | Description |
|------|-------------|
| `proxies/proxies_working.txt` | Working proxies (tunnel verified) |
| `proxies/proxies_valid.txt` | Valid SOCKS5 handshake |
| `proxies/results.json` | Full results with stats |

---

## Performance

### CI/CD Optimizations
The GitHub Actions workflow includes several optimizations:
- **uvloop** - 20-30% faster async event loop
- **Hybrid GeoIP** - GeoLite2 offline database (50K+ lookups/sec) + API fallback
- **Parallel source fetching** - All 20+ sources fetched concurrently
- **500 concurrent connections** - 5x default concurrency
- **No GeoIP limits** - ALL working proxies enriched (not capped at 500)

### Real-World Benchmarks (GitHub Actions)
| Metric | Result |
|--------|--------|
| Proxies Scanned | ~104,000 |
| Working Found | ~900 |
| Scan Time | ~11 minutes |
| GeoIP Enriched | **ALL working proxies** |
| ↳ Offline (GeoLite2) | ~98% (instant) |
| ↳ API fallback | ~2% (rate-limited) |
| Threat Checked | ALL proxies (via blocklists) |

### Theoretical Benchmarks
| Mode | Concurrency | 5000 proxies | 100K proxies |
|------|-------------|--------------|--------------|
| Sync | 50 threads | ~2-3 min | ~40 min |
| Sync | 100 threads | ~1-2 min | ~20 min |
| Async | 100 concurrent | ~45 sec | ~15 min |
| Async | 500 concurrent | ~15 sec | ~5 min |
| Async + uvloop | 500 concurrent | ~12 sec | ~4 min |

---

## Architecture

```
socks5-scanner/
├── .github/
│   └── workflows/
│       ├── scan.yml          # Automated scanning
│       └── pages.yml         # GitHub Pages deploy
├── docs/
│   └── index.html            # Web UI
├── proxies/
│   ├── proxies_working.txt   # Working proxies
│   ├── proxies_valid.txt     # Valid proxies
│   └── results.json          # Full scan results
├── src/
│   ├── core.py               # Types, enums, results
│   ├── sync_scanner.py       # Sync scanner
│   ├── async_scanner_v2.py   # Async scanner
│   ├── geoip.py              # GeoIP enrichment (MaxMind + ip-api)
│   ├── udp_associate.py      # UDP ASSOCIATE testing (RFC 1928)
│   ├── anonymity.py          # Anonymity detection
│   ├── fingerprint.py        # Proxy quality profiling
│   ├── logger.py             # Logging
│   ├── export.py             # Export & hooks
│   ├── cli.py                # CLI interface
│   ├── scanner.py            # Source collection
│   ├── validator.py          # Validation
│   ├── hunter.py             # GitHub discovery
│   └── utils.py              # Utilities
├── requirements.txt
└── README.md
```

---

## Threat Intelligence

Multi-source threat intelligence checking for ALL proxies using free, unlimited APIs.

### Data Sources (Free, No API Key Required)

| Source | Type | Description |
|--------|------|-------------|
| **[Feodo Tracker](https://feodotracker.abuse.ch/)** | Botnet C2 | Tracks botnet command & control servers |
| **[SSLBL](https://sslbl.abuse.ch/)** | SSL Blacklist | Malicious SSL certificates and IPs |
| **[URLhaus](https://urlhaus.abuse.ch/)** | Malware URLs | Malware distribution sites |

### Optional: AlienVault OTX (API Key Required)

For additional threat pulse data on the first 50 proxies:

1. Create free account at https://otx.alienvault.com/
2. Get your API key from Settings → API Integration
3. Add `OTX_API_KEY` as a repository secret:
   - Go to repo Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `OTX_API_KEY`, Value: your key

### How It Works
1. **Blocklists** are fetched at scan time (no rate limits)
2. **ALL proxies** are checked against blocklists instantly
3. **OTX** adds pulse count for first 50 (if API key set)
4. **Tooltips** show which sources flagged each IP

### Threat Levels
| Badge | Score | Meaning |
|-------|-------|---------|
| **Clean** (green) | 0 | Not in any blocklist |
| **Low** (yellow) | 1-4 | Flagged by 1 source or low OTX pulses |
| **Risk** (red) | 5+ | Multiple sources or high OTX pulses |

Hover over any threat badge to see which sources flagged that IP.

---

## GeoIP Enrichment

The scanner uses a **hybrid approach** for maximum GeoIP coverage with minimal latency:

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID GEOIP STRATEGY                    │
├─────────────────────────────────────────────────────────────┤
│  Phase 1: Offline Database (GeoLite2-City)                  │
│  ├─ Speed: 50,000+ lookups/second                           │
│  ├─ Data: Country, City, Coordinates                        │
│  ├─ Coverage: ~98% of IPs                                   │
│  └─ No rate limits, no API keys needed                      │
├─────────────────────────────────────────────────────────────┤
│  Phase 2: API Fallback (ip-api.com batch)                   │
│  ├─ For: IPs not found in offline DB                        │
│  ├─ Speed: 100 IPs per request, 45 req/min                  │
│  ├─ Data: Country, City, ISP, Org, ASN                      │
│  └─ Only used for ~2% of IPs                                │
└─────────────────────────────────────────────────────────────┘
```

### Performance Comparison

| Method | 1,000 IPs | 10,000 IPs | 100,000 IPs |
|--------|-----------|------------|-------------|
| **Hybrid (current)** | ~0.02s | ~0.2s | ~2s |
| API-only (old) | ~2 min | ~22 min | ~3.7 hours |
| Improvement | **6,000x** | **6,600x** | **6,660x** |

### Data Sources

| Source | Type | Fields | Rate Limit |
|--------|------|--------|------------|
| [GeoLite2-City](https://github.com/P3TERX/GeoLite.mmdb) | Offline MMDB | Country, City, Coords | None |
| [ip-api.com](https://ip-api.com/) | REST API | + ISP, Org, ASN | 45 req/min |

The GeoLite2 database is downloaded fresh each scan from a community-maintained mirror (updated daily).

---

## UDP ASSOCIATE Testing (Unique Feature)

This scanner tests **UDP ASSOCIATE** support (RFC 1928 CMD=0x03) - a SOCKS5 capability that most scanners skip.

### Why It Matters
- **DNS queries** can go through UDP (prevents DNS leaks)
- **QUIC/HTTP3** uses UDP exclusively
- **VoIP/Gaming** apps need UDP relay
- **Full SOCKS5 compliance** verification

### Protocol Flow (RFC 1928 Section 7)
```
Client                              SOCKS5 Proxy
   │                                      │
   │  1. TCP Connect                      │
   │─────────────────────────────────────>│
   │  2. Auth Handshake                   │
   │<────────────────────────────────────>│
   │  3. UDP ASSOCIATE (CMD=0x03)         │
   │─────────────────────────────────────>│
   │  4. Reply: BND.ADDR:BND.PORT         │
   │<─────────────────────────────────────│
   │                                      │
   │  5. Send UDP to BND.ADDR:BND.PORT    │
   │  (with SOCKS5 header encapsulation)  │
   │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>│───> Destination
   │                                      │
   └──── TCP stays OPEN (controls session)│
```

### Test Results
Each proxy gets a `udp` field in results:
```json
{
    "proxy": "1.2.3.4:1080",
    "udp": {
        "udp_supported": true,
        "udp_works": false,
        "result": "supported",
        "handshake_ms": 45.2,
        "bnd_addr": "1.2.3.4",
        "bnd_port": 10800,
        "reply_code": 0
    }
}
```

### Result Types
| Result | Meaning |
|--------|---------|
| `success` | UDP relay fully tested and working |
| `supported` | UDP ASSOCIATE accepted (relay untested) |
| `not_supported` | Proxy returned CMD_NOT_SUPPORTED (0x07) |
| `auth_required` | Authentication needed for UDP |
| `timeout` | Connection/operation timeout |
| `error` | Other failure |

### Python API
```python
from src.udp_associate import test_udp_associate
import asyncio

async def check_udp():
    result = await test_udp_associate("1.2.3.4", 1080, timeout=5.0)
    print(f"UDP Supported: {result.udp_supported}")
    print(f"BND Address: {result.bnd_addr}:{result.bnd_port}")

asyncio.run(check_udp())
```

---

## Additional Modules

```python
# GeoIP enrichment (supports MaxMind databases or ip-api.com)
from src.geoip import GeoIPEnricher
enricher = GeoIPEnricher()
info = enricher.enrich("1.2.3.4")
# Returns: country, city, ASN, ISP, org

# UDP ASSOCIATE testing (RFC 1928 Section 7)
from src.udp_associate import test_udp_sync
result = test_udp_sync("1.2.3.4:1080")
# Returns: udp_supported, bnd_addr, bnd_port, result type

# Anonymity detection
from src.anonymity import AnonymityChecker
checker = AnonymityChecker()
result = checker.check("1.2.3.4", 1080)
# Returns: anonymity_level (transparent/anonymous/elite), headers leaked

# Proxy quality profiling
from src.fingerprint import ProxyProfiler
profiler = ProxyProfiler()
profile = profiler.profile("1.2.3.4", 1080)
# Returns: quality_tier, proxy_type, stability_score, estimated_hops

# GitHub hunting (discovers new proxy sources)
from src import ProxyHunter
hunter = ProxyHunter()
proxies, results = hunter.hunt()
```

---

## CLI Reference

```
usage: socks5-scanner [-h] [-v] [--debug] [-q] [--json] {scan,test,fetch,version}

Commands:
  scan      Scan proxies from file/stdin
  test      Test a single proxy
  fetch     Fetch and scan from sources
  version   Show version info

Scan Options:
  -o, --output DIR      Output directory
  -f, --format FMT      Output formats (json, csv, txt, detailed)
  --async               Use async scanner
  -c, --concurrency N   Concurrent connections
  --timeout SECS        Connection timeout
  --http-timeout SECS   HTTP test timeout
  --retries N           Retry count
```

---

## License

MIT License

## Disclaimer

Proxies are collected from public sources. Use at your own risk. No guarantees of uptime, speed, or anonymity.
