# SOCKS5 Proxy Scanner v2.0

[![Scan Status](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml/badge.svg)](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml)
[![GitHub Pages](https://github.com/arandomguyhere/Tools/actions/workflows/pages.yml/badge.svg)](https://arandomguyhere.github.io/Tools/socks5-scanner/)

A production-ready, high-performance SOCKS5 proxy scanner with automated updates and web UI.

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
| **Structured results** | Full `ProxyResult` objects |
| **Error classification** | 15+ error categories |
| **Configurable timeouts** | Per-stage (connect/read/write/http) |
| **Retry logic** | Exponential backoff |
| **Export formats** | JSON, CSV, TXT |
| **Pipeline hooks** | Callbacks, filters, webhooks |

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

Every scan returns structured `ProxyResult` objects:

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

| Mode | Concurrency | 5000 proxies |
|------|-------------|--------------|
| Sync | 50 threads | ~2-3 min |
| Sync | 100 threads | ~1-2 min |
| Async | 100 concurrent | ~45 sec |
| Async | 200 concurrent | ~25 sec |
| Async + uvloop | 200 concurrent | ~20 sec |

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

## Legacy Features

```python
# GitHub hunting (discovers new proxy sources)
from src import ProxyHunter
hunter = ProxyHunter()
proxies, results = hunter.hunt()

# IP enrichment (ASN, geo, ownership)
from src import IPEnricher
enricher = IPEnricher()
info = enricher.enrich("1.2.3.4")

# Quick scan from static sources
from src import quick_scan
results = quick_scan()
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
