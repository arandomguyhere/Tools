# SOCKS5 Proxy Scanner v2.0

A production-ready, high-performance SOCKS5 proxy scanner with structured results and pipeline integration.

## Features

### Core Capabilities
- **Sync and Async modes**: Choose based on your use case
- **Structured results**: Full `ProxyResult` objects with error categorization
- **Error classification**: 15+ error categories (timeout, DNS, protocol mismatch, etc.)
- **Configurable timeouts**: Per-stage timeouts (connect/read/write/http)
- **Retry logic**: Configurable retries with exponential backoff

### Performance
- **Semaphore-controlled concurrency**: Precise control over parallel connections
- **Optional uvloop**: Faster event loop on Linux/macOS
- **Streaming results**: Memory-efficient for large scans

### Integration
- **JSON/CSV/TXT export**: Multiple output formats
- **Pipeline hooks**: Callbacks, filters, streaming, webhooks
- **Feed interfaces**: File, URL, and custom source adapters
- **Logging infrastructure**: Debug/info/warn levels with color support

## Installation

```bash
cd socks5-scanner
pip install -r requirements.txt
```

## Quick Start

### CLI Usage

```bash
# Scan proxies from file (sync mode)
python -m src.cli scan proxies.txt

# Async mode (faster) with 200 concurrent connections
python -m src.cli scan proxies.txt --async -c 200

# Test a single proxy
python -m src.cli test 1.2.3.4:1080 --verbose

# Fetch from default sources and scan
python -m src.cli fetch --sources default --async
```

### Python API

```python
# Sync scanning
from src import SyncScanner, ScanConfig

config = ScanConfig(
    connect_timeout=5.0,
    max_concurrent=50,
    max_retries=1
)

with SyncScanner(config) as scanner:
    # Single proxy
    result = scanner.scan_one("1.2.3.4:1080")
    print(result.to_dict())

    # Multiple proxies
    results = scanner.scan_many(proxy_list)
    print(f"Working: {results.working}/{results.total}")
```

```python
# Async scanning (faster)
from src import AsyncScanner
import asyncio

async def scan():
    async with AsyncScanner() as scanner:
        results = await scanner.scan_many(proxies, concurrency=200)
        return results

results = asyncio.run(scan())
```

## Structured Results

Every scan returns structured `ProxyResult` objects:

```python
{
    "proxy": "1.2.3.4:1080",
    "host": "1.2.3.4",
    "port": 1080,
    "protocol": "socks5",
    "reachable": true,
    "socks5_valid": true,
    "tunnel_works": true,
    "http_works": true,
    "latency_ms": 85,
    "error": null,
    "error_category": null,
    "external_ip": "1.2.3.4",
    "timing": {
        "connect_ms": 12,
        "handshake_ms": 8,
        "tunnel_ms": 15,
        "http_ms": 50
    }
}
```

## Error Categories

Precise failure diagnosis with 15+ categories:

| Category | Description |
|----------|-------------|
| `TIMEOUT_CONNECT` | Connection timeout |
| `TIMEOUT_READ` | Read/recv timeout |
| `DNS_FAILURE` | DNS resolution failed |
| `NETWORK_UNREACHABLE` | Network/host unreachable |
| `CONNECTION_REFUSED` | Connection actively refused |
| `CONNECTION_RESET` | Connection reset by peer |
| `HANDSHAKE_FAILED` | SOCKS5 handshake rejected |
| `PROTOCOL_MISMATCH` | Not SOCKS5 or wrong version |
| `AUTH_REQUIRED` | Authentication needed |
| `PROXY_ERROR` | Proxy returned error code |
| `HTTP_ERROR` | HTTP test failed |

## Configuration

```python
from src import ScanConfig

config = ScanConfig(
    # Timeouts (seconds)
    connect_timeout=5.0,
    read_timeout=5.0,
    write_timeout=5.0,
    http_timeout=10.0,

    # Retry settings
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

## Export & Integration

### Export Formats

```python
from src import export_results

# Export in multiple formats
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

# Process results through pipeline
for result in results.results:
    pipeline.process(result)

pipeline.finalize(results)
```

### Feed Interfaces

```python
from src import FileFeed, URLFeed, MultiFeed

# Combine multiple sources
feed = MultiFeed([
    FileFeed("local_proxies.txt"),
    URLFeed("https://example.com/proxies.txt"),
])

proxies = feed.fetch()
```

## Performance Comparison

| Mode | Concurrency | 5000 proxies |
|------|-------------|--------------|
| Sync | 50 threads | ~2-3 min |
| Sync | 100 threads | ~1-2 min |
| Async | 100 concurrent | ~45 sec |
| Async | 200 concurrent | ~25 sec |
| Async + uvloop | 200 concurrent | ~20 sec |

## Legacy Features

The v1 API is still available for compatibility:

```python
# GitHub hunting (discovers new proxy sources)
from src import ProxyHunter

hunter = ProxyHunter()
proxies, results = hunter.hunt()

# IP enrichment (ASN, geo, ownership)
from src import IPEnricher

enricher = IPEnricher()
info = enricher.enrich("1.2.3.4")
# Returns: country, city, asn, isp, is_datacenter, etc.

# Quick scan from static sources
from src import quick_scan
results = quick_scan()
```

## Architecture

```
src/
├── core.py           # Types, enums, structured results
├── sync_scanner.py   # Synchronous scanner with thread pool
├── async_scanner_v2.py # Async scanner with semaphore control
├── logger.py         # Logging infrastructure
├── export.py         # Export formats and hooks
├── cli.py            # Unified CLI
├── scanner.py        # Legacy: Source collection
├── validator.py      # Legacy: Proxy validation
├── hunter.py         # Legacy: GitHub discovery
└── utils.py          # Legacy: Utilities
```

## CLI Reference

```
usage: socks5-scanner [-h] [-v] [--debug] [-q] [--json] {scan,test,fetch,version}

Commands:
  scan      Scan proxies from file/stdin
  test      Test a single proxy
  fetch     Fetch and scan from sources
  version   Show version info

Scan options:
  -o, --output DIR      Output directory
  -f, --format FMT      Output formats (json, csv, txt, detailed)
  --async               Use async scanner
  -c, --concurrency N   Concurrent connections
  --timeout SECS        Connection timeout
  --http-timeout SECS   HTTP test timeout
  --retries N           Retry count
```

## License

MIT License
