# SOCKS5 Proxy Scanner

A high-performance, multi-threaded tool for discovering and validating SOCKS5 proxies from various free sources. Inspired by [monosans/proxy-scraper-checker](https://github.com/monosans/proxy-scraper-checker).

## Features

- **Multi-source scanning**: Collects from 20+ free proxy lists
- **SOCKS5 validation**: Tests actual protocol handshake
- **HTTP testing**: Verifies real connectivity through proxies
- **Async mode**: High-performance concurrent scanning with `aiohttp`
- **Geolocation**: IP location lookup (country, city, ISP)
- **Flexible output**: JSON and plain text formats

## Installation

```bash
cd socks5-scanner

# Install core dependencies
pip install -r requirements.txt

# Or minimal install
pip install requests PySocks PyYAML

# For async mode (recommended for large scans)
pip install aiohttp
```

## Quick Start

```bash
# Run a quick test
python quick_test.py

# Standard scan (threaded)
python -m src.main

# Async mode - much faster for large scans
python -m src.main --async --concurrency 200

# With geolocation
python -m src.main --async --geo

# Custom output
python -m src.main -o ./my_proxies -t 50
```

## Usage

```
usage: main.py [-h] [-c CONFIG] [-m {free,file,both}] [-f PROXY_FILE]
               [-t THREADS] [--async] [--concurrency N] [--geo]
               [-o OUTPUT] [--timeout TIMEOUT] [--no-validate] [-q] [-v]

Options:
  -m, --mode          Scan mode: free, file, or both
  -f, --proxy-file    Proxy list file for file/both modes
  -t, --threads       Threads for sync mode (default: 20)
  --async             Use async mode (faster, requires aiohttp)
  --concurrency       Concurrent connections in async mode (default: 100)
  --geo               Enable geolocation lookup
  -o, --output        Output directory (default: ./results)
  --timeout           Validation timeout in seconds (default: 5)
  --no-validate       Only collect, skip validation
```

## Examples

```bash
# Fast async scan with 200 concurrent connections
python -m src.main --async --concurrency 200

# Async with geolocation
python -m src.main --async --geo -o ./results

# Test proxies from a file
python -m src.main -m file -f my_proxies.txt

# Standard threaded mode
python -m src.main -t 100

# Just collect proxies, no validation
python -m src.main --no-validate
```

## Python API

```python
# Standard mode
from src import Socks5Scanner, quick_scan

# Quick scan
results = quick_scan()

# Custom scan
scanner = Socks5Scanner({'timeout': 10})
results = scanner.run_full_scan(max_workers=50)

# Async mode (faster)
from src import run_async_scan, AsyncSocks5Scanner
import asyncio

# Quick async
results = run_async_scan(concurrency=200, geo_lookup=True)

# Custom async
scanner = AsyncSocks5Scanner()
results = asyncio.run(scanner.run_scan(concurrency=300))

# Access results
for proxy in results['valid']:
    print(f"{proxy['proxy']} - {proxy['response_time_ms']}ms")
    if proxy.get('geo'):
        print(f"  Location: {proxy['geo']['country']}, {proxy['geo']['city']}")
```

## Output

Results are saved to the output directory:

- `results_YYYYMMDD_HHMMSS.json` - Full results with metadata
- `valid_proxies_YYYYMMDD_HHMMSS.txt` - Valid SOCKS5 proxies
- `working_proxies_YYYYMMDD_HHMMSS.txt` - HTTP-tested working proxies

## Proxy Sources

The scanner collects from 20+ sources including:
- [TheSpeedX/SOCKS-List](https://github.com/TheSpeedX/SOCKS-List)
- [monosans/proxy-list](https://github.com/monosans/proxy-list) (hourly updated)
- [jetkai/proxy-list](https://github.com/jetkai/proxy-list)
- [proxyscrape.com](https://proxyscrape.com)
- And many more...

## Performance Comparison

| Mode | Threads/Concurrency | ~Time for 5000 proxies |
|------|---------------------|------------------------|
| Sync | 20 threads | ~4-5 minutes |
| Sync | 100 threads | ~1-2 minutes |
| Async | 100 concurrent | ~45 seconds |
| Async | 200 concurrent | ~25 seconds |

## Configuration

Edit `config/config.yaml` to customize sources, timeouts, and output settings.

## License

MIT License
