# SOCKS5 Proxy Scanner

A high-performance tool for discovering and validating SOCKS5 proxies.

Inspired by:
- [monosans/proxy-scraper-checker](https://github.com/monosans/proxy-scraper-checker) (Rust)
- [arandomguyhere/Proxy-Hound](https://github.com/arandomguyhere/Proxy-Hound) (Python)

## Features

- **Multi-source scanning**: 20+ static proxy sources
- **GitHub hunting**: Discovers new proxy repositories automatically
- **SOCKS5 validation**: Tests actual protocol handshake
- **HTTP testing**: Verifies connectivity through proxies
- **Async mode**: High-performance concurrent scanning
- **Geolocation**: IP location lookup (country, city, ISP)
- **Adaptive learning**: Tracks which sources work best over time
- **SQLite database**: Persistent storage for source quality scores

## Installation

```bash
cd socks5-scanner
pip install -r requirements.txt
```

## Quick Start

```bash
# Standard scan from static sources
python -m src.main

# Hunt for new sources on GitHub
python -m src.main --hunt

# Hunt mode only
python -m src.main -m hunt

# Async mode for speed
python -m src.main --async --concurrency 200

# All features combined
python -m src.main --hunt --async --geo
```

## Usage

```
usage: main.py [-h] [-m {free,file,hunt,both}] [-f PROXY_FILE] [--hunt]
               [-t THREADS] [--async] [--concurrency N] [--geo]
               [-o OUTPUT] [--timeout TIMEOUT] [--no-validate] [-q] [-v]

Options:
  -m, --mode          Scan mode: free, file, hunt, or both
  --hunt              Enable GitHub repository hunting
  -t, --threads       Threads for sync mode (default: 20)
  --async             Use async mode (faster)
  --concurrency       Concurrent connections (default: 100)
  --geo               Enable geolocation lookup
  -o, --output        Output directory (default: ./results)
```

## Modes

| Mode | Description |
|------|-------------|
| `free` | Use 20+ pre-configured static sources |
| `hunt` | Search GitHub for proxy repositories |
| `file` | Load proxies from a local file |
| `both` | Combine free and file sources |
| `--hunt` | Add hunting to any mode |

## Examples

```bash
# Fast async with GitHub hunting
python -m src.main --hunt --async --concurrency 200

# Hunt + geolocation
python -m src.main -m hunt --geo

# Standard + hunting combined
python -m src.main --hunt -t 50

# From file with validation
python -m src.main -m file -f proxies.txt
```

## How Hunting Works

The hunter (inspired by Proxy-Hound) uses:

1. **Scent Analysis**: Scores repositories by proxy-related keywords
2. **Freshness Detection**: Prioritizes recently updated repos
3. **Adaptive Learning**: Tracks which sources yield valid proxies
4. **SQLite Database**: Remembers good sources between runs

```python
from src import ProxyHunter

hunter = ProxyHunter()
proxies, results = hunter.hunt()

# Check hunting stats
stats = hunter.db.get_stats()
print(f"Tracked repos: {stats['total_repos']}")
print(f"Avg success score: {stats['avg_score']:.1f}")
```

## Python API

```python
# Standard scan
from src import Socks5Scanner, quick_scan
results = quick_scan()

# With hunting
scanner = Socks5Scanner()
results = scanner.run_full_scan(use_hunter=True)

# Async mode
from src import run_async_scan
results = run_async_scan(concurrency=200, geo_lookup=True)

# Direct hunter access
from src import ProxyHunter
hunter = ProxyHunter()
proxies, hunt_results = hunter.hunt()
```

## Output

Results are saved to the output directory:

- `results_*.json` - Full results with metadata
- `valid_proxies_*.txt` - Valid SOCKS5 proxies
- `working_proxies_*.txt` - HTTP-tested working proxies
- `proxy_hunt.db` - SQLite database (hunt mode)

## Performance

| Mode | Config | ~5000 proxies |
|------|--------|---------------|
| Sync | 20 threads | ~4-5 min |
| Sync | 100 threads | ~1-2 min |
| Async | 100 concurrent | ~45 sec |
| Async | 200 concurrent | ~25 sec |

## License

MIT License
