# SOCKS5 Proxy Scanner

A multi-threaded tool for discovering and validating SOCKS5 proxies from various free sources.

## Features

- **Multi-source scanning**: Aggregates proxies from multiple free proxy lists
- **SOCKS5 validation**: Tests actual SOCKS5 protocol handshake
- **HTTP testing**: Verifies proxies can make real HTTP requests
- **Concurrent processing**: Multi-threaded for fast scanning
- **Flexible output**: Results in JSON and plain text formats

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Run a quick test to verify everything works
python quick_test.py

# Run a full scan with default settings
python -m src.main

# Run with custom thread count
python -m src.main --threads 50

# Save to custom directory
python -m src.main --output ./my_proxies
```

## Usage

```
usage: main.py [-h] [-c CONFIG] [-m {free,file,both}] [-f PROXY_FILE]
               [-t THREADS] [-o OUTPUT] [--timeout TIMEOUT]
               [--no-validate] [--no-banner] [-q] [-v]

Options:
  -c, --config        Path to configuration file (YAML)
  -m, --mode          Scan mode: free, file, or both
  -f, --proxy-file    Proxy list file for file/both modes
  -t, --threads       Number of validation threads (default: 20)
  -o, --output        Output directory (default: ./results)
  --timeout           Validation timeout in seconds (default: 5)
  --no-validate       Only collect proxies, skip validation
  -q, --quiet         Minimal output
```

## Examples

```bash
# Scan free sources (default)
python -m src.main

# Test proxies from a file
python -m src.main --mode file --proxy-file my_proxies.txt

# Combine file and free sources
python -m src.main --mode both --proxy-file my_proxies.txt

# Fast scan with more threads
python -m src.main --threads 100

# Just collect proxies without validation
python -m src.main --no-validate
```

## Output

Results are saved to the output directory in two formats:

- `results_YYYYMMDD_HHMMSS.json` - Full results with all proxy details
- `valid_proxies_YYYYMMDD_HHMMSS.txt` - List of valid SOCKS5 proxies
- `working_proxies_YYYYMMDD_HHMMSS.txt` - List of HTTP-tested working proxies

## Configuration

Edit `config/config.yaml` to customize:

- Proxy sources
- Validation timeouts
- Test URLs
- Output settings

## Python API

```python
from src.scanner import Socks5Scanner, quick_scan

# Quick scan with defaults
results = quick_scan()

# Custom scan
scanner = Socks5Scanner({
    'timeout': 10,
    'validator': {'timeout': 3}
})
results = scanner.run_full_scan(max_workers=50)

# Access results
for proxy in results['working']:
    print(f"{proxy['proxy']} - {proxy['response_time_ms']}ms")
```

## License

MIT License
