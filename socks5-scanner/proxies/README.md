# SOCKS5 Proxy List

[![Scan Status](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml/badge.svg)](https://github.com/arandomguyhere/Tools/actions/workflows/scan.yml)

Auto-updated every 6 hours via GitHub Actions.

## Status

- **Last updated:** Awaiting first run
- **Working proxies:** 0

## Web UI

**[View Interactive Proxy List →](https://arandomguyhere.github.io/Tools/socks5-scanner/)**

## Files

| File | Description | Raw URL |
|------|-------------|---------|
| `socks5.txt` | Working proxies (tunnel verified) | [Download](https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt) |
| `socks5_valid.txt` | Valid SOCKS5 handshake | [Download](https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5_valid.txt) |

## Usage

### Raw URL
```
https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt
```

### Bash
```bash
curl -s https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt
```

### Python
```python
import requests

url = "https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt"
proxies = requests.get(url).text.strip().split("\n")
print(f"Loaded {len(proxies)} proxies")
```

### Python with PySocks
```python
import requests
import socks
import socket

# Fetch proxy list
url = "https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt"
proxy_list = requests.get(url).text.strip().split("\n")

# Use first proxy
proxy = proxy_list[0]
ip, port = proxy.split(":")

# Configure SOCKS5
socks.set_default_proxy(socks.SOCKS5, ip, int(port))
socket.socket = socks.socksocket

# Make request through proxy
response = requests.get("https://httpbin.org/ip")
print(response.json())
```

## Format

One proxy per line: `ip:port`

```
1.2.3.4:1080
5.6.7.8:1080
```

## Update Schedule

| UTC Time | Frequency |
|----------|-----------|
| 00:00 | Every 6 hours |
| 06:00 | |
| 12:00 | |
| 18:00 | |

## Disclaimer

These are public proxies collected from free sources.

**Use at your own risk.** No guarantees of:
- Uptime or availability
- Speed or latency
- Privacy or anonymity
- Security

For production use, consider paid proxy services.
