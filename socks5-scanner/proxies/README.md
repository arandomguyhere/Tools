# SOCKS5 Proxy List

Auto-updated every 6 hours via GitHub Actions.

## Status

- **Last updated:** Never (awaiting first run)
- **Working proxies:** 0

## Files

| File | Description |
|------|-------------|
| `socks5.txt` | Working proxies (tunnel verified) |
| `socks5_valid.txt` | Valid SOCKS5 handshake (may not tunnel) |

## Usage

### Raw URL (for tools)
```
https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt
```

### curl
```bash
curl -s https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt
```

### Python
```python
import requests
proxies = requests.get(
    "https://raw.githubusercontent.com/arandomguyhere/Tools/main/socks5-scanner/proxies/socks5.txt"
).text.strip().split("\n")
```

## Format

One proxy per line: `ip:port`

```
1.2.3.4:1080
5.6.7.8:1080
```

## Disclaimer

These are public proxies collected from free sources. Use at your own risk. No guarantees of uptime, speed, or anonymity.
