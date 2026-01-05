"""
SOCKS5 Proxy Scanner
A multi-threaded tool for discovering and validating SOCKS5 proxies.

Features:
- Multi-source proxy collection (20+ sources)
- SOCKS5 protocol validation
- HTTP connectivity testing
- Async mode for high-performance scanning
- Geolocation lookup
"""

from .scanner import Socks5Scanner, quick_scan
from .validator import ProxyValidator
from .utils import (
    Color, parse_proxy, validate_ip, validate_port,
    GeoLocator, get_geo_info, format_geo_info
)

# Async components (optional, requires aiohttp)
try:
    from .async_scanner import AsyncSocks5Scanner, AsyncProxyValidator, run_async_scan
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

__version__ = "1.1.0"
__all__ = [
    "Socks5Scanner",
    "ProxyValidator",
    "quick_scan",
    "Color",
    "parse_proxy",
    "validate_ip",
    "validate_port",
    "GeoLocator",
    "get_geo_info",
    "format_geo_info",
    "ASYNC_AVAILABLE",
]

if ASYNC_AVAILABLE:
    __all__.extend(["AsyncSocks5Scanner", "AsyncProxyValidator", "run_async_scan"])
