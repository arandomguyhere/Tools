"""
SOCKS5 Proxy Scanner
A multi-threaded tool for discovering and validating SOCKS5 proxies.

Features:
- Multi-source proxy collection (20+ static sources)
- GitHub repository hunting (discovers new sources)
- SOCKS5 protocol validation
- HTTP connectivity testing
- Async mode for high-performance scanning
- IP enrichment (ASN, geolocation, ownership)
- SQLite database for tracking source quality
"""

from .scanner import Socks5Scanner, quick_scan
from .validator import ProxyValidator
from .utils import (
    Color, parse_proxy, validate_ip, validate_port,
    IPEnricher, GeoLocator, get_geo_info, format_geo_info,
    format_asn_info, format_ownership_info, format_proxy_type
)

# Hunter components (GitHub discovery)
try:
    from .hunter import ProxyHunter, HuntDatabase, ScentAnalyzer
    HUNTER_AVAILABLE = True
except ImportError:
    HUNTER_AVAILABLE = False

# Async components (optional, requires aiohttp)
try:
    from .async_scanner import AsyncSocks5Scanner, AsyncProxyValidator, run_async_scan
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

__version__ = "1.3.0"
__all__ = [
    "Socks5Scanner",
    "ProxyValidator",
    "quick_scan",
    "Color",
    "parse_proxy",
    "validate_ip",
    "validate_port",
    "IPEnricher",
    "GeoLocator",
    "get_geo_info",
    "format_geo_info",
    "format_asn_info",
    "format_ownership_info",
    "format_proxy_type",
    "ASYNC_AVAILABLE",
    "HUNTER_AVAILABLE",
]

if HUNTER_AVAILABLE:
    __all__.extend(["ProxyHunter", "HuntDatabase", "ScentAnalyzer"])

if ASYNC_AVAILABLE:
    __all__.extend(["AsyncSocks5Scanner", "AsyncProxyValidator", "run_async_scan"])
