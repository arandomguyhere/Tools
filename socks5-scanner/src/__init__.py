"""
SOCKS5 Proxy Scanner v2.0.0
===========================

A production-ready, high-performance SOCKS5 proxy scanner.

Features:
- Sync and async scanning modes
- Structured result objects with error categorization
- Configurable timeouts and retries
- Semaphore-controlled concurrency
- JSON/CSV/TXT export
- Pipeline integration hooks
- Logging infrastructure

Quick Start:
    # Sync scanning
    from socks5_scanner import SyncScanner, ScanConfig

    config = ScanConfig(max_concurrent=50)
    with SyncScanner(config) as scanner:
        result = scanner.scan_one("1.2.3.4:1080")
        print(result.to_dict())

    # Async scanning
    from socks5_scanner import AsyncScanner
    import asyncio

    async def scan():
        async with AsyncScanner() as scanner:
            results = await scanner.scan_many(proxies, concurrency=200)
            return results

    results = asyncio.run(scan())

CLI Usage:
    python -m src.cli scan proxies.txt --async -c 200
    python -m src.cli test 1.2.3.4:1080
"""

__version__ = "2.0.0"

# =============================================================================
# Core Types (always available)
# =============================================================================

from .core import (
    # Result types
    ProxyResult,
    ScanResults,
    ScanConfig,
    TimingInfo,
    GeoInfo,

    # Enums
    ErrorCategory,
    ProxyProtocol,
    ProxyType,
    AnonymityLevel,

    # Protocol constants
    Socks5,

    # Exceptions
    ScannerError,
    TimeoutError,
    ProtocolError,
    AuthenticationError,
)

# =============================================================================
# Sync Scanner
# =============================================================================

from .sync_scanner import SyncScanner

# =============================================================================
# Async Scanner (optional, requires aiohttp)
# =============================================================================

try:
    from .async_scanner_v2 import (
        AsyncScanner,
        scan_proxies as async_scan_proxies,
        run_scan,
        install_uvloop,
    )
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

# =============================================================================
# Logging
# =============================================================================

from .logger import (
    setup_logger,
    get_logger,
    set_level,
    enable_debug,
    quiet,
    ProgressReporter,
)

# =============================================================================
# Export & Integration
# =============================================================================

from .export import (
    # Exporters
    JSONExporter,
    CSVExporter,
    PlainTextExporter,
    DetailedTextExporter,
    export_results,

    # Hooks
    ResultHook,
    CallbackHook,
    FilterHook,
    StreamingHook,
    WebhookHook,

    # Pipeline
    ProxyPipeline,

    # Feeds
    ProxyFeed,
    FileFeed,
    URLFeed,
    MultiFeed,
)

# =============================================================================
# Legacy Compatibility
# =============================================================================

try:
    from .scanner import Socks5Scanner, ProxyScanner, quick_scan
    from .validator import ProxyValidator
    from .utils import (
        Color, parse_proxy, validate_ip, validate_port,
        IPEnricher, GeoLocator, get_geo_info, format_geo_info,
        format_asn_info, format_ownership_info, format_proxy_type
    )
    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False

try:
    from .hunter import ProxyHunter, HuntDatabase, ScentAnalyzer
    HUNTER_AVAILABLE = True
except ImportError:
    HUNTER_AVAILABLE = False

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",

    # Core types
    "ProxyResult",
    "ScanResults",
    "ScanConfig",
    "TimingInfo",
    "GeoInfo",
    "ErrorCategory",
    "ProxyProtocol",
    "ProxyType",
    "AnonymityLevel",
    "Socks5",

    # Exceptions
    "ScannerError",
    "TimeoutError",
    "ProtocolError",
    "AuthenticationError",

    # Scanners
    "SyncScanner",

    # Logging
    "setup_logger",
    "get_logger",
    "set_level",
    "enable_debug",
    "quiet",
    "ProgressReporter",

    # Export
    "JSONExporter",
    "CSVExporter",
    "PlainTextExporter",
    "DetailedTextExporter",
    "export_results",

    # Hooks
    "ResultHook",
    "CallbackHook",
    "FilterHook",
    "StreamingHook",
    "WebhookHook",
    "ProxyPipeline",

    # Feeds
    "ProxyFeed",
    "FileFeed",
    "URLFeed",
    "MultiFeed",

    # Feature flags
    "ASYNC_AVAILABLE",
    "LEGACY_AVAILABLE",
    "HUNTER_AVAILABLE",
]

# Add async exports if available
if ASYNC_AVAILABLE:
    __all__.extend([
        "AsyncScanner",
        "async_scan_proxies",
        "run_scan",
        "install_uvloop",
    ])

# Add legacy exports if available
if LEGACY_AVAILABLE:
    __all__.extend([
        "Socks5Scanner",
        "ProxyScanner",
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
    ])

if HUNTER_AVAILABLE:
    __all__.extend(["ProxyHunter", "HuntDatabase", "ScentAnalyzer"])
