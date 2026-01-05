"""
Core types, enums, and structured results for the SOCKS5 proxy scanner.

This module provides the foundation for a production-ready scanner:
- Structured result objects
- Categorized error types
- Protocol constants
- Configuration dataclasses
"""

from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Optional, Dict, Any, List
import time


# =============================================================================
# Error Categories
# =============================================================================

class ErrorCategory(Enum):
    """Categorized error types for precise failure diagnosis."""

    NONE = auto()                    # No error
    TIMEOUT_CONNECT = auto()         # Connection timeout
    TIMEOUT_READ = auto()            # Read/recv timeout
    TIMEOUT_WRITE = auto()           # Write/send timeout
    DNS_FAILURE = auto()             # DNS resolution failed
    NETWORK_UNREACHABLE = auto()     # Network/host unreachable
    CONNECTION_REFUSED = auto()      # Connection actively refused
    CONNECTION_RESET = auto()        # Connection reset by peer
    HANDSHAKE_FAILED = auto()        # SOCKS5 handshake rejected
    PROTOCOL_MISMATCH = auto()       # Not SOCKS5 or wrong version
    AUTH_REQUIRED = auto()           # Authentication required but not provided
    AUTH_FAILED = auto()             # Authentication credentials rejected
    PROXY_ERROR = auto()             # Proxy returned error code
    HTTP_ERROR = auto()              # HTTP test failed
    INVALID_RESPONSE = auto()        # Malformed/invalid response
    UNKNOWN = auto()                 # Uncategorized error


class ProxyProtocol(Enum):
    """Supported proxy protocols."""

    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"  # SOCKS5 with remote DNS
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"
    HTTP = "http"
    HTTPS = "https"


class AnonymityLevel(Enum):
    """Proxy anonymity classification."""

    TRANSPARENT = "transparent"   # Reveals real IP
    ANONYMOUS = "anonymous"       # Hides IP but reveals proxy use
    ELITE = "elite"              # No trace of proxy
    UNKNOWN = "unknown"


class ProxyType(Enum):
    """IP ownership/type classification."""

    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    MOBILE = "mobile"
    ISP = "isp"
    UNKNOWN = "unknown"


# =============================================================================
# SOCKS5 Protocol Constants
# =============================================================================

class Socks5:
    """SOCKS5 protocol constants (RFC 1928)."""

    VERSION = 0x05

    # Authentication methods
    AUTH_NONE = 0x00
    AUTH_GSSAPI = 0x01
    AUTH_PASSWORD = 0x02
    AUTH_NO_ACCEPTABLE = 0xFF

    # Commands
    CMD_CONNECT = 0x01
    CMD_BIND = 0x02
    CMD_UDP_ASSOCIATE = 0x03

    # Address types
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04

    # Reply codes
    REPLY_SUCCESS = 0x00
    REPLY_GENERAL_FAILURE = 0x01
    REPLY_NOT_ALLOWED = 0x02
    REPLY_NETWORK_UNREACHABLE = 0x03
    REPLY_HOST_UNREACHABLE = 0x04
    REPLY_CONNECTION_REFUSED = 0x05
    REPLY_TTL_EXPIRED = 0x06
    REPLY_COMMAND_NOT_SUPPORTED = 0x07
    REPLY_ADDRESS_NOT_SUPPORTED = 0x08

    REPLY_MESSAGES = {
        0x00: "Success",
        0x01: "General SOCKS server failure",
        0x02: "Connection not allowed by ruleset",
        0x03: "Network unreachable",
        0x04: "Host unreachable",
        0x05: "Connection refused",
        0x06: "TTL expired",
        0x07: "Command not supported",
        0x08: "Address type not supported",
    }


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ScanConfig:
    """Scanner configuration with sensible defaults."""

    # Timeouts (seconds)
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    write_timeout: float = 5.0
    http_timeout: float = 10.0

    # Retry settings
    max_retries: int = 1
    retry_delay: float = 0.5

    # Concurrency
    max_concurrent: int = 100
    semaphore_limit: int = 200

    # Test targets
    test_host: str = "httpbin.org"
    test_port: int = 80
    test_url: str = "http://httpbin.org/ip"

    # Features
    check_anonymity: bool = False
    enrich_ip: bool = False
    verify_ssl: bool = False

    # Output
    verbose: bool = False
    debug: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Structured Results
# =============================================================================

@dataclass
class TimingInfo:
    """Detailed timing breakdown."""

    connect_ms: Optional[float] = None
    handshake_ms: Optional[float] = None
    tunnel_ms: Optional[float] = None
    http_ms: Optional[float] = None
    total_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class GeoInfo:
    """Geolocation and network information."""

    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    proxy_type: ProxyType = ProxyType.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for k, v in asdict(self).items():
            if v is not None:
                if isinstance(v, Enum):
                    result[k] = v.value
                else:
                    result[k] = v
        return result


@dataclass
class ProxyResult:
    """
    Structured result for a single proxy scan.

    This is the primary output format, designed for easy downstream parsing.
    """

    # Identity
    proxy: str                              # ip:port
    host: str = ""
    port: int = 0
    protocol: ProxyProtocol = ProxyProtocol.SOCKS5

    # Status
    reachable: bool = False                 # TCP connection succeeded
    socks5_valid: bool = False              # SOCKS5 handshake passed
    tunnel_works: bool = False              # CONNECT command succeeded
    http_works: bool = False                # HTTP request through proxy worked

    # Timing
    latency_ms: Optional[float] = None      # Total response time
    timing: Optional[TimingInfo] = None     # Detailed breakdown

    # Error info
    error: Optional[str] = None             # Human-readable error
    error_category: ErrorCategory = ErrorCategory.NONE
    error_stage: Optional[str] = None       # connect/handshake/tunnel/http

    # Extended info
    external_ip: Optional[str] = None       # IP seen by target
    auth_required: bool = False
    auth_methods: List[int] = field(default_factory=list)
    anonymity: AnonymityLevel = AnonymityLevel.UNKNOWN
    geo: Optional[GeoInfo] = None

    # Metadata
    timestamp: float = field(default_factory=time.time)
    scan_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        result = {
            "proxy": self.proxy,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "reachable": self.reachable,
            "socks5_valid": self.socks5_valid,
            "tunnel_works": self.tunnel_works,
            "http_works": self.http_works,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "error_category": self.error_category.name if self.error_category != ErrorCategory.NONE else None,
            "error_stage": self.error_stage,
            "external_ip": self.external_ip,
            "auth_required": self.auth_required,
            "anonymity": self.anonymity.value,
            "timestamp": self.timestamp,
        }

        if self.timing:
            result["timing"] = self.timing.to_dict()

        if self.geo:
            result["geo"] = self.geo.to_dict()

        # Remove None values for cleaner output
        return {k: v for k, v in result.items() if v is not None}

    @property
    def is_working(self) -> bool:
        """Quick check if proxy is fully functional."""
        return self.socks5_valid and self.tunnel_works

    @property
    def is_elite(self) -> bool:
        """Check if proxy provides elite anonymity."""
        return self.anonymity == AnonymityLevel.ELITE

    def __str__(self) -> str:
        status = "✓" if self.is_working else "✗"
        latency = f"{self.latency_ms:.0f}ms" if self.latency_ms else "?"
        return f"[{status}] {self.proxy} ({latency})"


@dataclass
class ScanResults:
    """Aggregated results from a scan operation."""

    results: List[ProxyResult] = field(default_factory=list)

    # Statistics
    total: int = 0
    reachable: int = 0
    valid: int = 0
    working: int = 0
    failed: int = 0

    # Timing
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None

    # Config used
    config: Optional[ScanConfig] = None

    def add(self, result: ProxyResult):
        """Add a result and update statistics."""
        self.results.append(result)
        self.total += 1

        if result.reachable:
            self.reachable += 1
        if result.socks5_valid:
            self.valid += 1
        if result.is_working:
            self.working += 1
        if result.error:
            self.failed += 1

    def finalize(self):
        """Mark scan as complete and calculate duration."""
        self.end_time = time.time()
        self.duration_seconds = self.end_time - self.start_time

    def get_working(self) -> List[ProxyResult]:
        """Get only working proxies."""
        return [r for r in self.results if r.is_working]

    def get_by_error(self, category: ErrorCategory) -> List[ProxyResult]:
        """Get results filtered by error category."""
        return [r for r in self.results if r.error_category == category]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "stats": {
                "total": self.total,
                "reachable": self.reachable,
                "valid": self.valid,
                "working": self.working,
                "failed": self.failed,
                "duration_seconds": self.duration_seconds,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_proxies_list(self, working_only: bool = True) -> List[str]:
        """Export as simple list of proxy strings."""
        if working_only:
            return [r.proxy for r in self.results if r.is_working]
        return [r.proxy for r in self.results]


# =============================================================================
# Exception Classes
# =============================================================================

class ScannerError(Exception):
    """Base exception for scanner errors."""

    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN):
        super().__init__(message)
        self.category = category


class TimeoutError(ScannerError):
    """Timeout during operation."""

    def __init__(self, message: str, stage: str = "unknown"):
        super().__init__(message, ErrorCategory.TIMEOUT_CONNECT)
        self.stage = stage


class ProtocolError(ScannerError):
    """Protocol-level error."""

    def __init__(self, message: str, reply_code: Optional[int] = None):
        super().__init__(message, ErrorCategory.PROTOCOL_MISMATCH)
        self.reply_code = reply_code


class AuthenticationError(ScannerError):
    """Authentication error."""

    def __init__(self, message: str, methods: List[int] = None):
        super().__init__(message, ErrorCategory.AUTH_FAILED)
        self.methods = methods or []
