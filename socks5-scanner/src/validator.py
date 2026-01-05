"""
Proxy Validator - LEGACY COMPATIBILITY WRAPPER.

This module is deprecated. Use src.sync_scanner.SyncScanner instead.

This wrapper maintains backwards compatibility with existing code while
delegating to the new sync_scanner module.
"""

import warnings
from typing import Dict, List, Optional, Tuple, Any

from .sync_scanner import SyncScanner
from .core import ScanConfig, ProxyResult, ErrorCategory
from .utils import IPEnricher

# Emit deprecation warning on import
warnings.warn(
    "src.validator is deprecated. Use src.sync_scanner.SyncScanner instead.",
    DeprecationWarning,
    stacklevel=2
)


class ProxyValidator:
    """
    DEPRECATED: Use SyncScanner instead.

    This class maintains backwards compatibility with the old API.
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize with config dict for backwards compatibility."""
        config = config or {}
        self.timeout = config.get('timeout', 5)
        self.test_urls = config.get('test_urls', [
            "http://httpbin.org/ip",
            "http://icanhazip.com",
        ])
        self.verify_ssl = config.get('verify_ssl', False)
        self.enricher = IPEnricher() if config.get('enrich', False) else None

        # Create underlying scanner with converted config
        scan_config = ScanConfig(
            connect_timeout=float(self.timeout),
            read_timeout=float(self.timeout),
            test_url=self.test_urls[0] if self.test_urls else "http://httpbin.org/ip"
        )
        self._scanner = SyncScanner(scan_config)

    def test_socks5_handshake(
        self,
        ip: str,
        port: int,
        timeout: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Test SOCKS5 proxy handshake.

        Returns:
            Tuple of (success: bool, message: str)
        """
        proxy = f"{ip}:{port}"
        result = self._scanner.scan_one(proxy)

        if result.socks5_valid:
            if result.auth_required:
                return True, "OK (auth required)"
            return True, "OK (no auth)"
        elif result.error:
            return False, result.error
        else:
            return False, "Unknown error"

    def test_socks5_connect(
        self,
        ip: str,
        port: int,
        target_host: str = "httpbin.org",
        target_port: int = 80,
        timeout: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Test SOCKS5 proxy by connecting to a target through it.

        Returns:
            Tuple of (success: bool, message: str)
        """
        proxy = f"{ip}:{port}"
        result = self._scanner.scan_one(proxy)

        if result.tunnel_works:
            return True, "Connection successful"
        elif result.error:
            return False, result.error
        else:
            return False, "Tunnel failed"

    def validate_proxy(self, proxy: str, timeout: Optional[int] = None) -> Dict:
        """
        Full validation of a SOCKS5 proxy.

        Returns dict with validation results for backwards compatibility.
        """
        result = self._scanner.scan_one(proxy)

        # Convert to old dict format
        return {
            'proxy': result.proxy,
            'host': result.host,
            'port': result.port,
            'reachable': result.reachable,
            'socks5_valid': result.socks5_valid,
            'tunnel_works': result.tunnel_works,
            'auth_required': result.auth_required,
            'latency_ms': result.latency_ms,
            'error': result.error,
            'external_ip': result.external_ip,
            'working': result.is_working,
        }

    def validate_many(
        self,
        proxies: List[str],
        max_workers: int = 20,
        callback=None
    ) -> List[Dict]:
        """
        Validate multiple proxies in parallel.

        Returns list of validation results for backwards compatibility.
        """
        results = self._scanner.scan_many(proxies, max_workers=max_workers)

        validated = []
        for result in results.all_results:
            validated.append({
                'proxy': result.proxy,
                'host': result.host,
                'port': result.port,
                'reachable': result.reachable,
                'socks5_valid': result.socks5_valid,
                'tunnel_works': result.tunnel_works,
                'auth_required': result.auth_required,
                'latency_ms': result.latency_ms,
                'error': result.error,
                'external_ip': result.external_ip,
                'working': result.is_working,
            })
            if callback:
                callback(validated[-1])

        return validated


# Convenience function for backwards compatibility
def validate_proxy(proxy: str, timeout: int = 5) -> Dict:
    """Validate a single proxy. DEPRECATED."""
    validator = ProxyValidator({'timeout': timeout})
    return validator.validate_proxy(proxy)
