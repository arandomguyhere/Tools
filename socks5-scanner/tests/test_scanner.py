"""
Tests for sync_scanner.py and async_scanner_v2.py
"""

import pytest
from src.sync_scanner import SyncScanner
from src.core import ScanConfig, ErrorCategory


class TestSyncScanner:
    """Tests for SyncScanner."""

    def test_create_scanner(self):
        scanner = SyncScanner()
        assert scanner.config is not None

    def test_create_with_config(self):
        config = ScanConfig(connect_timeout=2.0)
        scanner = SyncScanner(config)
        assert scanner.config.connect_timeout == 2.0

    def test_parse_proxy_ip_port(self):
        scanner = SyncScanner()
        host, port = scanner._parse_proxy("1.2.3.4:1080")
        assert host == "1.2.3.4"
        assert port == 1080

    def test_parse_proxy_socks5_url(self):
        scanner = SyncScanner()
        host, port = scanner._parse_proxy("socks5://5.6.7.8:8080")
        assert host == "5.6.7.8"
        assert port == 8080

    def test_parse_proxy_socks5h_url(self):
        scanner = SyncScanner()
        host, port = scanner._parse_proxy("socks5h://10.0.0.1:1080")
        assert host == "10.0.0.1"
        assert port == 1080

    def test_parse_proxy_with_auth(self):
        scanner = SyncScanner()
        host, port = scanner._parse_proxy("user:pass@1.2.3.4:1080")
        assert host == "1.2.3.4"
        assert port == 1080

    def test_parse_proxy_invalid(self):
        scanner = SyncScanner()

        # No port
        host, port = scanner._parse_proxy("1.2.3.4")
        assert host is None
        assert port is None

        # Invalid format
        host, port = scanner._parse_proxy("invalid")
        assert host is None

        # Invalid port
        host, port = scanner._parse_proxy("1.2.3.4:99999")
        assert host is None

    def test_scan_one_invalid_proxy(self):
        config = ScanConfig(connect_timeout=1.0, max_retries=0)
        scanner = SyncScanner(config)

        result = scanner.scan_one("invalid_proxy")
        assert result.error is not None
        assert result.error_category == ErrorCategory.INVALID_RESPONSE

    def test_scan_one_unreachable(self):
        config = ScanConfig(connect_timeout=1.0, max_retries=0)
        scanner = SyncScanner(config)

        # TEST-NET-1 (192.0.2.0/24) - guaranteed to not respond
        result = scanner.scan_one("192.0.2.1:1080")
        assert result.reachable == False
        assert result.error_category == ErrorCategory.TIMEOUT_CONNECT

    def test_context_manager(self):
        with SyncScanner() as scanner:
            assert scanner is not None

    def test_scan_many_empty_list(self):
        scanner = SyncScanner()
        results = scanner.scan_many([])
        assert results.total == 0


class TestAsyncScanner:
    """Tests for AsyncScanner."""

    def test_import(self):
        from src.async_scanner_v2 import AsyncScanner
        assert AsyncScanner is not None

    def test_parse_proxy(self):
        from src.async_scanner_v2 import AsyncScanner

        scanner = AsyncScanner()
        host, port = scanner._parse_proxy("1.2.3.4:1080")
        assert host == "1.2.3.4"
        assert port == 1080

    @pytest.mark.asyncio
    async def test_scan_one_unreachable(self):
        from src.async_scanner_v2 import AsyncScanner
        from src.core import ScanConfig

        config = ScanConfig(connect_timeout=1.0, max_retries=0)
        async with AsyncScanner(config) as scanner:
            result = await scanner.scan_one("192.0.2.1:1080")
            assert result.reachable == False
            assert result.error_category == ErrorCategory.TIMEOUT_CONNECT

    @pytest.mark.asyncio
    async def test_scan_many_empty(self):
        from src.async_scanner_v2 import AsyncScanner

        async with AsyncScanner() as scanner:
            results = await scanner.scan_many([])
            assert results.total == 0
