"""
Tests for core.py - Types, enums, and structured results.
"""

import pytest
import time
from src.core import (
    ProxyResult, ScanResults, ScanConfig, TimingInfo, GeoInfo,
    ErrorCategory, ProxyProtocol, ProxyType, AnonymityLevel,
    Socks5, ScannerError
)


class TestProxyResult:
    """Tests for ProxyResult dataclass."""

    def test_create_basic(self):
        result = ProxyResult(proxy="1.2.3.4:1080")
        assert result.proxy == "1.2.3.4:1080"
        assert result.reachable == False
        assert result.socks5_valid == False
        assert result.error is None

    def test_is_working_property(self):
        result = ProxyResult(proxy="1.2.3.4:1080")
        assert result.is_working == False

        result.socks5_valid = True
        assert result.is_working == False  # Still needs tunnel_works

        result.tunnel_works = True
        assert result.is_working == True

    def test_to_dict(self):
        result = ProxyResult(
            proxy="1.2.3.4:1080",
            host="1.2.3.4",
            port=1080,
            reachable=True,
            latency_ms=100.5
        )
        d = result.to_dict()

        assert d["proxy"] == "1.2.3.4:1080"
        assert d["reachable"] == True
        assert d["latency_ms"] == 100.5
        assert "error_category" not in d or d["error_category"] is None

    def test_with_error(self):
        result = ProxyResult(
            proxy="1.2.3.4:1080",
            error="Connection timeout",
            error_category=ErrorCategory.TIMEOUT_CONNECT,
            error_stage="connect"
        )
        d = result.to_dict()

        assert d["error"] == "Connection timeout"
        assert d["error_category"] == "TIMEOUT_CONNECT"
        assert d["error_stage"] == "connect"


class TestScanResults:
    """Tests for ScanResults aggregation."""

    def test_add_results(self):
        results = ScanResults()
        assert results.total == 0

        r1 = ProxyResult(proxy="1.2.3.4:1080", socks5_valid=True, tunnel_works=True)
        results.add(r1)

        assert results.total == 1
        assert results.valid == 1
        assert results.working == 1

    def test_statistics(self):
        results = ScanResults()

        # Add working proxy
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        # Add valid but not working
        results.add(ProxyResult(proxy="2.2.2.2:1080", socks5_valid=True, tunnel_works=False))
        # Add failed
        results.add(ProxyResult(proxy="3.3.3.3:1080", error="timeout"))

        assert results.total == 3
        assert results.valid == 2
        assert results.working == 1
        assert results.failed == 1

    def test_get_working(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        results.add(ProxyResult(proxy="2.2.2.2:1080", socks5_valid=False))

        working = results.get_working()
        assert len(working) == 1
        assert working[0].proxy == "1.1.1.1:1080"

    def test_to_dict(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        results.finalize()

        d = results.to_dict()
        assert "stats" in d
        assert "results" in d
        assert d["stats"]["total"] == 1
        assert d["stats"]["working"] == 1


class TestScanConfig:
    """Tests for ScanConfig."""

    def test_defaults(self):
        config = ScanConfig()
        assert config.connect_timeout == 5.0
        assert config.max_concurrent == 100
        assert config.max_retries == 1

    def test_custom_values(self):
        config = ScanConfig(
            connect_timeout=3.0,
            max_concurrent=50,
            test_url="http://example.com"
        )
        assert config.connect_timeout == 3.0
        assert config.max_concurrent == 50
        assert config.test_url == "http://example.com"


class TestErrorCategory:
    """Tests for ErrorCategory enum."""

    def test_all_categories_exist(self):
        categories = [
            ErrorCategory.NONE,
            ErrorCategory.TIMEOUT_CONNECT,
            ErrorCategory.TIMEOUT_READ,
            ErrorCategory.DNS_FAILURE,
            ErrorCategory.NETWORK_UNREACHABLE,
            ErrorCategory.CONNECTION_REFUSED,
            ErrorCategory.CONNECTION_RESET,
            ErrorCategory.HANDSHAKE_FAILED,
            ErrorCategory.PROTOCOL_MISMATCH,
            ErrorCategory.AUTH_REQUIRED,
            ErrorCategory.PROXY_ERROR,
            ErrorCategory.HTTP_ERROR,
        ]
        assert len(categories) >= 10


class TestSocks5Constants:
    """Tests for SOCKS5 protocol constants."""

    def test_version(self):
        assert Socks5.VERSION == 0x05

    def test_auth_methods(self):
        assert Socks5.AUTH_NONE == 0x00
        assert Socks5.AUTH_PASSWORD == 0x02
        assert Socks5.AUTH_NO_ACCEPTABLE == 0xFF

    def test_commands(self):
        assert Socks5.CMD_CONNECT == 0x01

    def test_reply_messages(self):
        assert Socks5.REPLY_SUCCESS == 0x00
        assert Socks5.REPLY_MESSAGES[0x00] == "Success"
