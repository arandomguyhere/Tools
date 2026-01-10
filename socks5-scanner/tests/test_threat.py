"""
Unit tests for the threat intelligence module.
"""

import ipaddress
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.threat import (
    ThreatChecker,
    ThreatLevel,
    ThreatResult,
    ThreatSource,
    THREAT_SOURCES,
)


class TestThreatResult:
    """Tests for ThreatResult dataclass."""

    def test_default_values(self):
        result = ThreatResult(ip="1.2.3.4")
        assert result.ip == "1.2.3.4"
        assert result.score == 0
        assert result.level == ThreatLevel.CLEAN
        assert result.sources == []
        assert result.flagged is False
        assert result.details == {}

    def test_to_dict(self):
        result = ThreatResult(
            ip="1.2.3.4",
            score=6,
            level=ThreatLevel.RISK,
            sources=["feodo", "sslbl"],
            flagged=True,
            details={"max_severity": 3},
        )
        d = result.to_dict()
        assert d["score"] == 6
        assert d["level"] == "risk"
        assert d["sources"] == ["feodo", "sslbl"]
        assert d["flagged"] is True
        assert d["details"]["max_severity"] == 3


class TestThreatChecker:
    """Tests for ThreatChecker class."""

    def test_is_valid_ip(self):
        checker = ThreatChecker()
        assert checker._is_valid_ip("1.2.3.4") is True
        assert checker._is_valid_ip("192.168.1.1") is True
        assert checker._is_valid_ip("0.0.0.0") is True
        assert checker._is_valid_ip("255.255.255.255") is True
        assert checker._is_valid_ip("invalid") is False
        assert checker._is_valid_ip("1.2.3") is False
        assert checker._is_valid_ip("1.2.3.4.5") is False
        assert checker._is_valid_ip("256.1.1.1") is False
        assert checker._is_valid_ip("1.2.3.a") is False

    def test_parse_ip_plain(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("1.2.3.4", "ip")
        assert ip == "1.2.3.4"
        assert network is None

    def test_parse_ip_with_port(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("1.2.3.4:1080", "ip")
        assert ip == "1.2.3.4"
        assert network is None

    def test_parse_ip_port_format(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("1.2.3.4:8080", "ip_port")
        assert ip == "1.2.3.4"
        assert network is None

    def test_parse_ip_cidr(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("192.168.0.0/24", "cidr")
        assert ip is None
        assert network is not None
        assert network == ipaddress.IPv4Network("192.168.0.0/24")

    def test_parse_ip_cidr_with_comment(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("192.168.0.0/24 ; SBL123456", "cidr")
        assert ip is None
        assert network == ipaddress.IPv4Network("192.168.0.0/24")

    def test_parse_ip_url(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("http://1.2.3.4/malware.exe", "url")
        assert ip == "1.2.3.4"
        assert network is None

    def test_parse_ip_url_https(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("https://5.6.7.8:443/bad", "url")
        assert ip == "5.6.7.8"
        assert network is None

    def test_parse_ip_skips_comments(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("# This is a comment", "ip")
        assert ip is None
        assert network is None

        ip, network = checker._parse_ip("; Another comment", "ip")
        assert ip is None
        assert network is None

    def test_parse_ip_skips_empty(self):
        checker = ThreatChecker()
        ip, network = checker._parse_ip("", "ip")
        assert ip is None
        assert network is None

        ip, network = checker._parse_ip("   ", "ip")
        assert ip is None
        assert network is None


class TestScoring:
    """Tests for threat scoring system."""

    def test_score_single_low_severity(self):
        checker = ThreatChecker()
        score = checker._calculate_score(["ciarmy"], 1)
        assert score == 2  # Low severity base

    def test_score_single_medium_severity(self):
        checker = ThreatChecker()
        score = checker._calculate_score(["spamhaus_drop"], 2)
        assert score == 4  # Medium severity base

    def test_score_single_high_severity(self):
        checker = ThreatChecker()
        score = checker._calculate_score(["feodo"], 3)
        assert score == 6  # High severity base

    def test_score_multiple_sources(self):
        checker = ThreatChecker()
        # 2 sources: base + 1 additional
        score = checker._calculate_score(["feodo", "sslbl"], 3)
        assert score == 7  # 6 base + 1

        # 3 sources: base + 2 additional
        score = checker._calculate_score(["feodo", "sslbl", "urlhaus"], 3)
        assert score == 8  # 6 base + 2

    def test_score_capped_at_10(self):
        checker = ThreatChecker()
        sources = ["a", "b", "c", "d", "e", "f"]  # 6 sources
        score = checker._calculate_score(sources, 3)
        assert score == 10  # Should cap at 10

    def test_level_clean(self):
        checker = ThreatChecker()
        assert checker._score_to_level(0) == ThreatLevel.CLEAN

    def test_level_low(self):
        checker = ThreatChecker()
        assert checker._score_to_level(1) == ThreatLevel.LOW
        assert checker._score_to_level(2) == ThreatLevel.LOW
        assert checker._score_to_level(3) == ThreatLevel.LOW
        assert checker._score_to_level(4) == ThreatLevel.LOW

    def test_level_risk(self):
        checker = ThreatChecker()
        assert checker._score_to_level(5) == ThreatLevel.RISK
        assert checker._score_to_level(6) == ThreatLevel.RISK
        assert checker._score_to_level(10) == ThreatLevel.RISK


class TestCIDRMatching:
    """Tests for CIDR range matching."""

    def _create_checker_with_test_source(self, severity=2):
        """Helper to create a checker with a test source."""
        test_source = ThreatSource(
            name="test", url="", description="Test", severity=severity
        )
        checker = ThreatChecker(sources=[test_source])
        return checker

    def test_ip_in_cidr_range(self):
        checker = self._create_checker_with_test_source(severity=2)
        # Manually add a CIDR network
        checker.networks["test"] = [ipaddress.IPv4Network("192.168.1.0/24")]
        checker.blocklists["test"] = set()

        # IP in range should match
        result = checker.check_ip("192.168.1.100")
        assert result.flagged is True
        assert "test" in result.sources

    def test_ip_outside_cidr_range(self):
        checker = self._create_checker_with_test_source(severity=2)
        checker.networks["test"] = [ipaddress.IPv4Network("192.168.1.0/24")]
        checker.blocklists["test"] = set()

        # IP outside range should not match
        result = checker.check_ip("192.168.2.100")
        assert result.flagged is False
        assert result.sources == []

    def test_direct_ip_match(self):
        checker = self._create_checker_with_test_source(severity=3)
        checker.blocklists["test"] = {"1.2.3.4"}
        checker.networks["test"] = []

        result = checker.check_ip("1.2.3.4")
        assert result.flagged is True
        assert "test" in result.sources
        assert result.level == ThreatLevel.RISK

    def test_no_match(self):
        checker = self._create_checker_with_test_source(severity=3)
        checker.blocklists["test"] = {"1.2.3.4"}
        checker.networks["test"] = []

        result = checker.check_ip("5.6.7.8")
        assert result.flagged is False
        assert result.level == ThreatLevel.CLEAN
        assert result.score == 0


class TestCheckMany:
    """Tests for batch IP checking."""

    def test_check_many(self):
        test_source = ThreatSource(
            name="test", url="", description="Test", severity=2
        )
        checker = ThreatChecker(sources=[test_source])
        checker.blocklists["test"] = {"1.2.3.4", "5.6.7.8"}
        checker.networks["test"] = []

        results = checker.check_many(["1.2.3.4", "5.6.7.8", "9.10.11.12"])

        assert "1.2.3.4" in results
        assert "5.6.7.8" in results
        assert "9.10.11.12" in results

        assert results["1.2.3.4"].flagged is True
        assert results["5.6.7.8"].flagged is True
        assert results["9.10.11.12"].flagged is False


class TestThreatSources:
    """Tests for threat source configuration."""

    def test_default_sources_exist(self):
        assert len(THREAT_SOURCES) > 0

    def test_all_sources_have_required_fields(self):
        for source in THREAT_SOURCES:
            assert source.name
            assert source.url
            assert source.description
            assert source.severity in [1, 2, 3]
            assert source.format in ["ip", "cidr", "ip_port", "url"]

    def test_source_names_unique(self):
        names = [s.name for s in THREAT_SOURCES]
        assert len(names) == len(set(names))


class TestInvalidInput:
    """Tests for handling invalid input."""

    def test_invalid_ip_returns_clean(self):
        test_source = ThreatSource(
            name="test", url="", description="Test", severity=3
        )
        checker = ThreatChecker(sources=[test_source])
        checker.blocklists["test"] = {"1.2.3.4"}
        checker.networks["test"] = []

        result = checker.check_ip("not-an-ip")
        assert result.flagged is False
        assert result.level == ThreatLevel.CLEAN

    def test_empty_ip_returns_clean(self):
        checker = ThreatChecker(sources=[])
        result = checker.check_ip("")
        assert result.flagged is False
