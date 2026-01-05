"""
Tests for new modules: anonymity, geoip, fingerprint.
"""

import pytest
import asyncio


class TestAnonymityModule:
    """Tests for anonymity detection module."""

    def test_import(self):
        from src.anonymity import AnonymityChecker, AnonymityLevel, AnonymityResult
        assert AnonymityChecker is not None
        assert AnonymityLevel is not None

    def test_anonymity_levels(self):
        from src.anonymity import AnonymityLevel

        assert AnonymityLevel.TRANSPARENT.value == "transparent"
        assert AnonymityLevel.ANONYMOUS.value == "anonymous"
        assert AnonymityLevel.ELITE.value == "elite"

    def test_anonymity_result(self):
        from src.anonymity import AnonymityResult, AnonymityLevel

        result = AnonymityResult(
            level=AnonymityLevel.ELITE,
            real_ip_leaked=False,
            proxy_detected=False
        )

        assert result.level == AnonymityLevel.ELITE
        assert result.real_ip_leaked is False
        assert result.proxy_detected is False

    def test_anonymity_result_to_dict(self):
        from src.anonymity import AnonymityResult, AnonymityLevel

        result = AnonymityResult(
            level=AnonymityLevel.ANONYMOUS,
            real_ip_leaked=False,
            proxy_detected=True,
            proxy_headers=["Via"]
        )

        d = result.to_dict()
        assert d["level"] == "anonymous"
        assert d["proxy_detected"] is True

    def test_leak_headers_constant(self):
        from src.anonymity import LEAK_HEADERS, PROXY_HEADERS

        assert "X-Forwarded-For" in LEAK_HEADERS
        assert "X-Real-IP" in LEAK_HEADERS
        assert "Via" in PROXY_HEADERS

    def test_checker_creation(self):
        from src.anonymity import AnonymityChecker

        checker = AnonymityChecker(timeout=3.0)
        assert checker.timeout == 3.0


class TestGeoIPModule:
    """Tests for GeoIP module."""

    def test_import(self):
        from src.geoip import GeoIPResult, OnlineGeoIP, get_geoip
        assert GeoIPResult is not None
        assert OnlineGeoIP is not None
        assert get_geoip is not None

    def test_geoip_result(self):
        from src.geoip import GeoIPResult

        result = GeoIPResult(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            city="Mountain View",
            asn=15169,
            asn_org="Google LLC"
        )

        assert result.ip == "8.8.8.8"
        assert result.country_code == "US"
        assert result.asn == 15169

    def test_geoip_result_asn_str(self):
        from src.geoip import GeoIPResult

        result = GeoIPResult(ip="1.1.1.1", asn=13335)
        assert result.asn_str == "AS13335"

        result_no_asn = GeoIPResult(ip="1.1.1.1")
        assert result_no_asn.asn_str == ""

    def test_geoip_result_location_str(self):
        from src.geoip import GeoIPResult

        result = GeoIPResult(ip="8.8.8.8", city="Mountain View", country_code="US")
        assert result.location_str == "Mountain View, US"

        result_no_city = GeoIPResult(ip="8.8.8.8", country_code="US")
        assert result_no_city.location_str == "US"

        result_empty = GeoIPResult(ip="8.8.8.8")
        assert result_empty.location_str == "Unknown"

    def test_geoip_result_to_dict(self):
        from src.geoip import GeoIPResult

        result = GeoIPResult(
            ip="1.1.1.1",
            country="Australia",
            country_code="AU",
            latitude=-33.8688,
            longitude=151.2093
        )

        d = result.to_dict()
        assert d["ip"] == "1.1.1.1"
        assert d["country_code"] == "AU"
        assert "latitude" in d
        # None values should be excluded
        assert "city" not in d or d.get("city") is None

    def test_online_geoip_creation(self):
        from src.geoip import OnlineGeoIP

        geoip = OnlineGeoIP(timeout=5)
        assert geoip.timeout == 5
        assert len(geoip._cache) == 0

    def test_get_geoip_function(self):
        from src.geoip import get_geoip, OnlineGeoIP

        # Without GeoIP2 databases, should return OnlineGeoIP
        provider = get_geoip()
        # Should be either GeoIPDatabase or OnlineGeoIP
        assert provider is not None


class TestFingerprintModule:
    """Tests for RTT fingerprinting module."""

    def test_import(self):
        from src.fingerprint import (
            RTTFingerprint, RTTFingerprinter, RTTSample,
            ProxyLikelihood, fingerprint_proxy
        )
        assert RTTFingerprint is not None
        assert RTTFingerprinter is not None

    def test_proxy_likelihood_enum(self):
        from src.fingerprint import ProxyLikelihood

        assert ProxyLikelihood.UNLIKELY.value == "unlikely"
        assert ProxyLikelihood.POSSIBLE.value == "possible"
        assert ProxyLikelihood.LIKELY.value == "likely"
        assert ProxyLikelihood.VERY_LIKELY.value == "very_likely"

    def test_rtt_sample(self):
        from src.fingerprint import RTTSample

        sample = RTTSample(rtt_ms=100.5, timestamp=1234567890.0, stage="handshake")
        assert sample.rtt_ms == 100.5
        assert sample.stage == "handshake"

    def test_rtt_fingerprint_creation(self):
        from src.fingerprint import RTTFingerprint, ProxyLikelihood

        fp = RTTFingerprint(target="1.2.3.4:1080")
        assert fp.target == "1.2.3.4:1080"
        assert fp.proxy_likelihood == ProxyLikelihood.UNLIKELY
        assert fp.confidence == 0.0
        assert len(fp.samples) == 0

    def test_rtt_fingerprint_add_sample(self):
        from src.fingerprint import RTTFingerprint

        fp = RTTFingerprint(target="1.2.3.4:1080")
        fp.add_sample(100.0, "handshake")
        fp.add_sample(150.0, "data")

        assert len(fp.samples) == 2
        assert fp.samples[0].rtt_ms == 100.0
        assert fp.samples[0].stage == "handshake"

    def test_rtt_fingerprint_compute_statistics(self):
        from src.fingerprint import RTTFingerprint

        fp = RTTFingerprint(target="1.2.3.4:1080")
        fp.add_sample(100.0, "handshake")
        fp.add_sample(120.0, "handshake")
        fp.add_sample(200.0, "data")
        fp.add_sample(220.0, "data")

        fp.compute_statistics()

        assert fp.min_rtt_ms == 100.0
        assert fp.max_rtt_ms == 220.0
        assert fp.mean_rtt_ms == 160.0
        assert fp.handshake_rtt_ms == 110.0  # (100 + 120) / 2
        assert fp.data_rtt_ms == 210.0  # (200 + 220) / 2

    def test_rtt_fingerprint_analyze(self):
        from src.fingerprint import RTTFingerprint, ProxyLikelihood

        # Create fingerprint with high variance (proxy indicator)
        fp = RTTFingerprint(target="1.2.3.4:1080")
        fp.add_sample(50.0, "handshake")
        fp.add_sample(100.0, "handshake")
        fp.add_sample(300.0, "data")
        fp.add_sample(400.0, "data")

        fp.analyze()

        # Should detect proxy indicators due to RTT inflation
        assert fp.confidence > 0
        assert len(fp.indicators) > 0

    def test_rtt_fingerprint_to_dict(self):
        from src.fingerprint import RTTFingerprint

        fp = RTTFingerprint(target="1.2.3.4:1080")
        fp.add_sample(100.0, "handshake")
        fp.analyze()

        d = fp.to_dict()
        assert d["target"] == "1.2.3.4:1080"
        assert d["sample_count"] == 1
        assert "proxy_likelihood" in d
        assert "confidence" in d

    def test_fingerprinter_creation(self):
        from src.fingerprint import RTTFingerprinter

        fp = RTTFingerprinter(sample_count=3, timeout=2.0)
        assert fp.sample_count == 3
        assert fp.timeout == 2.0

    @pytest.mark.asyncio
    async def test_fingerprint_proxy_function(self):
        from src.fingerprint import fingerprint_proxy

        # Test with invalid proxy (should return empty fingerprint)
        result = await fingerprint_proxy("invalid", sample_count=1, timeout=1.0)
        assert result.target == "invalid"
        assert len(result.samples) == 0


class TestTCPTimestampAnalyzer:
    """Tests for TCP timestamp analyzer."""

    def test_creation(self):
        from src.fingerprint import TCPTimestampAnalyzer

        analyzer = TCPTimestampAnalyzer()
        assert len(analyzer.samples) == 0

    def test_add_sample(self):
        from src.fingerprint import TCPTimestampAnalyzer

        analyzer = TCPTimestampAnalyzer()
        analyzer.add_sample(12345, 67890)
        analyzer.add_sample(12350, 67895)

        assert len(analyzer.samples) == 2

    def test_analyze_insufficient_samples(self):
        from src.fingerprint import TCPTimestampAnalyzer

        analyzer = TCPTimestampAnalyzer()
        analyzer.add_sample(12345, 67890)

        result = analyzer.analyze()
        assert result["status"] == "insufficient_samples"

    def test_analyze_normal_timestamps(self):
        from src.fingerprint import TCPTimestampAnalyzer

        analyzer = TCPTimestampAnalyzer()
        analyzer.add_sample(12345, 67890)
        analyzer.add_sample(12350, 67895)
        analyzer.add_sample(12355, 67900)

        result = analyzer.analyze()
        assert result["status"] == "analyzed"
        assert result["sample_count"] == 3

    def test_analyze_timestamp_regression(self):
        from src.fingerprint import TCPTimestampAnalyzer

        analyzer = TCPTimestampAnalyzer()
        analyzer.add_sample(12345, 67890)
        analyzer.add_sample(12340, 67895)  # Regression!
        analyzer.add_sample(12335, 67900)

        result = analyzer.analyze()
        assert "Timestamp regression detected" in result["indicators"]
        assert result["proxy_suspected"] is True


class TestLegacyWrappers:
    """Tests for legacy compatibility wrappers."""

    def test_validator_import(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from src.validator import ProxyValidator
            assert ProxyValidator is not None

    def test_async_scanner_import(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from src.async_scanner import AsyncSocks5Scanner
            assert AsyncSocks5Scanner is not None

    def test_validator_creation(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from src.validator import ProxyValidator

            validator = ProxyValidator({'timeout': 3})
            assert validator.timeout == 3

    def test_async_scanner_creation(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from src.async_scanner import AsyncSocks5Scanner

            scanner = AsyncSocks5Scanner({'timeout': 10})
            assert scanner.timeout == 10
