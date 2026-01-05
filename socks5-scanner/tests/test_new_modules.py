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
    """Tests for proxy quality profiling module."""

    def test_import(self):
        from src.fingerprint import (
            ProxyQualityProfile, ProxyProfiler, RTTSample,
            QualityTier, ProxyType, profile_proxy
        )
        assert ProxyQualityProfile is not None
        assert ProxyProfiler is not None

    def test_quality_tier_enum(self):
        from src.fingerprint import QualityTier

        assert QualityTier.EXCELLENT.value == "excellent"
        assert QualityTier.GOOD.value == "good"
        assert QualityTier.FAIR.value == "fair"
        assert QualityTier.POOR.value == "poor"
        assert QualityTier.BAD.value == "bad"

    def test_proxy_type_enum(self):
        from src.fingerprint import ProxyType

        assert ProxyType.DATACENTER.value == "datacenter"
        assert ProxyType.RESIDENTIAL.value == "residential"
        assert ProxyType.MOBILE.value == "mobile"
        assert ProxyType.PROXY_CHAIN.value == "proxy_chain"

    def test_rtt_sample(self):
        from src.fingerprint import RTTSample

        sample = RTTSample(rtt_ms=100.5, timestamp=1234567890.0, stage="handshake")
        assert sample.rtt_ms == 100.5
        assert sample.stage == "handshake"

    def test_quality_profile_creation(self):
        from src.fingerprint import ProxyQualityProfile, QualityTier

        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        assert profile.target == "1.2.3.4:1080"
        assert profile.quality_tier == QualityTier.BAD
        assert profile.quality_score == 0.0
        assert len(profile.samples) == 0

    def test_quality_profile_add_sample(self):
        from src.fingerprint import ProxyQualityProfile

        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        profile.add_sample(100.0, "handshake")
        profile.add_sample(150.0, "data")

        assert len(profile.samples) == 2
        assert profile.samples[0].rtt_ms == 100.0
        assert profile.samples[0].stage == "handshake"

    def test_quality_profile_compute_statistics(self):
        from src.fingerprint import ProxyQualityProfile

        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        profile.add_sample(100.0, "handshake")
        profile.add_sample(120.0, "handshake")
        profile.add_sample(200.0, "data")
        profile.add_sample(220.0, "data")

        profile.compute_statistics()

        assert profile.min_rtt_ms == 100.0
        assert profile.max_rtt_ms == 220.0
        assert profile.mean_rtt_ms == 160.0
        assert profile.handshake_rtt_ms == 110.0  # (100 + 120) / 2
        assert profile.data_rtt_ms == 210.0  # (200 + 220) / 2

    def test_quality_profile_analyze_excellent(self):
        from src.fingerprint import ProxyQualityProfile, QualityTier, ProxyType

        # Create profile with excellent metrics (low latency, low jitter)
        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        profile.add_sample(50.0, "handshake")
        profile.add_sample(52.0, "handshake")
        profile.add_sample(55.0, "data")
        profile.add_sample(53.0, "data")

        profile.analyze()

        # Should have high quality score
        assert profile.quality_score >= 0.8
        assert profile.quality_tier == QualityTier.EXCELLENT
        assert profile.proxy_type == ProxyType.DATACENTER
        assert profile.estimated_hops == 1

    def test_quality_profile_analyze_poor(self):
        from src.fingerprint import ProxyQualityProfile, QualityTier

        # Create profile with poor metrics (high latency, high jitter)
        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        profile.add_sample(500.0, "handshake")
        profile.add_sample(800.0, "handshake")
        profile.add_sample(600.0, "data")
        profile.add_sample(900.0, "data")

        profile.analyze()

        # Should have low quality score
        assert profile.quality_score < 0.5
        assert profile.quality_tier in [QualityTier.FAIR, QualityTier.POOR, QualityTier.BAD]
        assert profile.estimated_hops >= 2

    def test_quality_profile_to_dict(self):
        from src.fingerprint import ProxyQualityProfile

        profile = ProxyQualityProfile(target="1.2.3.4:1080")
        profile.add_sample(100.0, "handshake")
        profile.analyze()

        d = profile.to_dict()
        assert d["target"] == "1.2.3.4:1080"
        assert d["sample_count"] == 1
        assert "quality_score" in d
        assert "quality_tier" in d
        assert "proxy_type" in d
        assert "estimated_hops" in d

    def test_profiler_creation(self):
        from src.fingerprint import ProxyProfiler

        profiler = ProxyProfiler(sample_count=3, timeout=2.0)
        assert profiler.sample_count == 3
        assert profiler.timeout == 2.0

    @pytest.mark.asyncio
    async def test_profile_proxy_function(self):
        from src.fingerprint import profile_proxy

        # Test with invalid proxy (should return empty profile)
        result = await profile_proxy("invalid", sample_count=1, timeout=1.0)
        assert result.target == "invalid"
        assert len(result.samples) == 0

    def test_backwards_compatibility_aliases(self):
        from src.fingerprint import RTTFingerprint, RTTFingerprinter, fingerprint_proxy
        from src.fingerprint import ProxyQualityProfile, ProxyProfiler, profile_proxy

        # Aliases should point to new classes
        assert RTTFingerprint is ProxyQualityProfile
        assert RTTFingerprinter is ProxyProfiler
        assert fingerprint_proxy is profile_proxy


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
