"""
Proxy Quality Fingerprinting - Assess proxy quality via timing analysis.

Measures:
- Latency stability and jitter
- Estimated hop count (proxy chain depth)
- Proxy type classification (residential vs datacenter)
- Overall quality scoring

This helps identify:
- High-quality low-latency proxies
- Unstable/unreliable proxies
- Proxy chains (multiple hops)
- Residential vs datacenter proxies
"""

import asyncio
import logging
import statistics
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    """Proxy type based on RTT characteristics."""
    UNKNOWN = "unknown"
    DATACENTER = "datacenter"      # Low, stable RTT
    RESIDENTIAL = "residential"    # Variable RTT, higher jitter
    MOBILE = "mobile"              # High jitter, variable latency
    PROXY_CHAIN = "proxy_chain"    # Very high latency, multiple hops


class QualityTier(Enum):
    """Proxy quality tier."""
    EXCELLENT = "excellent"   # Score >= 0.8
    GOOD = "good"             # Score >= 0.6
    FAIR = "fair"             # Score >= 0.4
    POOR = "poor"             # Score >= 0.2
    BAD = "bad"               # Score < 0.2


@dataclass
class RTTSample:
    """Single RTT measurement."""
    rtt_ms: float
    timestamp: float
    stage: str = "unknown"  # handshake, data, close


@dataclass
class ProxyQualityProfile:
    """Quality profile for a proxy based on RTT analysis."""

    target: str
    samples: List[RTTSample] = field(default_factory=list)

    # Computed statistics
    min_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    mean_rtt_ms: Optional[float] = None
    median_rtt_ms: Optional[float] = None
    stddev_rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None

    # Handshake vs data phase comparison
    handshake_rtt_ms: Optional[float] = None
    data_rtt_ms: Optional[float] = None

    # Quality metrics
    quality_score: float = 0.0
    quality_tier: QualityTier = QualityTier.BAD
    stability_score: float = 0.0
    estimated_hops: int = 1
    proxy_type: ProxyType = ProxyType.UNKNOWN

    # Details
    quality_factors: List[str] = field(default_factory=list)

    def add_sample(self, rtt_ms: float, stage: str = "unknown"):
        """Add RTT sample."""
        self.samples.append(RTTSample(
            rtt_ms=rtt_ms,
            timestamp=time.time(),
            stage=stage
        ))

    def compute_statistics(self):
        """Compute statistics from samples."""
        if not self.samples:
            return

        rtts = [s.rtt_ms for s in self.samples]

        self.min_rtt_ms = min(rtts)
        self.max_rtt_ms = max(rtts)
        self.mean_rtt_ms = statistics.mean(rtts)
        self.median_rtt_ms = statistics.median(rtts)

        if len(rtts) >= 2:
            self.stddev_rtt_ms = statistics.stdev(rtts)
            # Jitter: average deviation from mean
            self.jitter_ms = statistics.mean([abs(r - self.mean_rtt_ms) for r in rtts])

        # Separate handshake and data RTTs
        handshake_rtts = [s.rtt_ms for s in self.samples if s.stage == "handshake"]
        data_rtts = [s.rtt_ms for s in self.samples if s.stage == "data"]

        if handshake_rtts:
            self.handshake_rtt_ms = statistics.mean(handshake_rtts)
        if data_rtts:
            self.data_rtt_ms = statistics.mean(data_rtts)

    def analyze(self) -> 'ProxyQualityProfile':
        """Analyze RTT patterns to assess proxy quality."""
        self.compute_statistics()
        self.quality_factors = []

        if not self.samples or not self.mean_rtt_ms:
            return self

        # Calculate quality score (0-1, higher is better)
        score = 1.0

        # Factor 1: Latency penalty (lower is better)
        # < 100ms: excellent, 100-300ms: good, 300-500ms: fair, >500ms: poor
        if self.mean_rtt_ms < 100:
            self.quality_factors.append(f"Excellent latency: {self.mean_rtt_ms:.0f}ms")
        elif self.mean_rtt_ms < 300:
            score -= 0.15
            self.quality_factors.append(f"Good latency: {self.mean_rtt_ms:.0f}ms")
        elif self.mean_rtt_ms < 500:
            score -= 0.3
            self.quality_factors.append(f"Fair latency: {self.mean_rtt_ms:.0f}ms")
        else:
            score -= 0.5
            self.quality_factors.append(f"High latency: {self.mean_rtt_ms:.0f}ms")

        # Factor 2: Stability (jitter penalty)
        if self.jitter_ms and self.mean_rtt_ms > 0:
            jitter_ratio = self.jitter_ms / self.mean_rtt_ms
            self.stability_score = max(0, 1 - jitter_ratio * 2)

            if jitter_ratio < 0.1:
                self.quality_factors.append(f"Very stable (jitter: {self.jitter_ms:.1f}ms)")
            elif jitter_ratio < 0.2:
                score -= 0.1
                self.quality_factors.append(f"Stable (jitter: {self.jitter_ms:.1f}ms)")
            elif jitter_ratio < 0.3:
                score -= 0.2
                self.quality_factors.append(f"Moderate jitter: {self.jitter_ms:.1f}ms")
            else:
                score -= 0.35
                self.quality_factors.append(f"High jitter: {self.jitter_ms:.1f}ms")

        # Factor 3: Consistency (stddev penalty)
        if self.stddev_rtt_ms and self.mean_rtt_ms > 0:
            cv = self.stddev_rtt_ms / self.mean_rtt_ms  # coefficient of variation
            if cv > 0.5:
                score -= 0.15
                self.quality_factors.append(f"Inconsistent: CV={cv:.2f}")

        # Estimate hop count based on latency
        self._estimate_hops()

        # Classify proxy type
        self._classify_type()

        # Final score
        self.quality_score = max(0, min(1, score))

        # Determine tier
        if self.quality_score >= 0.8:
            self.quality_tier = QualityTier.EXCELLENT
        elif self.quality_score >= 0.6:
            self.quality_tier = QualityTier.GOOD
        elif self.quality_score >= 0.4:
            self.quality_tier = QualityTier.FAIR
        elif self.quality_score >= 0.2:
            self.quality_tier = QualityTier.POOR
        else:
            self.quality_tier = QualityTier.BAD

        return self

    def _estimate_hops(self):
        """Estimate number of proxy hops based on latency."""
        if not self.mean_rtt_ms:
            self.estimated_hops = 1
            return

        # Rough estimation based on typical network latency
        # Single hop: < 150ms, 2 hops: 150-400ms, 3+ hops: > 400ms
        if self.mean_rtt_ms < 150:
            self.estimated_hops = 1
        elif self.mean_rtt_ms < 400:
            self.estimated_hops = 2
            self.quality_factors.append("Possible 2-hop chain")
        elif self.mean_rtt_ms < 700:
            self.estimated_hops = 3
            self.quality_factors.append("Likely 3-hop chain")
        else:
            self.estimated_hops = 4
            self.quality_factors.append("Multi-hop chain (4+)")

    def _classify_type(self):
        """Classify proxy type based on RTT patterns."""
        if not self.mean_rtt_ms or not self.jitter_ms:
            self.proxy_type = ProxyType.UNKNOWN
            return

        jitter_ratio = self.jitter_ms / self.mean_rtt_ms if self.mean_rtt_ms > 0 else 0

        # Datacenter: Low latency, very stable
        if self.mean_rtt_ms < 200 and jitter_ratio < 0.15:
            self.proxy_type = ProxyType.DATACENTER
            self.quality_factors.append("Type: Datacenter (stable, low latency)")

        # Residential: Moderate latency, some jitter
        elif jitter_ratio < 0.3 and self.mean_rtt_ms < 500:
            self.proxy_type = ProxyType.RESIDENTIAL
            self.quality_factors.append("Type: Residential (moderate jitter)")

        # Mobile: High jitter
        elif jitter_ratio > 0.3:
            self.proxy_type = ProxyType.MOBILE
            self.quality_factors.append("Type: Mobile/unstable (high jitter)")

        # Proxy chain: Very high latency
        elif self.mean_rtt_ms > 500:
            self.proxy_type = ProxyType.PROXY_CHAIN
            self.quality_factors.append("Type: Proxy chain (high latency)")

        else:
            self.proxy_type = ProxyType.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "sample_count": len(self.samples),
            "min_rtt_ms": self.min_rtt_ms,
            "max_rtt_ms": self.max_rtt_ms,
            "mean_rtt_ms": self.mean_rtt_ms,
            "median_rtt_ms": self.median_rtt_ms,
            "stddev_rtt_ms": self.stddev_rtt_ms,
            "jitter_ms": self.jitter_ms,
            "handshake_rtt_ms": self.handshake_rtt_ms,
            "data_rtt_ms": self.data_rtt_ms,
            "quality_score": self.quality_score,
            "quality_tier": self.quality_tier.value,
            "stability_score": self.stability_score,
            "estimated_hops": self.estimated_hops,
            "proxy_type": self.proxy_type.value,
            "quality_factors": self.quality_factors,
        }


class ProxyProfiler:
    """
    Profiles proxy quality via RTT analysis.

    Usage:
        profiler = ProxyProfiler()
        profile = await profiler.profile("1.2.3.4", 1080)
        print(f"Quality: {profile.quality_tier.value}, Score: {profile.quality_score:.2f}")
    """

    def __init__(
        self,
        sample_count: int = 5,
        timeout: float = 5.0,
        test_host: str = "httpbin.org",
        test_port: int = 80
    ):
        """
        Initialize profiler.

        Args:
            sample_count: Number of RTT samples to collect
            timeout: Timeout per sample in seconds
            test_host: Host to test connectivity through proxy
            test_port: Port to test connectivity
        """
        self.sample_count = sample_count
        self.timeout = timeout
        self.test_host = test_host
        self.test_port = test_port

    async def profile(self, host: str, port: int) -> ProxyQualityProfile:
        """
        Profile a proxy's quality via RTT analysis.

        Args:
            host: Proxy host
            port: Proxy port

        Returns:
            ProxyQualityProfile with quality metrics
        """
        profile = ProxyQualityProfile(target=f"{host}:{port}")

        try:
            await self._collect_samples(profile, host, port)
        except Exception as e:
            logger.debug(f"Profiling failed for {host}:{port}: {e}")

        return profile.analyze()

    async def _collect_samples(
        self,
        profile: ProxyQualityProfile,
        proxy_host: str,
        proxy_port: int
    ):
        """Collect RTT samples through SOCKS5 proxy."""
        for i in range(self.sample_count):
            try:
                # Measure TCP connect to proxy
                start = time.perf_counter()

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy_host, proxy_port),
                    timeout=self.timeout
                )

                tcp_rtt = (time.perf_counter() - start) * 1000
                profile.add_sample(tcp_rtt, "handshake")

                # SOCKS5 handshake
                start = time.perf_counter()
                writer.write(bytes([0x05, 0x01, 0x00]))  # Version, 1 method, no auth
                await writer.drain()

                response = await asyncio.wait_for(reader.read(2), timeout=self.timeout)
                handshake_rtt = (time.perf_counter() - start) * 1000
                profile.add_sample(handshake_rtt, "handshake")

                if len(response) < 2 or response[0] != 0x05:
                    writer.close()
                    await writer.wait_closed()
                    continue

                # SOCKS5 CONNECT request
                start = time.perf_counter()

                # Build CONNECT request for test host
                connect_req = bytes([
                    0x05,  # Version
                    0x01,  # CONNECT
                    0x00,  # Reserved
                    0x03,  # Domain name
                    len(self.test_host),
                ]) + self.test_host.encode() + struct.pack(">H", self.test_port)

                writer.write(connect_req)
                await writer.drain()

                # Read CONNECT response
                response = await asyncio.wait_for(reader.read(10), timeout=self.timeout)
                connect_rtt = (time.perf_counter() - start) * 1000
                profile.add_sample(connect_rtt, "data")

                if len(response) >= 2 and response[0] == 0x05 and response[1] == 0x00:
                    # Connection established, send HTTP request
                    start = time.perf_counter()
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {self.test_host}\r\n\r\n".encode())
                    await writer.drain()
                    await asyncio.wait_for(reader.read(1), timeout=self.timeout)
                    http_rtt = (time.perf_counter() - start) * 1000
                    profile.add_sample(http_rtt, "data")

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                logger.debug(f"Timeout on sample {i+1}")
            except Exception as e:
                logger.debug(f"Error on sample {i+1}: {e}")

            # Small delay between samples
            if i < self.sample_count - 1:
                await asyncio.sleep(0.1)

    def profile_sync(self, host: str, port: int) -> ProxyQualityProfile:
        """Synchronous version of profile."""
        return asyncio.get_event_loop().run_until_complete(
            self.profile(host, port)
        )


# Utility function
async def profile_proxy(
    proxy: str,
    sample_count: int = 5,
    timeout: float = 5.0
) -> ProxyQualityProfile:
    """
    Convenience function to profile a proxy.

    Args:
        proxy: Proxy in host:port format
        sample_count: Number of samples
        timeout: Timeout per operation

    Returns:
        ProxyQualityProfile with quality metrics
    """
    try:
        host, port_str = proxy.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        return ProxyQualityProfile(target=proxy)

    profiler = ProxyProfiler(sample_count=sample_count, timeout=timeout)
    return await profiler.profile(host, port)


# Backwards compatibility aliases
RTTFingerprint = ProxyQualityProfile
RTTFingerprinter = ProxyProfiler
fingerprint_proxy = profile_proxy


class ProxyLikelihood(Enum):
    """Deprecated: Use QualityTier instead."""
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    LIKELY = "likely"
    VERY_LIKELY = "very_likely"
