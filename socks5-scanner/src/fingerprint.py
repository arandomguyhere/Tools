"""
RTT Fingerprinting Module - Detect proxies via timing analysis.

Based on research showing that proxied connections exhibit:
- Higher RTT variance (jitter)
- RTT inflation compared to geo-expected values
- Distinct patterns in handshake vs data transfer timing

References:
- "Aroma: Automatic Detection of Web Proxies" (academic research)
- TCP timestamp analysis techniques
"""

import asyncio
import logging
import socket
import statistics
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class ProxyLikelihood(Enum):
    """Likelihood that a connection is proxied."""
    UNLIKELY = "unlikely"      # Direct connection likely
    POSSIBLE = "possible"      # Some proxy indicators
    LIKELY = "likely"          # Strong proxy indicators
    VERY_LIKELY = "very_likely"  # Very strong proxy indicators


@dataclass
class RTTSample:
    """Single RTT measurement."""
    rtt_ms: float
    timestamp: float
    stage: str = "unknown"  # handshake, data, close


@dataclass
class RTTFingerprint:
    """RTT fingerprint analysis results."""

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
    rtt_ratio: Optional[float] = None  # data_rtt / handshake_rtt

    # Analysis results
    proxy_likelihood: ProxyLikelihood = ProxyLikelihood.UNLIKELY
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)

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

        if self.handshake_rtt_ms and self.data_rtt_ms and self.handshake_rtt_ms > 0:
            self.rtt_ratio = self.data_rtt_ms / self.handshake_rtt_ms

    def analyze(self) -> 'RTTFingerprint':
        """Analyze RTT patterns for proxy indicators."""
        self.compute_statistics()
        self.indicators = []
        score = 0.0

        if not self.samples:
            return self

        # Indicator 1: High jitter (proxies add variable latency)
        if self.jitter_ms and self.mean_rtt_ms:
            jitter_ratio = self.jitter_ms / self.mean_rtt_ms
            if jitter_ratio > 0.3:
                self.indicators.append(f"High jitter ratio: {jitter_ratio:.2f}")
                score += 0.25
            elif jitter_ratio > 0.15:
                self.indicators.append(f"Moderate jitter ratio: {jitter_ratio:.2f}")
                score += 0.1

        # Indicator 2: RTT inflation (handshake vs data)
        if self.rtt_ratio:
            if self.rtt_ratio > 1.5:
                self.indicators.append(f"RTT inflation: {self.rtt_ratio:.2f}x")
                score += 0.25
            elif self.rtt_ratio > 1.2:
                self.indicators.append(f"Slight RTT inflation: {self.rtt_ratio:.2f}x")
                score += 0.1

        # Indicator 3: High absolute RTT (>500ms suggests proxy chain)
        if self.mean_rtt_ms and self.mean_rtt_ms > 500:
            self.indicators.append(f"High latency: {self.mean_rtt_ms:.0f}ms")
            score += 0.15
        elif self.mean_rtt_ms and self.mean_rtt_ms > 300:
            self.indicators.append(f"Elevated latency: {self.mean_rtt_ms:.0f}ms")
            score += 0.05

        # Indicator 4: High variance (stddev > 50% of mean)
        if self.stddev_rtt_ms and self.mean_rtt_ms and self.mean_rtt_ms > 0:
            cv = self.stddev_rtt_ms / self.mean_rtt_ms  # coefficient of variation
            if cv > 0.5:
                self.indicators.append(f"High variance: CV={cv:.2f}")
                score += 0.2
            elif cv > 0.25:
                self.indicators.append(f"Moderate variance: CV={cv:.2f}")
                score += 0.1

        # Indicator 5: RTT steps (sudden jumps between samples)
        if len(self.samples) >= 3:
            rtts = [s.rtt_ms for s in self.samples]
            jumps = [abs(rtts[i] - rtts[i-1]) for i in range(1, len(rtts))]
            max_jump = max(jumps) if jumps else 0
            if self.mean_rtt_ms and max_jump > self.mean_rtt_ms * 0.5:
                self.indicators.append(f"RTT step detected: {max_jump:.0f}ms")
                score += 0.15

        # Compute confidence and likelihood
        self.confidence = min(score, 1.0)

        if self.confidence >= 0.7:
            self.proxy_likelihood = ProxyLikelihood.VERY_LIKELY
        elif self.confidence >= 0.5:
            self.proxy_likelihood = ProxyLikelihood.LIKELY
        elif self.confidence >= 0.25:
            self.proxy_likelihood = ProxyLikelihood.POSSIBLE
        else:
            self.proxy_likelihood = ProxyLikelihood.UNLIKELY

        return self

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
            "rtt_ratio": self.rtt_ratio,
            "proxy_likelihood": self.proxy_likelihood.value,
            "confidence": self.confidence,
            "indicators": self.indicators,
        }


class RTTFingerprinter:
    """
    Fingerprints connections via RTT analysis.

    Usage:
        fingerprinter = RTTFingerprinter()
        result = await fingerprinter.fingerprint("1.2.3.4", 1080)
        print(f"Proxy likelihood: {result.proxy_likelihood}")
    """

    def __init__(
        self,
        sample_count: int = 5,
        timeout: float = 5.0,
        test_host: str = "httpbin.org",
        test_port: int = 80
    ):
        """
        Initialize fingerprinter.

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

    async def fingerprint(
        self,
        host: str,
        port: int,
        through_proxy: bool = True
    ) -> RTTFingerprint:
        """
        Fingerprint a target via RTT analysis.

        Args:
            host: Target host (proxy IP or direct host)
            port: Target port
            through_proxy: If True, test through SOCKS5 proxy

        Returns:
            RTTFingerprint with analysis results
        """
        result = RTTFingerprint(target=f"{host}:{port}")

        try:
            if through_proxy:
                await self._collect_proxy_samples(result, host, port)
            else:
                await self._collect_direct_samples(result, host, port)
        except Exception as e:
            logger.debug(f"Fingerprinting failed for {host}:{port}: {e}")

        return result.analyze()

    async def _collect_direct_samples(
        self,
        result: RTTFingerprint,
        host: str,
        port: int
    ):
        """Collect RTT samples for direct TCP connection."""
        for i in range(self.sample_count):
            try:
                start = time.perf_counter()

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

                connect_rtt = (time.perf_counter() - start) * 1000
                result.add_sample(connect_rtt, "handshake")

                # Send minimal data and measure response
                start = time.perf_counter()
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.read(1), timeout=self.timeout)
                data_rtt = (time.perf_counter() - start) * 1000
                result.add_sample(data_rtt, "data")

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                logger.debug(f"Timeout on sample {i+1}")
            except Exception as e:
                logger.debug(f"Error on sample {i+1}: {e}")

            # Small delay between samples
            if i < self.sample_count - 1:
                await asyncio.sleep(0.1)

    async def _collect_proxy_samples(
        self,
        result: RTTFingerprint,
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
                result.add_sample(tcp_rtt, "handshake")

                # SOCKS5 handshake
                start = time.perf_counter()
                writer.write(bytes([0x05, 0x01, 0x00]))  # Version, 1 method, no auth
                await writer.drain()

                response = await asyncio.wait_for(reader.read(2), timeout=self.timeout)
                handshake_rtt = (time.perf_counter() - start) * 1000
                result.add_sample(handshake_rtt, "handshake")

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
                result.add_sample(connect_rtt, "data")

                if len(response) >= 2 and response[0] == 0x05 and response[1] == 0x00:
                    # Connection established, send HTTP request
                    start = time.perf_counter()
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {self.test_host}\r\n\r\n".encode())
                    await writer.drain()
                    await asyncio.wait_for(reader.read(1), timeout=self.timeout)
                    http_rtt = (time.perf_counter() - start) * 1000
                    result.add_sample(http_rtt, "data")

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                logger.debug(f"Timeout on sample {i+1}")
            except Exception as e:
                logger.debug(f"Error on sample {i+1}: {e}")

            # Small delay between samples
            if i < self.sample_count - 1:
                await asyncio.sleep(0.1)

    def fingerprint_sync(self, host: str, port: int, through_proxy: bool = True) -> RTTFingerprint:
        """Synchronous version of fingerprint."""
        return asyncio.get_event_loop().run_until_complete(
            self.fingerprint(host, port, through_proxy)
        )


class TCPTimestampAnalyzer:
    """
    Analyzes TCP timestamps to detect proxy behavior.

    TCP timestamps can reveal:
    - Different system clocks (proxy vs origin)
    - Timestamp discontinuities
    - Mismatched timing patterns
    """

    def __init__(self):
        self.samples: List[Tuple[int, int]] = []  # (tsval, tsecr)

    def add_sample(self, tsval: int, tsecr: int):
        """Add TCP timestamp sample."""
        self.samples.append((tsval, tsecr))

    def analyze(self) -> Dict[str, Any]:
        """Analyze timestamp patterns."""
        if len(self.samples) < 2:
            return {"status": "insufficient_samples"}

        # Check for timestamp discontinuities
        tsvals = [s[0] for s in self.samples]
        deltas = [tsvals[i] - tsvals[i-1] for i in range(1, len(tsvals))]

        # Large jumps may indicate different hosts
        max_delta = max(deltas) if deltas else 0
        min_delta = min(deltas) if deltas else 0

        indicators = []
        if max_delta > 0 and min_delta > 0 and max_delta / min_delta > 10:
            indicators.append("Timestamp delta variance")

        # Negative deltas indicate different hosts
        if any(d < 0 for d in deltas):
            indicators.append("Timestamp regression detected")

        return {
            "status": "analyzed",
            "sample_count": len(self.samples),
            "max_delta": max_delta,
            "min_delta": min_delta,
            "indicators": indicators,
            "proxy_suspected": len(indicators) > 0
        }


# Utility function
async def fingerprint_proxy(
    proxy: str,
    sample_count: int = 5,
    timeout: float = 5.0
) -> RTTFingerprint:
    """
    Convenience function to fingerprint a proxy.

    Args:
        proxy: Proxy in host:port format
        sample_count: Number of samples
        timeout: Timeout per operation

    Returns:
        RTTFingerprint with analysis
    """
    try:
        host, port_str = proxy.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        return RTTFingerprint(target=proxy)

    fingerprinter = RTTFingerprinter(sample_count=sample_count, timeout=timeout)
    return await fingerprinter.fingerprint(host, port)
