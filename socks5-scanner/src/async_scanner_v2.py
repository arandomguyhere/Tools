"""
Asynchronous SOCKS5 Scanner with high-performance concurrent scanning.

Features:
- asyncio + aiohttp for maximum throughput
- Semaphore-controlled concurrency
- Precise error categorization
- Configurable timeouts per stage
- Structured ProxyResult output
- Optional uvloop for extra speed
"""

import asyncio
import logging
import struct
import time
from typing import Optional, List, Callable, Awaitable, AsyncIterator

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import uvloop
    HAS_UVLOOP = True
except ImportError:
    HAS_UVLOOP = False

from .core import (
    ProxyResult, ScanResults, ScanConfig, TimingInfo, GeoInfo,
    ErrorCategory, Socks5
)

# Optional advanced modules
try:
    from .geoip import get_geoip, GeoIPResult
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

logger = logging.getLogger(__name__)


def install_uvloop():
    """Install uvloop as the event loop policy if available."""
    if HAS_UVLOOP:
        uvloop.install()
        logger.info("uvloop installed for faster async I/O")
        return True
    return False


class AsyncScanner:
    """
    High-performance async SOCKS5 proxy scanner.

    Usage:
        async with AsyncScanner(config) as scanner:
            result = await scanner.scan_one("1.2.3.4:1080")
            results = await scanner.scan_many(proxies)

    Or without context manager:
        scanner = AsyncScanner(config)
        results = await scanner.scan_many(proxies)
    """

    def __init__(self, config: Optional[ScanConfig] = None, enable_geoip: bool = False):
        self.config = config or ScanConfig()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._geoip = None

        # Initialize optional modules
        if enable_geoip and HAS_GEOIP:
            try:
                self._geoip = get_geoip()
                logger.info("GeoIP enrichment enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize GeoIP: {e}")

    async def __aenter__(self):
        await self._init_session()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _init_session(self):
        """Initialize aiohttp session."""
        if HAS_AIOHTTP and self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'curl/7.88.0'}
            )

    async def close(self):
        """Clean up resources."""
        if self._session:
            await self._session.close()
            self._session = None

    # =========================================================================
    # Core Scanning Methods
    # =========================================================================

    async def scan_one(self, proxy: str, retries: Optional[int] = None) -> ProxyResult:
        """
        Scan a single proxy with full validation.

        Args:
            proxy: Proxy address (ip:port)
            retries: Override config retries

        Returns:
            ProxyResult with complete scan data
        """
        result = ProxyResult(proxy=proxy)
        retries = retries if retries is not None else self.config.max_retries

        # Parse proxy
        host, port = self._parse_proxy(proxy)
        if not host or not port:
            result.error = "Invalid proxy format"
            result.error_category = ErrorCategory.INVALID_RESPONSE
            return result

        result.host = host
        result.port = port
        result.timing = TimingInfo()

        start_time = time.time()
        attempt = 0

        while attempt <= retries:
            try:
                # Stage 1: TCP Connect
                reader, writer = await self._tcp_connect(host, port, result)
                if not reader:
                    if attempt < retries:
                        attempt += 1
                        await asyncio.sleep(self.config.retry_delay * attempt)
                        continue
                    break

                result.reachable = True

                try:
                    # Stage 2: SOCKS5 Handshake
                    if not await self._socks5_handshake(reader, writer, result):
                        break

                    result.socks5_valid = True

                    # Stage 3: SOCKS5 CONNECT
                    if not await self._socks5_connect(reader, writer, result):
                        break

                    result.tunnel_works = True

                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                # Stage 4: HTTP Test
                if result.tunnel_works and HAS_AIOHTTP:
                    await self._http_test(proxy, result)

                    # Stage 5: GeoIP Enrichment (if enabled and we have external IP)
                    if self._geoip and result.external_ip:
                        self._enrich_geoip(result)

                # Success - no retry needed
                break

            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} failed for {proxy}: {e}")
                if attempt < retries:
                    attempt += 1
                    await asyncio.sleep(self.config.retry_delay * attempt)
                else:
                    if not result.error:
                        result.error = str(e)
                        result.error_category = ErrorCategory.UNKNOWN

        # Calculate total timing
        result.timing.total_ms = (time.time() - start_time) * 1000
        result.latency_ms = result.timing.total_ms

        return result

    async def scan_many(
        self,
        proxies: List[str],
        concurrency: Optional[int] = None,
        callback: Optional[Callable[[ProxyResult], Awaitable[None]]] = None,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None
    ) -> ScanResults:
        """
        Scan multiple proxies with semaphore-controlled concurrency.

        Args:
            proxies: List of proxy addresses
            concurrency: Max concurrent scans (default: config.max_concurrent)
            callback: Async callback for each result
            progress_callback: Async callback with (completed, total)

        Returns:
            ScanResults with all results and statistics
        """
        await self._init_session()

        concurrency = concurrency or self.config.max_concurrent
        self._semaphore = asyncio.Semaphore(concurrency)

        results = ScanResults(config=self.config)
        total = len(proxies)
        completed = 0

        logger.info(f"Scanning {total} proxies with concurrency {concurrency}")

        async def scan_with_semaphore(proxy: str) -> ProxyResult:
            nonlocal completed
            async with self._semaphore:
                result = await self.scan_one(proxy)

                if callback:
                    await callback(result)

                completed += 1
                if progress_callback:
                    await progress_callback(completed, total)

                return result

        # Create tasks
        tasks = [scan_with_semaphore(proxy) for proxy in proxies]

        # Gather results
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(scan_results):
            if isinstance(res, Exception):
                error_result = ProxyResult(
                    proxy=proxies[i],
                    error=str(res),
                    error_category=ErrorCategory.UNKNOWN
                )
                results.add(error_result)
            else:
                results.add(res)

        results.finalize()
        logger.info(
            f"Scan complete: {results.working}/{results.total} working "
            f"in {results.duration_seconds:.1f}s"
        )

        return results

    async def scan_stream(
        self,
        proxies: List[str],
        concurrency: Optional[int] = None
    ) -> AsyncIterator[ProxyResult]:
        """
        Stream results as they complete (memory efficient for large scans).

        Usage:
            async for result in scanner.scan_stream(proxies):
                print(result)
        """
        await self._init_session()

        concurrency = concurrency or self.config.max_concurrent
        self._semaphore = asyncio.Semaphore(concurrency)

        async def scan_with_semaphore(proxy: str) -> ProxyResult:
            async with self._semaphore:
                return await self.scan_one(proxy)

        # Create tasks
        tasks = [asyncio.create_task(scan_with_semaphore(p)) for p in proxies]

        # Yield as completed
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                yield result
            except Exception as e:
                yield ProxyResult(
                    proxy="unknown",
                    error=str(e),
                    error_category=ErrorCategory.UNKNOWN
                )

    # =========================================================================
    # Stage 1: TCP Connect
    # =========================================================================

    async def _tcp_connect(
        self, host: str, port: int, result: ProxyResult
    ) -> tuple:
        """Establish TCP connection with timeout."""
        start = time.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            result.timing.connect_ms = (time.time() - start) * 1000
            return reader, writer

        except asyncio.TimeoutError:
            result.error = "Connection timeout"
            result.error_category = ErrorCategory.TIMEOUT_CONNECT
            result.error_stage = "connect"

        except OSError as e:
            if "Name or service not known" in str(e) or e.errno == -2:
                result.error = f"DNS resolution failed"
                result.error_category = ErrorCategory.DNS_FAILURE
            elif e.errno == 111:  # Connection refused
                result.error = "Connection refused"
                result.error_category = ErrorCategory.CONNECTION_REFUSED
            elif e.errno == 104:  # Connection reset
                result.error = "Connection reset"
                result.error_category = ErrorCategory.CONNECTION_RESET
            elif e.errno == 101:  # Network unreachable
                result.error = "Network unreachable"
                result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            elif e.errno == 113:  # No route to host
                result.error = "Host unreachable"
                result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            else:
                result.error = f"OS error: {e}"
                result.error_category = ErrorCategory.UNKNOWN
            result.error_stage = "connect"

        except Exception as e:
            result.error = str(e)
            result.error_category = ErrorCategory.UNKNOWN
            result.error_stage = "connect"

        return None, None

    # =========================================================================
    # Stage 2: SOCKS5 Handshake
    # =========================================================================

    async def _socks5_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        result: ProxyResult
    ) -> bool:
        """Perform SOCKS5 authentication handshake."""
        start = time.time()

        try:
            # Send greeting
            writer.write(bytes([Socks5.VERSION, 0x01, Socks5.AUTH_NONE]))
            await asyncio.wait_for(
                writer.drain(),
                timeout=self.config.write_timeout
            )

            # Read response
            response = await asyncio.wait_for(
                reader.read(2),
                timeout=self.config.read_timeout
            )

            result.timing.handshake_ms = (time.time() - start) * 1000

            if len(response) < 2:
                result.error = "Invalid handshake response"
                result.error_category = ErrorCategory.INVALID_RESPONSE
                result.error_stage = "handshake"
                return False

            version, method = response[0], response[1]

            if version != Socks5.VERSION:
                result.error = f"Protocol mismatch: version {version}"
                result.error_category = ErrorCategory.PROTOCOL_MISMATCH
                result.error_stage = "handshake"
                return False

            if method == Socks5.AUTH_NONE:
                return True

            if method == Socks5.AUTH_PASSWORD:
                result.auth_required = True
                result.auth_methods = [Socks5.AUTH_PASSWORD]
                result.error = "Authentication required"
                result.error_category = ErrorCategory.AUTH_REQUIRED
                result.error_stage = "handshake"
                return False

            if method == Socks5.AUTH_NO_ACCEPTABLE:
                result.error = "No acceptable auth method"
                result.error_category = ErrorCategory.HANDSHAKE_FAILED
                result.error_stage = "handshake"
                return False

            result.auth_required = True
            result.error = f"Unsupported auth: {method}"
            result.error_category = ErrorCategory.AUTH_REQUIRED
            result.error_stage = "handshake"
            return False

        except asyncio.TimeoutError:
            result.error = "Handshake timeout"
            result.error_category = ErrorCategory.TIMEOUT_READ
            result.error_stage = "handshake"
            return False

        except Exception as e:
            result.error = f"Handshake error: {e}"
            result.error_category = ErrorCategory.HANDSHAKE_FAILED
            result.error_stage = "handshake"
            return False

    # =========================================================================
    # Stage 3: SOCKS5 CONNECT
    # =========================================================================

    async def _socks5_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        result: ProxyResult
    ) -> bool:
        """Send SOCKS5 CONNECT command."""
        start = time.time()

        try:
            target_host = self.config.test_host
            target_port = self.config.test_port

            # Build request
            domain_bytes = target_host.encode('utf-8')
            request = bytes([
                Socks5.VERSION,
                Socks5.CMD_CONNECT,
                0x00,
                Socks5.ATYP_DOMAIN,
                len(domain_bytes)
            ]) + domain_bytes + struct.pack('>H', target_port)

            writer.write(request)
            await asyncio.wait_for(
                writer.drain(),
                timeout=self.config.write_timeout
            )

            response = await asyncio.wait_for(
                reader.read(10),
                timeout=self.config.read_timeout
            )

            result.timing.tunnel_ms = (time.time() - start) * 1000

            if len(response) < 2:
                result.error = "Invalid CONNECT response"
                result.error_category = ErrorCategory.INVALID_RESPONSE
                result.error_stage = "tunnel"
                return False

            version, reply = response[0], response[1]

            if version != Socks5.VERSION:
                result.error = "Protocol mismatch"
                result.error_category = ErrorCategory.PROTOCOL_MISMATCH
                result.error_stage = "tunnel"
                return False

            if reply == Socks5.REPLY_SUCCESS:
                return True

            error_msg = Socks5.REPLY_MESSAGES.get(reply, f"Error {reply}")
            result.error = f"CONNECT: {error_msg}"
            result.error_stage = "tunnel"

            if reply in (Socks5.REPLY_NETWORK_UNREACHABLE, Socks5.REPLY_HOST_UNREACHABLE):
                result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            elif reply == Socks5.REPLY_CONNECTION_REFUSED:
                result.error_category = ErrorCategory.CONNECTION_REFUSED
            else:
                result.error_category = ErrorCategory.PROXY_ERROR

            return False

        except asyncio.TimeoutError:
            result.error = "CONNECT timeout"
            result.error_category = ErrorCategory.TIMEOUT_READ
            result.error_stage = "tunnel"
            return False

        except Exception as e:
            result.error = f"CONNECT error: {e}"
            result.error_category = ErrorCategory.PROXY_ERROR
            result.error_stage = "tunnel"
            return False

    # =========================================================================
    # Stage 4: HTTP Test
    # =========================================================================

    async def _http_test(self, proxy: str, result: ProxyResult) -> bool:
        """Test HTTP through proxy using aiohttp-socks."""
        if not HAS_AIOHTTP:
            return False

        start = time.time()

        try:
            connector = ProxyConnector.from_url(f'socks5://{proxy}')
            timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'curl/7.88.0'}
            ) as session:
                async with session.get(self.config.test_url) as response:
                    result.timing.http_ms = (time.time() - start) * 1000

                    if response.status == 200:
                        result.http_works = True
                        try:
                            data = await response.json()
                            result.external_ip = data.get('origin', data.get('ip'))
                        except Exception:
                            pass
                        return True

                    result.error = f"HTTP {response.status}"
                    result.error_category = ErrorCategory.HTTP_ERROR
                    result.error_stage = "http"
                    return False

        except asyncio.TimeoutError:
            result.error = "HTTP timeout"
            result.error_category = ErrorCategory.TIMEOUT_READ
            result.error_stage = "http"
            return False

        except Exception as e:
            result.error = f"HTTP error: {e}"
            result.error_category = ErrorCategory.HTTP_ERROR
            result.error_stage = "http"
            return False

    # =========================================================================
    # Stage 5: GeoIP Enrichment
    # =========================================================================

    def _enrich_geoip(self, result: ProxyResult):
        """Enrich result with GeoIP data for the external IP."""
        if not self._geoip or not result.external_ip:
            return

        try:
            geo_result = self._geoip.lookup(result.external_ip)

            # Populate GeoInfo on the result
            result.geo = GeoInfo(
                country=geo_result.country,
                country_code=geo_result.country_code,
                city=geo_result.city,
                region=geo_result.region,
                latitude=geo_result.latitude,
                longitude=geo_result.longitude,
                timezone=geo_result.timezone,
                asn=geo_result.asn,
                asn_org=geo_result.asn_org
            )

            logger.debug(f"GeoIP enriched {result.external_ip}: {geo_result.location_str}, {geo_result.asn_str}")

        except Exception as e:
            logger.debug(f"GeoIP enrichment failed for {result.external_ip}: {e}")

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _parse_proxy(self, proxy: str) -> tuple:
        """Parse proxy string into host and port."""
        proxy = proxy.strip()

        for prefix in ('socks5h://', 'socks5://', 'http://', 'https://'):
            if proxy.startswith(prefix):
                proxy = proxy[len(prefix):]
                break

        if '@' in proxy:
            proxy = proxy.split('@')[-1]

        if ':' not in proxy:
            return None, None

        parts = proxy.rsplit(':', 1)
        if len(parts) != 2:
            return None, None

        host = parts[0].strip()
        try:
            port = int(parts[1].strip())
            if not (1 <= port <= 65535):
                return None, None
            return host, port
        except ValueError:
            return None, None


# =============================================================================
# Convenience Functions
# =============================================================================

async def scan_proxies(
    proxies: List[str],
    concurrency: int = 100,
    config: Optional[ScanConfig] = None
) -> ScanResults:
    """
    Quick async scan of proxy list.

    Args:
        proxies: List of proxy addresses
        concurrency: Max concurrent scans
        config: Optional scanner config

    Returns:
        ScanResults
    """
    config = config or ScanConfig(max_concurrent=concurrency)

    async with AsyncScanner(config) as scanner:
        return await scanner.scan_many(proxies, concurrency=concurrency)


def run_scan(proxies: List[str], concurrency: int = 100) -> ScanResults:
    """
    Synchronous wrapper for async scanning.

    Useful for simple scripts that don't need async context.
    """
    return asyncio.run(scan_proxies(proxies, concurrency))
