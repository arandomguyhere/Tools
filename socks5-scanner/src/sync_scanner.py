"""
Synchronous SOCKS5 Scanner with robust error handling and structured results.

Features:
- Precise error categorization
- Configurable timeouts (connect/read/write)
- Retry logic with backoff
- Thread-pool concurrency
- Structured ProxyResult output
"""

import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Tuple, Callable

import requests

from .core import (
    ProxyResult, ScanResults, ScanConfig, TimingInfo, GeoInfo,
    ErrorCategory, ProxyProtocol, ProxyType, AnonymityLevel,
    Socks5, ScannerError
)

logger = logging.getLogger(__name__)


class SyncScanner:
    """
    Synchronous SOCKS5 proxy scanner with thread-pool concurrency.

    Usage:
        scanner = SyncScanner(config)
        result = scanner.scan_one("1.2.3.4:1080")
        results = scanner.scan_many(["1.2.3.4:1080", "5.6.7.8:1080"])
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._session: Optional[requests.Session] = None

    @property
    def session(self) -> requests.Session:
        """Lazy-initialized requests session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers['User-Agent'] = 'curl/7.88.0'
        return self._session

    # =========================================================================
    # Core Scanning Methods
    # =========================================================================

    def scan_one(self, proxy: str, retries: Optional[int] = None) -> ProxyResult:
        """
        Scan a single proxy with full validation.

        Args:
            proxy: Proxy address (ip:port or socks5://ip:port)
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
                sock = self._tcp_connect(host, port, result)
                if not sock:
                    if attempt < retries:
                        attempt += 1
                        time.sleep(self.config.retry_delay * attempt)
                        continue
                    break

                result.reachable = True

                try:
                    # Stage 2: SOCKS5 Handshake
                    if not self._socks5_handshake(sock, result):
                        break

                    result.socks5_valid = True

                    # Stage 3: SOCKS5 CONNECT
                    if not self._socks5_connect(sock, result):
                        break

                    result.tunnel_works = True

                finally:
                    sock.close()

                # Stage 4: HTTP Test (separate connection via requests)
                if result.tunnel_works:
                    self._http_test(proxy, result)

                # Success - no retry needed
                break

            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} failed for {proxy}: {e}")
                if attempt < retries:
                    attempt += 1
                    time.sleep(self.config.retry_delay * attempt)
                else:
                    if not result.error:
                        result.error = str(e)
                        result.error_category = ErrorCategory.UNKNOWN

        # Calculate total timing
        result.timing.total_ms = (time.time() - start_time) * 1000
        result.latency_ms = result.timing.total_ms

        return result

    def scan_many(
        self,
        proxies: List[str],
        max_workers: Optional[int] = None,
        callback: Optional[Callable[[ProxyResult], None]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> ScanResults:
        """
        Scan multiple proxies concurrently.

        Args:
            proxies: List of proxy addresses
            max_workers: Thread pool size (default: config.max_concurrent)
            callback: Called for each result as it completes
            progress_callback: Called with (completed, total) counts

        Returns:
            ScanResults with all results and statistics
        """
        results = ScanResults(config=self.config)
        max_workers = max_workers or self.config.max_concurrent
        total = len(proxies)

        logger.info(f"Scanning {total} proxies with {max_workers} threads")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_one, proxy): proxy
                for proxy in proxies
            }

            completed = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.add(result)

                    if callback:
                        callback(result)

                except Exception as e:
                    proxy = futures[future]
                    error_result = ProxyResult(
                        proxy=proxy,
                        error=str(e),
                        error_category=ErrorCategory.UNKNOWN
                    )
                    results.add(error_result)

                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        results.finalize()
        logger.info(
            f"Scan complete: {results.working}/{results.total} working "
            f"in {results.duration_seconds:.1f}s"
        )

        return results

    # =========================================================================
    # Stage 1: TCP Connect
    # =========================================================================

    def _tcp_connect(self, host: str, port: int, result: ProxyResult) -> Optional[socket.socket]:
        """
        Establish TCP connection with precise error categorization.
        """
        start = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.connect_timeout)
            sock.connect((host, port))

            result.timing.connect_ms = (time.time() - start) * 1000
            return sock

        except socket.timeout:
            result.error = "Connection timeout"
            result.error_category = ErrorCategory.TIMEOUT_CONNECT
            result.error_stage = "connect"

        except socket.gaierror as e:
            result.error = f"DNS resolution failed: {e}"
            result.error_category = ErrorCategory.DNS_FAILURE
            result.error_stage = "connect"

        except ConnectionRefusedError:
            result.error = "Connection refused"
            result.error_category = ErrorCategory.CONNECTION_REFUSED
            result.error_stage = "connect"

        except ConnectionResetError:
            result.error = "Connection reset"
            result.error_category = ErrorCategory.CONNECTION_RESET
            result.error_stage = "connect"

        except OSError as e:
            if e.errno == 101:  # Network unreachable
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

        return None

    # =========================================================================
    # Stage 2: SOCKS5 Handshake
    # =========================================================================

    def _socks5_handshake(self, sock: socket.socket, result: ProxyResult) -> bool:
        """
        Perform SOCKS5 authentication handshake.
        """
        start = time.time()

        try:
            sock.settimeout(self.config.write_timeout)

            # Send greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
            sock.sendall(bytes([Socks5.VERSION, 0x01, Socks5.AUTH_NONE]))

            sock.settimeout(self.config.read_timeout)
            response = sock.recv(2)

            result.timing.handshake_ms = (time.time() - start) * 1000

            if len(response) < 2:
                result.error = "Invalid handshake response (too short)"
                result.error_category = ErrorCategory.INVALID_RESPONSE
                result.error_stage = "handshake"
                return False

            version, method = response[0], response[1]

            # Check version
            if version != Socks5.VERSION:
                result.error = f"Protocol mismatch: expected SOCKS5, got version {version}"
                result.error_category = ErrorCategory.PROTOCOL_MISMATCH
                result.error_stage = "handshake"
                return False

            # Check auth method
            if method == Socks5.AUTH_NONE:
                return True

            elif method == Socks5.AUTH_PASSWORD:
                result.auth_required = True
                result.auth_methods = [Socks5.AUTH_PASSWORD]
                result.error = "Authentication required (username/password)"
                result.error_category = ErrorCategory.AUTH_REQUIRED
                result.error_stage = "handshake"
                return False

            elif method == Socks5.AUTH_NO_ACCEPTABLE:
                result.error = "No acceptable authentication method"
                result.error_category = ErrorCategory.HANDSHAKE_FAILED
                result.error_stage = "handshake"
                return False

            else:
                result.auth_required = True
                result.auth_methods = [method]
                result.error = f"Unsupported auth method: {method}"
                result.error_category = ErrorCategory.AUTH_REQUIRED
                result.error_stage = "handshake"
                return False

        except socket.timeout:
            result.error = "Handshake read timeout"
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

    def _socks5_connect(self, sock: socket.socket, result: ProxyResult) -> bool:
        """
        Send SOCKS5 CONNECT command to tunnel through proxy.
        """
        start = time.time()

        try:
            target_host = self.config.test_host
            target_port = self.config.test_port

            # Build CONNECT request
            # VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2)
            domain_bytes = target_host.encode('utf-8')
            request = bytes([
                Socks5.VERSION,
                Socks5.CMD_CONNECT,
                0x00,  # Reserved
                Socks5.ATYP_DOMAIN,
                len(domain_bytes)
            ]) + domain_bytes + struct.pack('>H', target_port)

            sock.settimeout(self.config.write_timeout)
            sock.sendall(request)

            sock.settimeout(self.config.read_timeout)
            response = sock.recv(10)

            result.timing.tunnel_ms = (time.time() - start) * 1000

            if len(response) < 2:
                result.error = "Invalid CONNECT response (too short)"
                result.error_category = ErrorCategory.INVALID_RESPONSE
                result.error_stage = "tunnel"
                return False

            version, reply = response[0], response[1]

            if version != Socks5.VERSION:
                result.error = f"Protocol mismatch in CONNECT response"
                result.error_category = ErrorCategory.PROTOCOL_MISMATCH
                result.error_stage = "tunnel"
                return False

            if reply == Socks5.REPLY_SUCCESS:
                return True

            # Map SOCKS5 reply code to error category
            error_msg = Socks5.REPLY_MESSAGES.get(reply, f"Unknown error {reply}")
            result.error = f"CONNECT failed: {error_msg}"
            result.error_stage = "tunnel"

            if reply == Socks5.REPLY_NETWORK_UNREACHABLE:
                result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            elif reply == Socks5.REPLY_HOST_UNREACHABLE:
                result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            elif reply == Socks5.REPLY_CONNECTION_REFUSED:
                result.error_category = ErrorCategory.CONNECTION_REFUSED
            elif reply == Socks5.REPLY_NOT_ALLOWED:
                result.error_category = ErrorCategory.PROXY_ERROR
            else:
                result.error_category = ErrorCategory.PROXY_ERROR

            return False

        except socket.timeout:
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

    def _http_test(self, proxy: str, result: ProxyResult) -> bool:
        """
        Test HTTP request through the proxy.
        """
        start = time.time()

        proxies = {
            'http': f'socks5h://{proxy}',
            'https': f'socks5h://{proxy}'
        }

        try:
            response = self.session.get(
                self.config.test_url,
                proxies=proxies,
                timeout=self.config.http_timeout,
                verify=self.config.verify_ssl
            )

            result.timing.http_ms = (time.time() - start) * 1000

            if response.status_code == 200:
                result.http_works = True

                # Try to extract external IP
                try:
                    data = response.json()
                    result.external_ip = data.get('origin', data.get('ip'))
                except Exception:
                    pass

                return True

            result.error = f"HTTP {response.status_code}"
            result.error_category = ErrorCategory.HTTP_ERROR
            result.error_stage = "http"
            return False

        except requests.exceptions.Timeout:
            result.error = "HTTP request timeout"
            result.error_category = ErrorCategory.TIMEOUT_READ
            result.error_stage = "http"
            return False

        except requests.exceptions.ProxyError as e:
            result.error = f"Proxy error: {e}"
            result.error_category = ErrorCategory.PROXY_ERROR
            result.error_stage = "http"
            return False

        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection error: {e}"
            result.error_category = ErrorCategory.NETWORK_UNREACHABLE
            result.error_stage = "http"
            return False

        except Exception as e:
            result.error = f"HTTP error: {e}"
            result.error_category = ErrorCategory.HTTP_ERROR
            result.error_stage = "http"
            return False

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _parse_proxy(self, proxy: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse proxy string into host and port."""
        proxy = proxy.strip()

        # Handle URL format
        for prefix in ('socks5h://', 'socks5://', 'http://', 'https://'):
            if proxy.startswith(prefix):
                proxy = proxy[len(prefix):]
                break

        # Handle user:pass@host:port
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

    def close(self):
        """Clean up resources."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
