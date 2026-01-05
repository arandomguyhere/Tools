"""
Async SOCKS5 Proxy Scanner - High-performance async implementation.

Uses asyncio and aiohttp for concurrent proxy collection and validation.
Inspired by monosans/proxy-scraper-checker (Rust).
"""

import asyncio
import socket
import struct
import time
from typing import Dict, List, Optional, Set, Any

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .utils import (
    Color, extract_proxies_from_text, parse_proxy, validate_ip,
    get_user_agent, GeoLocator, format_geo_info, save_json,
    save_proxies_to_file, progress_bar, format_time
)


class AsyncProxyValidator:
    """Async SOCKS5 proxy validator for high-performance checking."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 5)
        self.test_url = self.config.get('test_url', 'http://httpbin.org/ip')
        self.geo_lookup = self.config.get('geo_lookup', False)
        self.geolocator = GeoLocator() if self.geo_lookup else None

    async def test_socks5_handshake(self, ip: str, port: int,
                                     timeout: Optional[float] = None) -> tuple:
        """
        Async test of SOCKS5 handshake.

        Returns (success, message, response_time_ms)
        """
        timeout = timeout or self.timeout
        start_time = time.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

            # SOCKS5 handshake
            writer.write(b'\x05\x01\x00')
            await writer.drain()

            response = await asyncio.wait_for(reader.read(2), timeout=timeout)

            writer.close()
            await writer.wait_closed()

            response_time = int((time.time() - start_time) * 1000)

            if len(response) >= 2 and response[0:1] == b'\x05':
                if response[1:2] == b'\x00':
                    return True, "OK", response_time
                elif response[1:2] == b'\x02':
                    return True, "Auth required", response_time

            return False, "Invalid response", response_time

        except asyncio.TimeoutError:
            return False, "Timeout", None
        except ConnectionRefusedError:
            return False, "Refused", None
        except Exception as e:
            return False, str(e)[:20], None

    async def test_socks5_connect(self, ip: str, port: int,
                                   target: str = "httpbin.org",
                                   target_port: int = 80,
                                   timeout: Optional[float] = None) -> tuple:
        """
        Async test of SOCKS5 CONNECT command.

        Returns (success, message)
        """
        timeout = timeout or self.timeout

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

            # Handshake
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(2), timeout=timeout)

            if response != b'\x05\x00':
                writer.close()
                return False, "Handshake failed"

            # Connect request
            domain_bytes = target.encode('utf-8')
            request = (
                b'\x05\x01\x00\x03' +
                bytes([len(domain_bytes)]) +
                domain_bytes +
                struct.pack('>H', target_port)
            )
            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(10), timeout=timeout)

            writer.close()
            await writer.wait_closed()

            if len(response) >= 2 and response[1] == 0x00:
                return True, "OK"

            return False, f"Error code: {response[1] if len(response) > 1 else 'unknown'}"

        except asyncio.TimeoutError:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)[:20]

    async def validate_proxy(self, proxy: str) -> Dict[str, Any]:
        """Validate a single proxy asynchronously."""
        result = {
            'proxy': proxy,
            'valid': False,
            'socks5': False,
            'connect': False,
            'response_time_ms': None,
            'geo': None,
            'error': None
        }

        parsed = parse_proxy(proxy)
        if not parsed:
            result['error'] = "Invalid format"
            return result

        ip, port = parsed

        # Test SOCKS5 handshake
        success, msg, response_time = await self.test_socks5_handshake(ip, port)
        result['socks5'] = success
        result['response_time_ms'] = response_time

        if not success:
            result['error'] = msg
            return result

        # Test CONNECT
        success, msg = await self.test_socks5_connect(ip, port)
        result['connect'] = success
        result['valid'] = result['socks5']

        if not success:
            result['error'] = msg

        # Geolocation lookup (if enabled)
        if self.geolocator and result['valid']:
            result['geo'] = self.geolocator.lookup(ip)

        return result

    async def validate_proxies(self, proxies: List[str],
                                concurrency: int = 100,
                                show_progress: bool = True) -> Dict:
        """
        Validate multiple proxies with high concurrency.

        Args:
            proxies: List of proxy strings
            concurrency: Max concurrent connections
            show_progress: Show progress bar

        Returns:
            Results dictionary
        """
        results = {
            'all': [],
            'valid': [],
            'stats': {
                'total': len(proxies),
                'valid': 0,
                'failed': 0
            }
        }

        if not proxies:
            return results

        if show_progress:
            print(f"\n{Color.cyan('Validating')} {len(proxies)} proxies "
                  f"(concurrency: {concurrency})...")

        semaphore = asyncio.Semaphore(concurrency)
        completed = 0
        start_time = time.time()

        async def validate_with_semaphore(proxy: str) -> Dict:
            async with semaphore:
                return await self.validate_proxy(proxy)

        tasks = [validate_with_semaphore(p) for p in proxies]

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                results['all'].append(result)

                if result['valid']:
                    results['valid'].append(result)
                    results['stats']['valid'] += 1
                else:
                    results['stats']['failed'] += 1

            except Exception:
                results['stats']['failed'] += 1

            completed += 1

            if show_progress and completed % 50 == 0:
                print(f"\r{progress_bar(completed, len(proxies), prefix='Progress: ')}", end='')

        if show_progress:
            print(f"\r{progress_bar(completed, len(proxies), prefix='Progress: ')}")
            elapsed = time.time() - start_time
            rate = len(proxies) / elapsed if elapsed > 0 else 0
            print(f"Completed in {format_time(elapsed)} ({rate:.0f} proxies/sec)")

        return results


class AsyncSocks5Scanner:
    """High-performance async SOCKS5 proxy scanner."""

    DEFAULT_SOURCES = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
    ]

    def __init__(self, config: Optional[Dict] = None):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for async scanner. Install with: pip install aiohttp")

        self.config = config or {}
        self.sources = self.config.get('sources', self.DEFAULT_SOURCES)
        self.timeout = self.config.get('timeout', 15)
        self.validator = AsyncProxyValidator(self.config.get('validator', {}))

    async def fetch_from_url(self, session: aiohttp.ClientSession,
                              url: str) -> List[str]:
        """Fetch proxies from a URL asynchronously."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return extract_proxies_from_text(text)
        except Exception:
            pass
        return []

    async def scan_sources(self, show_progress: bool = True) -> List[str]:
        """Scan all proxy sources asynchronously."""
        all_proxies: Set[str] = set()

        if show_progress:
            print(f"\n{Color.cyan('Scanning')} {len(self.sources)} sources async...")

        headers = {'User-Agent': get_user_agent()}

        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = [self.fetch_from_url(session, url) for url in self.sources]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for url, result in zip(self.sources, results):
                if isinstance(result, list) and result:
                    if show_progress:
                        display_url = url[:55] + '...' if len(url) > 58 else url
                        print(f"  {Color.green('✓')} {display_url}: {len(result)}")
                    all_proxies.update(result)
                elif show_progress:
                    display_url = url[:55] + '...' if len(url) > 58 else url
                    print(f"  {Color.dim('✗')} {display_url}: 0")

        proxy_list = list(all_proxies)

        if show_progress:
            print(f"\n{Color.bold('Total unique:')} {Color.green(str(len(proxy_list)))}")

        return proxy_list

    async def run_scan(self,
                       concurrency: int = 100,
                       output_dir: str = './results',
                       validate: bool = True,
                       geo_lookup: bool = False) -> Dict:
        """
        Run a complete async scan.

        Args:
            concurrency: Max concurrent validations
            output_dir: Output directory
            validate: Whether to validate proxies
            geo_lookup: Whether to lookup geolocation

        Returns:
            Results dictionary
        """
        import os

        timestamp = time.strftime("%Y%m%d_%H%M%S")

        print(f"\n{'='*60}")
        print(f"{Color.bold('SOCKS5 Async Scanner')}")
        print(f"Concurrency: {concurrency} | Geo: {'On' if geo_lookup else 'Off'}")
        print(f"{'='*60}")

        start = time.time()

        # Collect proxies
        proxies = await self.scan_sources()

        if not proxies:
            print(f"\n{Color.red('No proxies found!')}")
            return {'proxies': [], 'results': None, 'stats': {}}

        # Validate
        results = None
        if validate:
            if geo_lookup:
                self.validator.geo_lookup = True
                self.validator.geolocator = GeoLocator()

            results = await self.validator.validate_proxies(
                proxies,
                concurrency=concurrency,
                show_progress=True
            )

            # Save results
            os.makedirs(output_dir, exist_ok=True)

            json_path = f"{output_dir}/results_{timestamp}.json"
            save_json(results, json_path)

            valid_proxies = [r['proxy'] for r in results.get('valid', [])]
            if valid_proxies:
                txt_path = f"{output_dir}/valid_{timestamp}.txt"
                save_proxies_to_file(valid_proxies, txt_path)

            # Stats
            self._print_stats(results, geo_lookup)

            print(f"\n{Color.green('Saved:')} {json_path}")

        elapsed = time.time() - start
        print(f"\n{Color.bold('Total time:')} {format_time(elapsed)}")

        return {
            'proxies': proxies,
            'results': results,
            'stats': results['stats'] if results else {}
        }

    def _print_stats(self, results: Dict, geo_lookup: bool = False):
        """Print statistics."""
        stats = results.get('stats', {})

        print(f"\n{'='*60}")
        print(f"{Color.bold('Results')}")
        print(f"{'='*60}")
        print(f"  Total:   {stats.get('total', 0)}")
        print(f"  Valid:   {Color.green(str(stats.get('valid', 0)))}")
        print(f"  Failed:  {Color.red(str(stats.get('failed', 0)))}")

        # Show samples with geo info
        valid = results.get('valid', [])[:5]
        if valid:
            print(f"\n{Color.bold('Sample proxies:')}")
            for p in valid:
                geo_str = ""
                if geo_lookup and p.get('geo'):
                    geo_str = f" [{format_geo_info(p['geo'])}]"
                time_str = f"{p.get('response_time_ms', '?')}ms"
                print(f"  • {p['proxy']} ({time_str}){geo_str}")


def run_async_scan(concurrency: int = 100,
                   output_dir: str = './results',
                   geo_lookup: bool = False) -> Dict:
    """
    Quick function to run an async scan.

    Example:
        from src.async_scanner import run_async_scan
        results = run_async_scan(concurrency=200)
    """
    scanner = AsyncSocks5Scanner()
    return asyncio.run(scanner.run_scan(
        concurrency=concurrency,
        output_dir=output_dir,
        geo_lookup=geo_lookup
    ))
