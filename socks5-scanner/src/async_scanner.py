"""
Async SOCKS5 Scanner - LEGACY COMPATIBILITY WRAPPER.

This module is deprecated. Use src.async_scanner_v2.AsyncScanner instead.

This wrapper maintains backwards compatibility with existing code while
delegating to the new async_scanner_v2 module.
"""

import asyncio
import os
import warnings
from typing import Dict, List, Optional, Any

from .async_scanner_v2 import AsyncScanner
from .core import ScanConfig, ScanResults
from .utils import Color, save_json, save_proxies_to_file

# Emit deprecation warning on import
warnings.warn(
    "src.async_scanner is deprecated. Use src.async_scanner_v2.AsyncScanner instead.",
    DeprecationWarning,
    stacklevel=2
)


class AsyncSocks5Scanner:
    """
    DEPRECATED: Use AsyncScanner from async_scanner_v2 instead.

    This class maintains backwards compatibility with the old API.
    """

    # Re-export DEFAULT_SOURCES for backwards compatibility
    DEFAULT_SOURCES = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
    ]

    def __init__(self, config: Optional[Dict] = None):
        """Initialize with config dict for backwards compatibility."""
        self.config = config or {}
        self.sources = self.config.get('sources', self.DEFAULT_SOURCES)
        self.timeout = self.config.get('timeout', 15)

        # Create underlying scanner with converted config
        validator_config = self.config.get('validator', {})
        scan_config = ScanConfig(
            connect_timeout=float(validator_config.get('timeout', 5)),
            read_timeout=float(validator_config.get('timeout', 5)),
        )
        self._scanner = AsyncScanner(scan_config)

    async def fetch_proxies(self) -> List[str]:
        """Fetch proxies from all configured sources."""
        try:
            import aiohttp
        except ImportError:
            print("aiohttp required: pip install aiohttp")
            return []

        proxies = set()

        async with aiohttp.ClientSession() as session:
            for source in self.sources:
                try:
                    async with session.get(source, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.strip().split('\n'):
                                line = line.strip()
                                if ':' in line and line[0].isdigit():
                                    proxies.add(line.split()[0])
                except Exception:
                    pass

        return list(proxies)

    async def validate_proxy(self, proxy: str) -> Dict:
        """Validate a single proxy."""
        result = await self._scanner.scan_one(proxy)

        # Convert to old dict format
        return {
            'proxy': result.proxy,
            'host': result.host,
            'port': result.port,
            'reachable': result.reachable,
            'socks5_valid': result.socks5_valid,
            'tunnel_works': result.tunnel_works,
            'auth_required': result.auth_required,
            'latency_ms': result.latency_ms,
            'error': result.error,
            'external_ip': result.external_ip,
            'working': result.is_working,
        }

    async def validate_many(
        self,
        proxies: List[str],
        concurrency: int = 100,
        callback=None
    ) -> List[Dict]:
        """Validate multiple proxies concurrently."""
        results = await self._scanner.scan_many(proxies, max_concurrent=concurrency)

        validated = []
        for result in results.all_results:
            entry = {
                'proxy': result.proxy,
                'host': result.host,
                'port': result.port,
                'reachable': result.reachable,
                'socks5_valid': result.socks5_valid,
                'tunnel_works': result.tunnel_works,
                'auth_required': result.auth_required,
                'latency_ms': result.latency_ms,
                'error': result.error,
                'external_ip': result.external_ip,
                'working': result.is_working,
            }
            validated.append(entry)
            if callback:
                callback(entry)

        return validated

    async def run_scan(
        self,
        concurrency: int = 100,
        output_dir: str = './results',
        validate: bool = True,
        geo_lookup: bool = False
    ) -> Dict:
        """
        Run full scan: fetch and optionally validate.

        Returns dict with results for backwards compatibility.
        """
        print(f"\n{Color.cyan('Fetching proxies from sources...')}")
        proxies = await self.fetch_proxies()
        print(f"Found {len(proxies)} unique proxies")

        if not proxies:
            return {'proxies': [], 'stats': {'total': 0, 'working': 0}}

        if not validate:
            # Just save raw proxies
            os.makedirs(output_dir, exist_ok=True)
            save_proxies_to_file(proxies, os.path.join(output_dir, 'proxies_raw.txt'))
            return {'proxies': proxies, 'stats': {'total': len(proxies)}}

        print(f"\n{Color.cyan('Validating proxies...')}")
        validated = await self.validate_many(proxies, concurrency=concurrency)

        # Separate working from failed
        working = [p for p in validated if p.get('working')]
        valid = [p for p in validated if p.get('socks5_valid')]

        print(f"\n{Color.green('Results:')}")
        print(f"  Total scanned: {len(validated)}")
        print(f"  SOCKS5 valid: {len(valid)}")
        print(f"  Fully working: {len(working)}")

        # Save results
        os.makedirs(output_dir, exist_ok=True)

        # Save working proxies
        working_proxies = [p['proxy'] for p in working]
        save_proxies_to_file(working_proxies, os.path.join(output_dir, 'proxies_working.txt'))

        # Save full results
        save_json({
            'stats': {
                'total': len(validated),
                'valid': len(valid),
                'working': len(working),
            },
            'proxies': validated
        }, os.path.join(output_dir, 'results.json'))

        return {
            'proxies': validated,
            'working': working,
            'stats': {
                'total': len(validated),
                'valid': len(valid),
                'working': len(working),
            }
        }


# Convenience function for backwards compatibility
async def run_async_scan(
    sources: List[str] = None,
    concurrency: int = 100,
    output_dir: str = './results'
) -> Dict:
    """Run async scan. DEPRECATED."""
    config = {}
    if sources:
        config['sources'] = sources
    scanner = AsyncSocks5Scanner(config)
    return await scanner.run_scan(concurrency=concurrency, output_dir=output_dir)
