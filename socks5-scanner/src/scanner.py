"""
SOCKS5 Proxy Scanner - Collects proxies from multiple sources.

Supports multiple modes:
- Static sources: Pre-configured proxy lists
- Hunt mode: GitHub repository discovery (inspired by Proxy-Hound)
"""

import concurrent.futures
import os
import time
from typing import Dict, List, Optional, Set, Tuple

import requests

from .validator import ProxyValidator
from .utils import (
    Color, extract_proxies_from_text, get_user_agent, parse_proxy,
    load_proxies_from_file, Timer
)


class Socks5Scanner:
    """Scans and collects SOCKS5 proxies from various sources."""

    # Default free proxy sources - comprehensive list
    DEFAULT_SOURCES = [
        # Actively maintained GitHub lists
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        "https://raw.githubusercontent.com/ErcinDedeworken/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
        "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
        # API endpoints
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://proxyspace.pro/socks5.txt",
        "https://spys.me/socks.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
    ]

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.sources = self.config.get('sources', self.DEFAULT_SOURCES)
        self.timeout = self.config.get('timeout', 15)
        self.validator = ProxyValidator(self.config.get('validator', {}))

        # Load custom sources from file if specified
        sources_file = self.config.get('sources_file')
        if sources_file:
            custom_sources = self._load_custom_sources(sources_file)
            self.sources.extend(custom_sources)

    def _load_custom_sources(self, filepath: str) -> List[str]:
        """Load custom proxy sources from a file."""
        sources = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            sources.append(line)
            except Exception:
                pass
        return sources

    def fetch_from_url(self, url: str) -> List[str]:
        """Fetch proxy list from a URL."""
        proxies = []

        try:
            headers = {
                'User-Agent': get_user_agent(),
                'Accept': 'text/plain,*/*',
            }

            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False  # Some sources have SSL issues
            )

            if response.status_code == 200:
                # Extract proxies from response text
                proxies = extract_proxies_from_text(response.text)

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass

        return proxies

    def scan_free_sources(self, show_progress: bool = True) -> List[str]:
        """
        Scan all configured free proxy sources.

        Returns a deduplicated list of proxies.
        """
        all_proxies: Set[str] = set()

        if show_progress:
            print(f"\n{Color.cyan('Scanning')} {len(self.sources)} proxy sources...")

        def fetch_source(url: str) -> tuple:
            proxies = self.fetch_from_url(url)
            return url, proxies

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(fetch_source, url): url
                for url in self.sources
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    url, proxies = future.result()
                    if proxies:
                        if show_progress:
                            # Truncate URL for display
                            display_url = url[:60] + '...' if len(url) > 63 else url
                            print(f"  {Color.green('✓')} {display_url}: "
                                  f"{Color.bold(str(len(proxies)))} proxies")
                        all_proxies.update(proxies)
                    elif show_progress:
                        display_url = url[:60] + '...' if len(url) > 63 else url
                        print(f"  {Color.dim('✗')} {display_url}: no proxies")
                except Exception:
                    pass

        proxy_list = list(all_proxies)

        if show_progress:
            print(f"\n{Color.bold('Total unique proxies collected:')} "
                  f"{Color.green(str(len(proxy_list)))}")

        return proxy_list

    def scan_from_file(self, filepath: str) -> List[str]:
        """Load proxies from a local file."""
        proxies = load_proxies_from_file(filepath)
        print(f"Loaded {len(proxies)} proxies from {filepath}")
        return proxies

    def scan_with_hunter(self, show_progress: bool = True) -> Tuple[List[str], List]:
        """
        Hunt for proxies using GitHub repository discovery.

        Returns (proxies, hunt_results)
        """
        try:
            from .hunter import ProxyHunter
        except ImportError as e:
            print(f"{Color.red('Error:')} Hunter module not available: {e}")
            return [], []

        hunter = ProxyHunter()
        return hunter.hunt(show_progress=show_progress)

    def run_full_scan(self,
                      max_workers: int = 20,
                      mode: str = 'free',
                      output_dir: str = './results',
                      validate: bool = True,
                      proxy_file: Optional[str] = None,
                      use_hunter: bool = False) -> Dict:
        """
        Run a complete proxy scan and validation.

        Args:
            max_workers: Number of threads for validation
            mode: Scan mode ('free', 'file', 'hunt', or 'both')
            output_dir: Directory to save results
            validate: Whether to validate proxies
            proxy_file: Path to proxy file (for 'file' mode)
            use_hunter: Enable GitHub repository hunting

        Returns:
            Dictionary with scan results
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        all_proxies: Set[str] = set()
        hunt_results = []

        print(f"\n{'='*60}")
        print(f"{Color.bold('SOCKS5 Proxy Scanner')}")
        mode_str = mode
        if use_hunter:
            mode_str += " + hunt"
        print(f"Mode: {mode_str} | Workers: {max_workers}")
        print(f"{'='*60}")

        with Timer("Proxy collection") as timer:
            # Collect proxies based on mode
            if mode in ['free', 'both']:
                free_proxies = self.scan_free_sources()
                all_proxies.update(free_proxies)

            if mode in ['file', 'both'] and proxy_file:
                file_proxies = self.scan_from_file(proxy_file)
                all_proxies.update(file_proxies)

            if mode == 'hunt' or use_hunter:
                hunt_proxies, hunt_results = self.scan_with_hunter()
                all_proxies.update(hunt_proxies)

        proxy_list = list(all_proxies)

        if not proxy_list:
            print(f"\n{Color.red('No proxies found!')}")
            return {
                'proxies': [],
                'results': None,
                'stats': {'total': 0, 'valid': 0, 'working': 0, 'failed': 0}
            }

        print(f"\nCollection completed in {timer.get_elapsed():.1f}s")
        print(f"Total unique proxies: {Color.bold(str(len(proxy_list)))}")

        # Validate proxies if requested
        results = None
        if validate:
            results = self.validator.validate_proxies(
                proxy_list,
                max_workers=max_workers,
                show_progress=True
            )

            # Save results
            self.validator.save_results(results, output_dir=output_dir, timestamp=timestamp)

            # Print statistics
            self._print_stats(results)

        return {
            'proxies': proxy_list,
            'results': results,
            'stats': results['stats'] if results else {
                'total': len(proxy_list), 'valid': 0, 'working': 0, 'failed': 0
            }
        }

    def _print_stats(self, results: Dict):
        """Print scan statistics."""
        stats = results.get('stats', {})

        print(f"\n{'='*60}")
        print(f"{Color.bold('Scan Statistics')}")
        print(f"{'='*60}")
        print(f"  Total proxies scanned:  {stats.get('total', 0)}")
        print(f"  Valid (SOCKS5):         {Color.green(str(stats.get('valid', 0)))}")
        print(f"  Working (HTTP tested):  {Color.green(str(stats.get('working', 0)))}")
        print(f"  Failed:                 {Color.red(str(stats.get('failed', 0)))}")
        print(f"{'='*60}")

        # Show some working proxies
        working = results.get('working', [])
        if working:
            print(f"\n{Color.bold('Sample working proxies:')}")
            for proxy_info in working[:5]:
                proxy = proxy_info['proxy']
                response_time = proxy_info.get('response_time_ms', '?')
                ext_ip = proxy_info.get('external_ip', 'N/A')
                print(f"  • {proxy} ({response_time}ms) - IP: {ext_ip}")

            if len(working) > 5:
                print(f"  ... and {len(working) - 5} more")


def quick_scan(max_workers: int = 20, output_dir: str = './results') -> Dict:
    """
    Quick function to scan and validate proxies with default settings.

    Example:
        from src.scanner import quick_scan
        results = quick_scan()
    """
    scanner = Socks5Scanner()
    return scanner.run_full_scan(
        max_workers=max_workers,
        mode='free',
        output_dir=output_dir,
        validate=True
    )
