"""
Utility functions and helper classes for the SOCKS5 proxy scanner.
"""

import ipaddress
import json
import os
import re
import time
from typing import Optional, List, Tuple, Dict, Any
from urllib.parse import urlparse


class Color:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.RESET}"

    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def blue(cls, text: str) -> str:
        return f"{cls.BLUE}{text}{cls.RESET}"

    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.RESET}"

    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.RESET}"

    @classmethod
    def dim(cls, text: str) -> str:
        return f"{cls.DIM}{text}{cls.RESET}"


def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate a port number."""
    return isinstance(port, int) and 1 <= port <= 65535


def parse_proxy(proxy_string: str) -> Optional[Tuple[str, int]]:
    """
    Parse a proxy string into (ip, port) tuple.

    Supports formats:
    - ip:port
    - socks5://ip:port
    - socks5h://ip:port
    """
    proxy_string = proxy_string.strip()

    # Handle URL format
    if proxy_string.startswith(('socks5://', 'socks5h://', 'http://', 'https://')):
        try:
            parsed = urlparse(proxy_string)
            ip = parsed.hostname
            port = parsed.port
            if ip and port:
                return (ip, port)
        except Exception:
            pass
        return None

    # Handle ip:port format
    if ':' in proxy_string:
        parts = proxy_string.split(':')
        if len(parts) == 2:
            ip = parts[0].strip()
            try:
                port = int(parts[1].strip())
                if validate_ip(ip) and validate_port(port):
                    return (ip, port)
            except ValueError:
                pass

    return None


def format_proxy(ip: str, port: int, scheme: str = "") -> str:
    """Format IP and port as a proxy string."""
    if scheme:
        return f"{scheme}://{ip}:{port}"
    return f"{ip}:{port}"


def load_proxies_from_file(filepath: str) -> List[str]:
    """Load proxy list from a file (one proxy per line)."""
    proxies = []

    if not os.path.exists(filepath):
        return proxies

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    proxies.append(line)
    except Exception:
        pass

    return proxies


def save_proxies_to_file(proxies: List[str], filepath: str) -> bool:
    """Save proxy list to a file."""
    try:
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for proxy in proxies:
                f.write(f"{proxy}\n")
        return True
    except Exception:
        return False


def load_json(filepath: str) -> Optional[Dict]:
    """Safely load JSON from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(data: Any, filepath: str, indent: int = 2) -> bool:
    """Safely save data as JSON to file."""
    try:
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception:
        return False


def format_time(seconds: float) -> str:
    """Format seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_size(bytes_size: int) -> str:
    """Format bytes into a human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} PB"


def progress_bar(current: int, total: int, width: int = 40, prefix: str = "") -> str:
    """Generate a text-based progress bar."""
    if total == 0:
        percentage = 100
    else:
        percentage = (current / total) * 100

    filled = int(width * current / total) if total > 0 else width
    bar = '█' * filled + '░' * (width - filled)

    return f"{prefix}|{bar}| {current}/{total} ({percentage:.1f}%)"


class Timer:
    """Context manager for timing operations."""

    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
        self.elapsed = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, *args):
        self.end_time = time.time()
        self.elapsed = self.end_time - self.start_time

    def get_elapsed(self) -> float:
        if self.elapsed is not None:
            return self.elapsed
        if self.start_time is not None:
            return time.time() - self.start_time
        return 0.0


def print_banner():
    """Print the application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║           SOCKS5 Proxy Scanner v1.0.0                     ║
║     Multi-threaded Proxy Discovery & Validation           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(Color.cyan(banner))


def print_table(headers: List[str], rows: List[List[str]],
                col_widths: Optional[List[int]] = None):
    """Print a formatted ASCII table."""
    if not col_widths:
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width + 2)

    # Print header
    header_line = "│"
    separator = "├"
    top_border = "┌"
    bottom_border = "└"

    for i, (header, width) in enumerate(zip(headers, col_widths)):
        header_line += f" {header:<{width-1}}│"
        sep_char = "┼" if i < len(headers) - 1 else "┤"
        top_char = "┬" if i < len(headers) - 1 else "┐"
        bottom_char = "┴" if i < len(headers) - 1 else "┘"
        separator += "─" * width + sep_char
        top_border += "─" * width + top_char
        bottom_border += "─" * width + bottom_char

    print(top_border)
    print(header_line)
    print(separator)

    # Print rows
    for row in rows:
        row_line = "│"
        for i, width in enumerate(col_widths):
            value = str(row[i]) if i < len(row) else ""
            row_line += f" {value:<{width-1}}│"
        print(row_line)

    print(bottom_border)


def get_user_agent() -> str:
    """Return a common User-Agent string for HTTP requests."""
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def extract_proxies_from_text(text: str) -> List[str]:
    """Extract proxy addresses (ip:port) from arbitrary text."""
    # Pattern to match IP:PORT
    pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b'
    matches = re.findall(pattern, text)

    proxies = []
    for ip, port in matches:
        try:
            port_num = int(port)
            if validate_ip(ip) and validate_port(port_num):
                proxies.append(f"{ip}:{port}")
        except ValueError:
            continue

    return list(set(proxies))  # Remove duplicates


class IPEnricher:
    """
    Comprehensive IP enrichment with ASN, geolocation, and ownership data.

    Uses multiple free APIs with fallback for reliability.
    """

    # API providers with rate limits (requests per minute)
    PROVIDERS = {
        'ip-api': {
            'url': 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query',
            'rate_limit': 45,  # 45/min for free tier
        },
        'ipwho': {
            'url': 'https://ipwho.is/{ip}',
            'rate_limit': 10000,  # Very generous
        },
        'ipapi': {
            'url': 'https://ipapi.co/{ip}/json/',
            'rate_limit': 30,  # 1000/day ~ 30/min average
        },
    }

    def __init__(self, cache_enabled: bool = True, max_cache_size: int = 10000):
        self.cache: Dict[str, Dict] = {}
        self.cache_enabled = cache_enabled
        self.max_cache_size = max_cache_size
        self._request_counts: Dict[str, int] = {p: 0 for p in self.PROVIDERS}

    def enrich(self, ip: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Enrich an IP address with full ASN, geo, and ownership data.

        Returns comprehensive dict with:
        - Geolocation: country, country_code, region, city, lat, lon, timezone
        - Network: asn, asn_name, isp, org
        - Ownership: org, isp, hosting (datacenter), mobile, proxy
        """
        if not validate_ip(ip):
            return None

        # Check cache
        if self.cache_enabled and ip in self.cache:
            return self.cache[ip]

        import requests

        result = None

        # Try providers in order
        for provider_name, provider_config in self.PROVIDERS.items():
            try:
                url = provider_config['url'].format(ip=ip)
                response = requests.get(url, timeout=timeout, headers={
                    'User-Agent': get_user_agent(),
                    'Accept': 'application/json',
                })

                if response.status_code == 200:
                    data = response.json()
                    result = self._parse_response(provider_name, data, ip)

                    if result:
                        break

                elif response.status_code == 429:
                    # Rate limited, try next provider
                    continue

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        # Cache result
        if result and self.cache_enabled:
            if len(self.cache) >= self.max_cache_size:
                # Remove oldest entries (simple FIFO)
                keys_to_remove = list(self.cache.keys())[:1000]
                for key in keys_to_remove:
                    del self.cache[key]
            self.cache[ip] = result

        return result

    def _parse_response(self, provider: str, data: Dict, ip: str) -> Optional[Dict[str, Any]]:
        """Parse response from different providers into unified format."""

        if provider == 'ip-api':
            if data.get('status') != 'success':
                return None

            asn_full = data.get('as', '')
            asn_number = ''
            asn_name = data.get('asname', '')

            # Parse ASN number from "AS12345 Company Name" format
            if asn_full and asn_full.startswith('AS'):
                parts = asn_full.split(' ', 1)
                asn_number = parts[0]  # AS12345
                if len(parts) > 1 and not asn_name:
                    asn_name = parts[1]

            return {
                'ip': ip,
                # Geolocation
                'country': data.get('country', ''),
                'country_code': data.get('countryCode', ''),
                'region': data.get('regionName', '') or data.get('region', ''),
                'region_code': data.get('region', ''),
                'city': data.get('city', ''),
                'zip': data.get('zip', ''),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone', ''),
                # Network / ASN
                'asn': asn_number,
                'asn_name': asn_name,
                'asn_full': asn_full,
                # Ownership
                'isp': data.get('isp', ''),
                'org': data.get('org', ''),
                'is_mobile': data.get('mobile', False),
                'is_proxy': data.get('proxy', False),
                'is_hosting': data.get('hosting', False),
                # Provider info
                '_provider': 'ip-api',
            }

        elif provider == 'ipwho':
            if not data.get('success', False):
                return None

            connection = data.get('connection', {})

            return {
                'ip': ip,
                # Geolocation
                'country': data.get('country', ''),
                'country_code': data.get('country_code', ''),
                'region': data.get('region', ''),
                'region_code': data.get('region_code', ''),
                'city': data.get('city', ''),
                'zip': data.get('postal', ''),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone', {}).get('id', ''),
                # Network / ASN
                'asn': f"AS{connection.get('asn', '')}" if connection.get('asn') else '',
                'asn_name': connection.get('org', ''),
                'asn_full': f"AS{connection.get('asn', '')} {connection.get('org', '')}".strip(),
                # Ownership
                'isp': connection.get('isp', ''),
                'org': connection.get('org', ''),
                'is_mobile': data.get('type') == 'mobile',
                'is_proxy': False,  # Not provided
                'is_hosting': data.get('type') == 'hosting',
                # Provider info
                '_provider': 'ipwho',
            }

        elif provider == 'ipapi':
            if data.get('error'):
                return None

            asn = data.get('asn', '')

            return {
                'ip': ip,
                # Geolocation
                'country': data.get('country_name', ''),
                'country_code': data.get('country_code', ''),
                'region': data.get('region', ''),
                'region_code': data.get('region_code', ''),
                'city': data.get('city', ''),
                'zip': data.get('postal', ''),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone', ''),
                # Network / ASN
                'asn': asn,
                'asn_name': data.get('org', ''),
                'asn_full': f"{asn} {data.get('org', '')}".strip(),
                # Ownership
                'isp': data.get('org', ''),
                'org': data.get('org', ''),
                'is_mobile': False,  # Not provided
                'is_proxy': False,   # Not provided
                'is_hosting': False, # Not provided
                # Provider info
                '_provider': 'ipapi',
            }

        return None

    def enrich_batch(self, ips: List[str], max_workers: int = 10,
                     show_progress: bool = False,
                     rate_limit_delay: float = 0.1) -> Dict[str, Dict]:
        """
        Enrich multiple IPs concurrently with rate limiting.

        Args:
            ips: List of IP addresses
            max_workers: Concurrent threads
            show_progress: Print progress
            rate_limit_delay: Delay between requests (seconds)

        Returns:
            Dict mapping IP -> enrichment data
        """
        import concurrent.futures
        import threading

        results = {}
        lock = threading.Lock()
        completed = 0

        def enrich_with_delay(ip: str) -> Tuple[str, Optional[Dict]]:
            nonlocal completed
            time.sleep(rate_limit_delay)  # Rate limiting
            result = self.enrich(ip)
            with lock:
                completed += 1
                if show_progress and completed % 50 == 0:
                    print(f"\r  Enriched {completed}/{len(ips)} IPs...", end='')
            return ip, result

        # Deduplicate IPs
        unique_ips = list(set(ips))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(enrich_with_delay, ip) for ip in unique_ips]

            for future in concurrent.futures.as_completed(futures):
                try:
                    ip, data = future.result()
                    if data:
                        results[ip] = data
                except Exception:
                    pass

        if show_progress:
            print(f"\r  Enriched {len(results)}/{len(unique_ips)} IPs successfully")

        return results


# Backwards compatibility alias
GeoLocator = IPEnricher


def get_geo_info(ip: str) -> Optional[Dict[str, Any]]:
    """Quick helper to get geolocation for a single IP."""
    enricher = IPEnricher()
    return enricher.enrich(ip)


def format_geo_info(geo: Optional[Dict]) -> str:
    """Format geolocation info as a short string."""
    if not geo:
        return "Unknown"

    parts = []
    if geo.get('city'):
        parts.append(geo['city'])
    if geo.get('country_code'):
        parts.append(geo['country_code'])
    elif geo.get('country'):
        parts.append(geo['country'][:20])

    return ", ".join(parts) if parts else "Unknown"


def format_asn_info(geo: Optional[Dict]) -> str:
    """Format ASN info as a string."""
    if not geo:
        return "Unknown"

    asn = geo.get('asn', '')
    asn_name = geo.get('asn_name', '')

    if asn and asn_name:
        return f"{asn} ({asn_name[:30]})"
    elif asn:
        return asn
    elif asn_name:
        return asn_name[:40]
    return "Unknown"


def format_ownership_info(geo: Optional[Dict]) -> str:
    """Format ownership/ISP info as a string."""
    if not geo:
        return "Unknown"

    isp = geo.get('isp', '')
    org = geo.get('org', '')

    # Prefer ISP if different from org
    if isp and org and isp != org:
        return f"{isp} / {org}"[:50]
    elif isp:
        return isp[:50]
    elif org:
        return org[:50]
    return "Unknown"


def format_proxy_type(geo: Optional[Dict]) -> str:
    """Determine proxy type based on enrichment data."""
    if not geo:
        return "unknown"

    types = []
    if geo.get('is_hosting'):
        types.append("datacenter")
    if geo.get('is_mobile'):
        types.append("mobile")
    if geo.get('is_proxy'):
        types.append("proxy")

    if not types:
        types.append("residential")

    return "/".join(types)
