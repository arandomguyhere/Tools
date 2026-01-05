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


class GeoLocator:
    """IP Geolocation lookup using free APIs."""

    # Free geolocation APIs (no API key required)
    GEOIP_APIS = [
        "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as",
        "https://ipwho.is/{ip}",
    ]

    def __init__(self, cache_enabled: bool = True):
        self.cache: Dict[str, Dict] = {}
        self.cache_enabled = cache_enabled

    def lookup(self, ip: str, timeout: int = 3) -> Optional[Dict[str, Any]]:
        """
        Look up geolocation data for an IP address.

        Returns dict with country, city, isp, etc. or None on failure.
        """
        if not validate_ip(ip):
            return None

        # Check cache first
        if self.cache_enabled and ip in self.cache:
            return self.cache[ip]

        import requests

        for api_template in self.GEOIP_APIS:
            try:
                url = api_template.format(ip=ip)
                response = requests.get(url, timeout=timeout)

                if response.status_code == 200:
                    data = response.json()

                    # Normalize response format
                    geo_info = self._normalize_response(data)

                    if geo_info:
                        if self.cache_enabled:
                            self.cache[ip] = geo_info
                        return geo_info

            except Exception:
                continue

        return None

    def _normalize_response(self, data: Dict) -> Optional[Dict[str, Any]]:
        """Normalize different API response formats."""
        # ip-api.com format
        if 'status' in data:
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'asn': data.get('as', ''),
                }
            return None

        # ipwho.is format
        if 'success' in data:
            if data.get('success'):
                return {
                    'country': data.get('country', ''),
                    'country_code': data.get('country_code', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('connection', {}).get('isp', ''),
                    'org': data.get('connection', {}).get('org', ''),
                    'asn': data.get('connection', {}).get('asn', ''),
                }
            return None

        # Generic format (try common fields)
        if 'country' in data or 'country_name' in data:
            return {
                'country': data.get('country') or data.get('country_name', ''),
                'country_code': data.get('country_code', ''),
                'region': data.get('region') or data.get('region_name', ''),
                'city': data.get('city', ''),
                'isp': data.get('isp', ''),
                'org': data.get('org') or data.get('organization', ''),
                'asn': data.get('asn', ''),
            }

        return None

    def lookup_batch(self, ips: List[str], max_workers: int = 5,
                     show_progress: bool = False) -> Dict[str, Dict]:
        """
        Look up geolocation for multiple IPs concurrently.

        Returns dict mapping IP -> geo_info.
        """
        import concurrent.futures

        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.lookup, ip): ip for ip in ips}

            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    geo_info = future.result()
                    if geo_info:
                        results[ip] = geo_info
                except Exception:
                    pass

        return results


def get_geo_info(ip: str) -> Optional[Dict[str, Any]]:
    """Quick helper to get geolocation for a single IP."""
    locator = GeoLocator()
    return locator.lookup(ip)


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
