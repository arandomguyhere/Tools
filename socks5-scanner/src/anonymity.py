"""
Anonymity Detection Module

Detects proxy anonymity level by checking for IP leaks in HTTP headers.

Anonymity Levels:
- TRANSPARENT: Proxy reveals your real IP (X-Forwarded-For, Via, etc.)
- ANONYMOUS: Proxy hides your IP but reveals it's a proxy
- ELITE: No trace of proxy usage, appears as direct connection
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, List, Set

import requests

logger = logging.getLogger(__name__)


class AnonymityLevel(Enum):
    """Proxy anonymity classification."""
    TRANSPARENT = "transparent"
    ANONYMOUS = "anonymous"
    ELITE = "elite"
    UNKNOWN = "unknown"


# Headers that can leak real IP or reveal proxy usage
LEAK_HEADERS = {
    # Headers that leak real IP (TRANSPARENT)
    'X-Forwarded-For',
    'X-Real-IP',
    'X-Client-IP',
    'X-Originating-IP',
    'X-Remote-IP',
    'X-Remote-Addr',
    'X-Host',
    'Forwarded',
    'Forwarded-For',
    'X-Forwarded',
    'Client-IP',
    'Real-IP',
    'True-Client-IP',
    'CF-Connecting-IP',
    'X-Cluster-Client-IP',
    'Fastly-Client-IP',
    'X-Azure-ClientIP',
}

# Headers that reveal proxy usage (ANONYMOUS)
PROXY_HEADERS = {
    'Via',
    'Proxy-Connection',
    'X-Proxy-ID',
    'X-Proxy-Connection',
    'X-BlueCoat-Via',
    'X-Cache',
    'X-Cached',
    'X-Squid-Error',
}


@dataclass
class AnonymityResult:
    """Result of anonymity detection."""

    level: AnonymityLevel
    real_ip_leaked: bool = False
    proxy_detected: bool = False
    leaked_headers: List[str] = None
    proxy_headers: List[str] = None
    external_ip: Optional[str] = None
    details: Optional[str] = None

    def __post_init__(self):
        if self.leaked_headers is None:
            self.leaked_headers = []
        if self.proxy_headers is None:
            self.proxy_headers = []

    def to_dict(self) -> Dict:
        return {
            'level': self.level.value,
            'real_ip_leaked': self.real_ip_leaked,
            'proxy_detected': self.proxy_detected,
            'leaked_headers': self.leaked_headers,
            'proxy_headers': self.proxy_headers,
            'external_ip': self.external_ip,
            'details': self.details,
        }


class AnonymityChecker:
    """
    Checks proxy anonymity level by analyzing HTTP headers.

    Uses a judge server that echoes back all received headers.
    """

    # Judge servers that echo headers back
    JUDGE_URLS = [
        'http://httpbin.org/headers',
        'http://httpheader.net/azenv.php',
        'https://www.proxy-listen.de/azenv.php',
    ]

    def __init__(self, real_ip: Optional[str] = None, timeout: int = 10):
        """
        Args:
            real_ip: Your real IP address (for leak detection)
            timeout: Request timeout in seconds
        """
        self.real_ip = real_ip
        self.timeout = timeout
        self._session = None

    def _get_real_ip(self) -> Optional[str]:
        """Detect real IP by making direct request."""
        if self.real_ip:
            return self.real_ip

        try:
            response = requests.get(
                'https://api.ipify.org?format=json',
                timeout=5
            )
            if response.status_code == 200:
                self.real_ip = response.json().get('ip')
                return self.real_ip
        except Exception:
            pass

        try:
            response = requests.get(
                'http://httpbin.org/ip',
                timeout=5
            )
            if response.status_code == 200:
                self.real_ip = response.json().get('origin', '').split(',')[0].strip()
                return self.real_ip
        except Exception:
            pass

        return None

    def check(self, proxy: str, get_real_ip: bool = True) -> AnonymityResult:
        """
        Check anonymity level of a proxy.

        Args:
            proxy: Proxy address (ip:port)
            get_real_ip: Whether to fetch real IP first (for comparison)

        Returns:
            AnonymityResult with detected level and details
        """
        # Get real IP if needed
        if get_real_ip and not self.real_ip:
            self._get_real_ip()

        proxies = {
            'http': f'socks5h://{proxy}',
            'https': f'socks5h://{proxy}'
        }

        # Try each judge server
        for judge_url in self.JUDGE_URLS:
            try:
                result = self._check_with_judge(judge_url, proxies)
                if result:
                    return result
            except Exception as e:
                logger.debug(f"Judge {judge_url} failed: {e}")
                continue

        return AnonymityResult(
            level=AnonymityLevel.UNKNOWN,
            details="All judge servers failed"
        )

    def _check_with_judge(self, judge_url: str, proxies: dict) -> Optional[AnonymityResult]:
        """Check anonymity using a specific judge server."""
        try:
            response = requests.get(
                judge_url,
                proxies=proxies,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            if response.status_code != 200:
                return None

            return self._analyze_response(response)

        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _analyze_response(self, response: requests.Response) -> AnonymityResult:
        """Analyze judge response for anonymity indicators."""
        leaked_headers = []
        proxy_headers = []
        real_ip_leaked = False
        proxy_detected = False
        external_ip = None

        # Parse response - handle both JSON and text formats
        content = response.text.upper()

        try:
            data = response.json()
            headers = data.get('headers', {})
            # Convert to uppercase for comparison
            headers = {k.upper(): v for k, v in headers.items()}
        except Exception:
            # Plain text response - parse manually
            headers = {}
            for line in content.split('\n'):
                if '=' in line or ':' in line:
                    sep = '=' if '=' in line else ':'
                    parts = line.split(sep, 1)
                    if len(parts) == 2:
                        headers[parts[0].strip()] = parts[1].strip()

        # Check for IP leaks
        for header in LEAK_HEADERS:
            header_upper = header.upper()
            if header_upper in headers:
                value = headers[header_upper]
                leaked_headers.append(f"{header}: {value}")

                # Check if real IP is in the value
                if self.real_ip and self.real_ip in str(value):
                    real_ip_leaked = True

        # Check for proxy indicators
        for header in PROXY_HEADERS:
            header_upper = header.upper()
            if header_upper in headers:
                value = headers[header_upper]
                proxy_headers.append(f"{header}: {value}")
                proxy_detected = True

        # Also check response body for real IP
        if self.real_ip and self.real_ip in content:
            real_ip_leaked = True

        # Try to extract external IP
        for key in ['X-REAL-IP', 'REMOTE_ADDR', 'ORIGIN']:
            if key in headers:
                external_ip = headers[key]
                break

        # Determine anonymity level
        if real_ip_leaked:
            level = AnonymityLevel.TRANSPARENT
            details = f"Real IP leaked via: {', '.join(leaked_headers)}"
        elif proxy_detected or leaked_headers:
            level = AnonymityLevel.ANONYMOUS
            details = f"Proxy detected via: {', '.join(proxy_headers + leaked_headers)}"
        else:
            level = AnonymityLevel.ELITE
            details = "No IP leaks or proxy indicators detected"

        return AnonymityResult(
            level=level,
            real_ip_leaked=real_ip_leaked,
            proxy_detected=proxy_detected,
            leaked_headers=leaked_headers,
            proxy_headers=proxy_headers,
            external_ip=external_ip,
            details=details
        )


def check_anonymity(proxy: str, real_ip: Optional[str] = None) -> AnonymityResult:
    """
    Quick function to check proxy anonymity.

    Args:
        proxy: Proxy address (ip:port)
        real_ip: Your real IP (optional, will be detected)

    Returns:
        AnonymityResult
    """
    checker = AnonymityChecker(real_ip=real_ip)
    return checker.check(proxy)
