"""
SOCKS5 Proxy Scanner
A multi-threaded tool for discovering and validating SOCKS5 proxies.
"""

from .scanner import Socks5Scanner
from .validator import ProxyValidator
from .utils import Color, parse_proxy, validate_ip, validate_port

__version__ = "1.0.0"
__all__ = ["Socks5Scanner", "ProxyValidator", "Color", "parse_proxy", "validate_ip", "validate_port"]
