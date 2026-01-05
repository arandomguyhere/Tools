"""
Proxy Validator - Tests SOCKS5 proxy connectivity and functionality.
"""

import concurrent.futures
import os
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple, Any

import requests

from .utils import (
    Color, parse_proxy, format_proxy, save_json, save_proxies_to_file,
    progress_bar, format_time, Timer
)


class ProxyValidator:
    """Validates SOCKS5 proxies for connectivity and functionality."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 5)
        self.test_urls = self.config.get('test_urls', [
            "http://httpbin.org/ip",
            "http://icanhazip.com",
        ])
        self.verify_ssl = self.config.get('verify_ssl', False)

    def test_socks5_handshake(self, ip: str, port: int,
                               timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Test SOCKS5 proxy handshake.

        Returns:
            Tuple of (success: bool, message: str)
        """
        timeout = timeout or self.timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Connect to proxy
            sock.connect((ip, port))

            # SOCKS5 greeting: version(1) + nmethods(1) + methods(nmethods)
            # We send: version=5, nmethods=1, method=0 (no auth)
            sock.sendall(b'\x05\x01\x00')

            # Receive response: version(1) + method(1)
            response = sock.recv(2)

            sock.close()

            if len(response) < 2:
                return False, "Invalid response"

            if response[0:1] != b'\x05':
                return False, "Not SOCKS5"

            if response[1:2] == b'\x00':
                return True, "OK (no auth)"
            elif response[1:2] == b'\x02':
                return True, "OK (auth required)"
            elif response[1:2] == b'\xff':
                return False, "No acceptable methods"
            else:
                return False, f"Unknown method: {response[1]}"

        except socket.timeout:
            return False, "Timeout"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except ConnectionResetError:
            return False, "Connection reset"
        except OSError as e:
            return False, f"OS error: {e}"
        except Exception as e:
            return False, str(e)

    def test_socks5_connect(self, ip: str, port: int,
                            target_host: str = "httpbin.org",
                            target_port: int = 80,
                            timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Test SOCKS5 proxy by connecting to a target through it.

        Returns:
            Tuple of (success: bool, message: str)
        """
        timeout = timeout or self.timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Connect to proxy
            sock.connect((ip, port))

            # SOCKS5 handshake
            sock.sendall(b'\x05\x01\x00')
            response = sock.recv(2)

            if response != b'\x05\x00':
                sock.close()
                return False, "Handshake failed"

            # SOCKS5 connect request
            # version(1) + cmd(1) + rsv(1) + atyp(1) + dst.addr(variable) + dst.port(2)
            # cmd: 0x01 = connect
            # atyp: 0x03 = domain name

            domain_bytes = target_host.encode('utf-8')
            request = (
                b'\x05\x01\x00\x03' +
                bytes([len(domain_bytes)]) +
                domain_bytes +
                struct.pack('>H', target_port)
            )
            sock.sendall(request)

            # Receive response
            response = sock.recv(10)
            sock.close()

            if len(response) < 2:
                return False, "Invalid connect response"

            if response[0:1] != b'\x05':
                return False, "Not SOCKS5"

            reply_code = response[1]
            if reply_code == 0x00:
                return True, "Connection successful"
            elif reply_code == 0x01:
                return False, "General failure"
            elif reply_code == 0x02:
                return False, "Connection not allowed"
            elif reply_code == 0x03:
                return False, "Network unreachable"
            elif reply_code == 0x04:
                return False, "Host unreachable"
            elif reply_code == 0x05:
                return False, "Connection refused by target"
            elif reply_code == 0x06:
                return False, "TTL expired"
            elif reply_code == 0x07:
                return False, "Command not supported"
            elif reply_code == 0x08:
                return False, "Address type not supported"
            else:
                return False, f"Unknown error: {reply_code}"

        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)

    def test_http_through_proxy(self, proxy: str,
                                 url: Optional[str] = None,
                                 timeout: Optional[int] = None) -> Tuple[bool, str, Optional[str]]:
        """
        Test HTTP request through SOCKS5 proxy.

        Returns:
            Tuple of (success: bool, message: str, response_ip: Optional[str])
        """
        url = url or self.test_urls[0]
        timeout = timeout or self.timeout

        proxies = {
            'http': f'socks5h://{proxy}',
            'https': f'socks5h://{proxy}'
        }

        try:
            response = requests.get(
                url,
                proxies=proxies,
                timeout=timeout,
                verify=self.verify_ssl,
                headers={'User-Agent': 'curl/7.88.0'}
            )

            if response.status_code == 200:
                # Try to extract IP from response if it's an IP check service
                try:
                    if 'origin' in response.text.lower() or 'ip' in url.lower():
                        data = response.json()
                        ip = data.get('origin', data.get('ip', ''))
                        return True, "HTTP OK", ip
                except Exception:
                    pass
                return True, "HTTP OK", None

            return False, f"HTTP {response.status_code}", None

        except requests.exceptions.Timeout:
            return False, "HTTP timeout", None
        except requests.exceptions.ProxyError as e:
            return False, "Proxy error", None
        except requests.exceptions.ConnectionError:
            return False, "Connection error", None
        except Exception as e:
            return False, str(e), None

    def validate_proxy(self, proxy: str) -> Dict[str, Any]:
        """
        Fully validate a single proxy.

        Returns a dict with validation results.
        """
        result = {
            'proxy': proxy,
            'valid': False,
            'socks5_handshake': False,
            'socks5_connect': False,
            'http_working': False,
            'response_time_ms': None,
            'external_ip': None,
            'error': None
        }

        parsed = parse_proxy(proxy)
        if not parsed:
            result['error'] = "Invalid proxy format"
            return result

        ip, port = parsed
        start_time = time.time()

        # Test 1: SOCKS5 handshake
        success, msg = self.test_socks5_handshake(ip, port)
        result['socks5_handshake'] = success
        if not success:
            result['error'] = f"Handshake: {msg}"
            return result

        # Test 2: SOCKS5 connect
        success, msg = self.test_socks5_connect(ip, port)
        result['socks5_connect'] = success
        if not success:
            result['error'] = f"Connect: {msg}"
            # Still mark as valid if handshake passed
            result['valid'] = result['socks5_handshake']
            result['response_time_ms'] = int((time.time() - start_time) * 1000)
            return result

        # Test 3: HTTP through proxy
        success, msg, ext_ip = self.test_http_through_proxy(proxy)
        result['http_working'] = success
        result['external_ip'] = ext_ip

        result['valid'] = result['socks5_handshake']
        result['response_time_ms'] = int((time.time() - start_time) * 1000)

        if not success:
            result['error'] = f"HTTP: {msg}"

        return result

    def validate_proxies(self, proxies: List[str],
                         max_workers: int = 20,
                         show_progress: bool = True) -> Dict[str, Any]:
        """
        Validate multiple proxies concurrently.

        Returns a dict with all results and statistics.
        """
        results = {
            'all': [],
            'valid': [],
            'working': [],
            'stats': {
                'total': len(proxies),
                'valid': 0,
                'working': 0,
                'failed': 0
            }
        }

        if not proxies:
            return results

        if show_progress:
            print(f"\n{Color.cyan('Validating')} {len(proxies)} proxies "
                  f"with {max_workers} threads...")

        completed = 0
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {
                executor.submit(self.validate_proxy, proxy): proxy
                for proxy in proxies
            }

            for future in concurrent.futures.as_completed(future_to_proxy):
                try:
                    result = future.result()
                    results['all'].append(result)

                    if result['valid']:
                        results['valid'].append(result)
                        results['stats']['valid'] += 1

                        if result['http_working']:
                            results['working'].append(result)
                            results['stats']['working'] += 1
                    else:
                        results['stats']['failed'] += 1

                except Exception as e:
                    results['stats']['failed'] += 1

                completed += 1

                if show_progress and completed % 10 == 0:
                    print(f"\r{progress_bar(completed, len(proxies), prefix='Progress: ')}", end='')

        if show_progress:
            print(f"\r{progress_bar(completed, len(proxies), prefix='Progress: ')}")
            elapsed = time.time() - start_time
            print(f"Completed in {format_time(elapsed)}")

        return results

    def save_results(self, results: Dict, output_dir: str = "./results",
                     timestamp: Optional[str] = None) -> Dict[str, str]:
        """
        Save validation results to files.

        Returns dict of saved file paths.
        """
        import time as time_module

        timestamp = timestamp or time_module.strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

        saved_files = {}

        # Save full results as JSON
        json_path = os.path.join(output_dir, f"results_{timestamp}.json")
        if save_json(results, json_path):
            saved_files['json'] = json_path

        # Save valid proxies as text
        valid_proxies = [r['proxy'] for r in results.get('valid', [])]
        if valid_proxies:
            txt_path = os.path.join(output_dir, f"valid_proxies_{timestamp}.txt")
            if save_proxies_to_file(valid_proxies, txt_path):
                saved_files['valid_txt'] = txt_path

        # Save working proxies (HTTP tested) as text
        working_proxies = [r['proxy'] for r in results.get('working', [])]
        if working_proxies:
            txt_path = os.path.join(output_dir, f"working_proxies_{timestamp}.txt")
            if save_proxies_to_file(working_proxies, txt_path):
                saved_files['working_txt'] = txt_path

        print(f"\n{Color.green('Results saved:')}")
        for key, path in saved_files.items():
            print(f"  - {path}")

        return saved_files

    def test_proxy_file(self, filepath: str,
                        max_workers: int = 20) -> Dict[str, Any]:
        """
        Load and test proxies from a file.
        """
        from .utils import load_proxies_from_file

        proxies = load_proxies_from_file(filepath)

        if not proxies:
            print(f"{Color.red('Error:')} No proxies found in {filepath}")
            return {'all': [], 'valid': [], 'working': [], 'stats': {
                'total': 0, 'valid': 0, 'working': 0, 'failed': 0
            }}

        print(f"Loaded {len(proxies)} proxies from {filepath}")
        return self.validate_proxies(proxies, max_workers=max_workers)
