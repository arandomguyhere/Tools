"""
UDP ASSOCIATE Testing Module - RFC 1928 Section 7

Tests if a SOCKS5 proxy supports UDP relay (CMD=0x03).
This is a distinguishing feature that most scanners don't test.

Protocol Flow:
1. Establish TCP control connection
2. SOCKS5 handshake (version, auth negotiation)
3. Send UDP ASSOCIATE request (CMD=0x03)
4. Parse BND.ADDR:BND.PORT from reply
5. Send encapsulated UDP datagram to relay
6. Verify response received

References:
- RFC 1928: https://datatracker.ietf.org/doc/html/rfc1928
- asyncio-socks-server: https://github.com/Amaindex/asyncio-socks-server
"""

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# SOCKS5 Protocol Constants (RFC 1928)
SOCKS5_VERSION = 0x05
SOCKS5_RSV = 0x00

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address Types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Auth Methods
AUTH_NONE = 0x00
AUTH_GSSAPI = 0x01
AUTH_USER_PASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# Reply Codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

# Reply code descriptions
REPLY_CODES = {
    0x00: "Success",
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported",
    0x08: "Address type not supported",
}


class UDPTestResult(Enum):
    """Result of UDP ASSOCIATE test."""
    SUCCESS = "success"              # UDP works fully
    SUPPORTED = "supported"          # UDP ASSOCIATE accepted, relay untested
    NOT_SUPPORTED = "not_supported"  # Proxy returned CMD_NOT_SUPPORTED
    AUTH_REQUIRED = "auth_required"  # Auth required for UDP
    FAILED = "failed"                # Other failure
    TIMEOUT = "timeout"              # Timeout during test
    ERROR = "error"                  # Unexpected error


@dataclass
class UDPAssociateResult:
    """Result of UDP ASSOCIATE test."""

    proxy: str
    udp_supported: bool = False
    udp_works: bool = False
    result: UDPTestResult = UDPTestResult.ERROR

    # Timing
    handshake_ms: Optional[float] = None
    relay_ms: Optional[float] = None

    # Details
    bnd_addr: Optional[str] = None
    bnd_port: Optional[int] = None
    reply_code: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "proxy": self.proxy,
            "udp_supported": self.udp_supported,
            "udp_works": self.udp_works,
            "result": self.result.value,
            "handshake_ms": self.handshake_ms,
            "relay_ms": self.relay_ms,
            "bnd_addr": self.bnd_addr,
            "bnd_port": self.bnd_port,
            "reply_code": self.reply_code,
            "reply_msg": REPLY_CODES.get(self.reply_code, "Unknown") if self.reply_code else None,
            "error": self.error,
        }


def parse_address(data: bytes, offset: int = 0) -> Tuple[str, int, int]:
    """
    Parse SOCKS5 address from bytes.

    Returns: (address, port, bytes_consumed)
    """
    atyp = data[offset]
    offset += 1

    if atyp == ATYP_IPV4:
        addr = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == ATYP_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    elif atyp == ATYP_DOMAIN:
        length = data[offset]
        offset += 1
        addr = data[offset:offset + length].decode('utf-8')
        offset += length
    else:
        raise ValueError(f"Unknown address type: {atyp}")

    port = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2

    return addr, port, offset


def build_udp_header(dst_addr: str, dst_port: int, frag: int = 0) -> bytes:
    """
    Build SOCKS5 UDP request header (RFC 1928 Section 7).

    Format:
    +------+------+------+----------+----------+
    |  RSV | FRAG | ATYP | DST.ADDR | DST.PORT |
    +------+------+------+----------+----------+
    |  2   |  1   |  1   | Variable |    2     |
    +------+------+------+----------+----------+
    """
    header = struct.pack("!HB", 0, frag)  # RSV (2 bytes), FRAG (1 byte)

    # Try to parse as IP address
    try:
        # IPv4
        addr_bytes = socket.inet_aton(dst_addr)
        header += struct.pack("!B", ATYP_IPV4)
        header += addr_bytes
    except socket.error:
        try:
            # IPv6
            addr_bytes = socket.inet_pton(socket.AF_INET6, dst_addr)
            header += struct.pack("!B", ATYP_IPV6)
            header += addr_bytes
        except socket.error:
            # Domain name
            domain_bytes = dst_addr.encode('utf-8')
            header += struct.pack("!BB", ATYP_DOMAIN, len(domain_bytes))
            header += domain_bytes

    header += struct.pack("!H", dst_port)
    return header


def parse_udp_header(data: bytes) -> Tuple[int, int, str, int, bytes]:
    """
    Parse SOCKS5 UDP response header.

    Returns: (rsv, frag, src_addr, src_port, payload)
    """
    if len(data) < 7:
        raise ValueError("UDP response too short")

    rsv = struct.unpack("!H", data[0:2])[0]
    frag = data[2]

    src_addr, src_port, offset = parse_address(data, 3)
    payload = data[offset:]

    return rsv, frag, src_addr, src_port, payload


class UDPProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol for receiving relay responses."""

    def __init__(self):
        self.transport = None
        self.response_future: Optional[asyncio.Future] = None
        self.response_data: Optional[bytes] = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        self.response_data = data
        if self.response_future and not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc):
        if self.response_future and not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc):
        if self.response_future and not self.response_future.done():
            if exc:
                self.response_future.set_exception(exc)
            else:
                self.response_future.cancel()


async def test_udp_associate(
    proxy_host: str,
    proxy_port: int,
    timeout: float = 10.0,
    test_dns: bool = True,
    dns_server: str = "8.8.8.8",
    dns_port: int = 53,
) -> UDPAssociateResult:
    """
    Test if a SOCKS5 proxy supports UDP ASSOCIATE.

    Protocol:
    1. TCP connect to proxy
    2. SOCKS5 handshake
    3. Send UDP ASSOCIATE request (CMD=0x03)
    4. Parse BND.ADDR:BND.PORT from reply
    5. Optionally: Send DNS query via UDP relay to verify it works

    Args:
        proxy_host: Proxy IP address
        proxy_port: Proxy port
        timeout: Timeout in seconds
        test_dns: Whether to test actual UDP relay with DNS query
        dns_server: DNS server to test with
        dns_port: DNS port (usually 53)

    Returns:
        UDPAssociateResult with test results
    """
    result = UDPAssociateResult(proxy=f"{proxy_host}:{proxy_port}")
    reader = None
    writer = None
    udp_transport = None

    try:
        start_time = time.perf_counter()

        # Step 1: TCP connect to proxy
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            result.result = UDPTestResult.TIMEOUT
            result.error = "TCP connection timeout"
            return result
        except Exception as e:
            result.result = UDPTestResult.FAILED
            result.error = f"TCP connection failed: {e}"
            return result

        # Step 2: SOCKS5 handshake - send greeting
        # VER (1) | NMETHODS (1) | METHODS (1-255)
        writer.write(bytes([SOCKS5_VERSION, 1, AUTH_NONE]))
        await writer.drain()

        # Read auth response
        auth_response = await asyncio.wait_for(reader.read(2), timeout=timeout)
        if len(auth_response) < 2:
            result.result = UDPTestResult.FAILED
            result.error = "Invalid auth response"
            return result

        if auth_response[0] != SOCKS5_VERSION:
            result.result = UDPTestResult.FAILED
            result.error = f"Not SOCKS5: version={auth_response[0]}"
            return result

        if auth_response[1] == AUTH_NO_ACCEPTABLE:
            result.result = UDPTestResult.AUTH_REQUIRED
            result.error = "Authentication required"
            return result

        if auth_response[1] != AUTH_NONE:
            result.result = UDPTestResult.AUTH_REQUIRED
            result.error = f"Unsupported auth method: {auth_response[1]}"
            return result

        # Step 3: Send UDP ASSOCIATE request
        # VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        # Use 0.0.0.0:0 as we don't know our UDP address yet
        udp_request = bytes([
            SOCKS5_VERSION,
            CMD_UDP_ASSOCIATE,
            SOCKS5_RSV,
            ATYP_IPV4,
        ]) + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)

        writer.write(udp_request)
        await writer.drain()

        # Step 4: Read UDP ASSOCIATE response
        # VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
        response = await asyncio.wait_for(reader.read(256), timeout=timeout)

        if len(response) < 10:
            result.result = UDPTestResult.FAILED
            result.error = f"Response too short: {len(response)} bytes"
            return result

        ver, rep, rsv = response[0], response[1], response[2]
        result.reply_code = rep

        handshake_time = time.perf_counter()
        result.handshake_ms = (handshake_time - start_time) * 1000

        if ver != SOCKS5_VERSION:
            result.result = UDPTestResult.FAILED
            result.error = f"Invalid version in reply: {ver}"
            return result

        if rep == REP_CMD_NOT_SUPPORTED:
            result.result = UDPTestResult.NOT_SUPPORTED
            result.error = "UDP ASSOCIATE not supported (CMD 0x07)"
            return result

        if rep != REP_SUCCESS:
            result.result = UDPTestResult.FAILED
            result.error = f"UDP ASSOCIATE failed: {REPLY_CODES.get(rep, f'code {rep}')}"
            return result

        # Parse BND.ADDR and BND.PORT
        try:
            bnd_addr, bnd_port, _ = parse_address(response, 3)
            result.bnd_addr = bnd_addr
            result.bnd_port = bnd_port
        except Exception as e:
            result.result = UDPTestResult.FAILED
            result.error = f"Failed to parse BND.ADDR: {e}"
            return result

        # UDP ASSOCIATE is supported!
        result.udp_supported = True
        result.result = UDPTestResult.SUPPORTED

        # If BND.ADDR is 0.0.0.0, use the proxy host
        if bnd_addr == "0.0.0.0":
            bnd_addr = proxy_host
            result.bnd_addr = bnd_addr

        # Step 5: Optionally test actual UDP relay
        if test_dns and bnd_port > 0:
            try:
                relay_start = time.perf_counter()

                # Create UDP socket
                loop = asyncio.get_event_loop()
                udp_transport, protocol = await loop.create_datagram_endpoint(
                    UDPProtocol,
                    remote_addr=(bnd_addr, bnd_port)
                )

                # Build DNS query for google.com (simple A record query)
                # Transaction ID (2) | Flags (2) | Questions (2) | ...
                dns_query = bytes([
                    0x12, 0x34,  # Transaction ID
                    0x01, 0x00,  # Flags: Standard query
                    0x00, 0x01,  # Questions: 1
                    0x00, 0x00,  # Answer RRs: 0
                    0x00, 0x00,  # Authority RRs: 0
                    0x00, 0x00,  # Additional RRs: 0
                    # Query: google.com
                    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # "google"
                    0x03, 0x63, 0x6f, 0x6d,  # "com"
                    0x00,  # End of name
                    0x00, 0x01,  # Type: A
                    0x00, 0x01,  # Class: IN
                ])

                # Build SOCKS5 UDP header + DNS query
                udp_header = build_udp_header(dns_server, dns_port)
                udp_packet = udp_header + dns_query

                # Send via UDP relay
                udp_transport.sendto(udp_packet)

                # Wait for response
                protocol.response_future = asyncio.Future()
                try:
                    response_data = await asyncio.wait_for(
                        protocol.response_future,
                        timeout=5.0
                    )

                    # Parse response - should have SOCKS5 header
                    if len(response_data) > 10:
                        _, _, src_addr, src_port, payload = parse_udp_header(response_data)

                        # Check if we got a DNS response (starts with our transaction ID)
                        if len(payload) > 2 and payload[0:2] == bytes([0x12, 0x34]):
                            result.udp_works = True
                            result.result = UDPTestResult.SUCCESS
                            result.relay_ms = (time.perf_counter() - relay_start) * 1000
                        else:
                            # Got response but not valid DNS
                            result.result = UDPTestResult.SUPPORTED
                    else:
                        result.result = UDPTestResult.SUPPORTED

                except asyncio.TimeoutError:
                    # UDP relay didn't respond, but ASSOCIATE worked
                    result.result = UDPTestResult.SUPPORTED
                    logger.debug(f"UDP relay timeout for {proxy_host}:{proxy_port}")

            except Exception as e:
                # UDP test failed but ASSOCIATE was accepted
                logger.debug(f"UDP relay test failed: {e}")
                result.result = UDPTestResult.SUPPORTED

            finally:
                if udp_transport:
                    udp_transport.close()

        return result

    except asyncio.TimeoutError:
        result.result = UDPTestResult.TIMEOUT
        result.error = "Operation timeout"
        return result

    except Exception as e:
        result.result = UDPTestResult.ERROR
        result.error = str(e)
        return result

    finally:
        # Close TCP connection (this ends the UDP association)
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def test_udp_associate_batch(
    proxies: list,
    concurrency: int = 50,
    timeout: float = 10.0,
    test_dns: bool = False,  # Disable DNS test for speed in batch mode
) -> dict:
    """
    Test UDP ASSOCIATE support for multiple proxies.

    Args:
        proxies: List of "host:port" strings
        concurrency: Max concurrent tests
        timeout: Timeout per test
        test_dns: Whether to test actual UDP relay

    Returns:
        Dict with results and statistics
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def test_one(proxy: str):
        async with semaphore:
            try:
                host, port_str = proxy.rsplit(":", 1)
                port = int(port_str)
                return await test_udp_associate(
                    host, port,
                    timeout=timeout,
                    test_dns=test_dns
                )
            except Exception as e:
                return UDPAssociateResult(
                    proxy=proxy,
                    result=UDPTestResult.ERROR,
                    error=str(e)
                )

    tasks = [test_one(p) for p in proxies]
    results = await asyncio.gather(*tasks)

    # Compute statistics
    supported = sum(1 for r in results if r.udp_supported)
    working = sum(1 for r in results if r.udp_works)
    not_supported = sum(1 for r in results if r.result == UDPTestResult.NOT_SUPPORTED)
    errors = sum(1 for r in results if r.result in (UDPTestResult.ERROR, UDPTestResult.TIMEOUT, UDPTestResult.FAILED))

    return {
        "total": len(proxies),
        "udp_supported": supported,
        "udp_works": working,
        "not_supported": not_supported,
        "errors": errors,
        "results": [r.to_dict() for r in results],
    }


# Synchronous wrapper for CLI usage
def test_udp_sync(proxy: str, timeout: float = 10.0, test_dns: bool = True) -> UDPAssociateResult:
    """Synchronous wrapper for test_udp_associate."""
    try:
        host, port_str = proxy.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        return UDPAssociateResult(
            proxy=proxy,
            result=UDPTestResult.ERROR,
            error="Invalid proxy format"
        )

    return asyncio.run(test_udp_associate(host, port, timeout=timeout, test_dns=test_dns))


if __name__ == "__main__":
    # Test example
    import sys

    if len(sys.argv) < 2:
        print("Usage: python udp_associate.py <proxy_host:port>")
        print("Example: python udp_associate.py 1.2.3.4:1080")
        sys.exit(1)

    proxy = sys.argv[1]
    print(f"Testing UDP ASSOCIATE for {proxy}...")

    result = test_udp_sync(proxy, test_dns=True)

    print(f"\nResults:")
    print(f"  UDP Supported: {result.udp_supported}")
    print(f"  UDP Works: {result.udp_works}")
    print(f"  Result: {result.result.value}")
    if result.bnd_addr:
        print(f"  BND.ADDR: {result.bnd_addr}:{result.bnd_port}")
    if result.handshake_ms:
        print(f"  Handshake: {result.handshake_ms:.1f}ms")
    if result.relay_ms:
        print(f"  Relay RTT: {result.relay_ms:.1f}ms")
    if result.error:
        print(f"  Error: {result.error}")
