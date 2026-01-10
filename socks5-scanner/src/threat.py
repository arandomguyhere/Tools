"""
Threat Intelligence Module

Checks proxy IPs against multiple threat intelligence blocklists.
Supports CIDR ranges, multiple sources, and proper risk scoring.
"""

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import aiohttp


class ThreatLevel(Enum):
    """Threat classification levels."""
    CLEAN = "clean"
    LOW = "low"
    RISK = "risk"


@dataclass
class ThreatSource:
    """Configuration for a threat intelligence source."""
    name: str
    url: str
    description: str
    severity: int  # 1-3: 1=low, 2=medium, 3=high
    format: str = "ip"  # ip, cidr, ip_port, url


@dataclass
class ThreatResult:
    """Result of threat check for an IP."""
    ip: str
    score: int = 0
    level: ThreatLevel = ThreatLevel.CLEAN
    sources: list = field(default_factory=list)
    flagged: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return dict(
            score=self.score,
            level=self.level.value,
            sources=self.sources,
            flagged=self.flagged,
            details=self.details,
        )


# Threat intelligence sources with severity ratings
# Severity: 1=low (spam/suspicious), 2=medium (known bad), 3=high (active C2/malware)
THREAT_SOURCES = [
    # abuse.ch sources (high quality, actively maintained)
    ThreatSource(
        name="feodo",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        description="Feodo Tracker - Botnet C2 servers",
        severity=3,
        format="ip",
    ),
    ThreatSource(
        name="sslbl",
        url="https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        description="SSL Blacklist - Malicious SSL certificates",
        severity=3,
        format="ip",
    ),
    ThreatSource(
        name="urlhaus",
        url="https://urlhaus.abuse.ch/downloads/text/",
        description="URLhaus - Malware distribution URLs",
        severity=3,
        format="url",
    ),
    # Spamhaus sources (industry standard)
    ThreatSource(
        name="spamhaus_drop",
        url="https://www.spamhaus.org/drop/drop.txt",
        description="Spamhaus DROP - Hijacked/leased for spam",
        severity=2,
        format="cidr",
    ),
    ThreatSource(
        name="spamhaus_edrop",
        url="https://www.spamhaus.org/drop/edrop.txt",
        description="Spamhaus EDROP - Extended DROP list",
        severity=2,
        format="cidr",
    ),
    # Emerging Threats (Proofpoint)
    ThreatSource(
        name="et_compromised",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        description="Emerging Threats - Compromised IPs",
        severity=2,
        format="ip",
    ),
    # FireHOL (aggregated threat intelligence)
    ThreatSource(
        name="firehol_level1",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        description="FireHOL Level 1 - High confidence threats",
        severity=3,
        format="cidr",
    ),
    # Binary Defense (active threat hunting)
    ThreatSource(
        name="binarydefense",
        url="https://www.binarydefense.com/banlist.txt",
        description="Binary Defense - Active threat IPs",
        severity=2,
        format="ip",
    ),
    # CI Army (malicious IPs)
    ThreatSource(
        name="ciarmy",
        url="https://cinsscore.com/list/ci-badguys.txt",
        description="CI Army - Known malicious IPs",
        severity=1,
        format="ip",
    ),
]


class ThreatChecker:
    """
    Threat intelligence checker with proper CIDR support and scoring.

    Usage:
        async with ThreatChecker() as checker:
            await checker.fetch_blocklists()
            result = checker.check_ip("1.2.3.4")
    """

    def __init__(self, sources: list[ThreatSource] = None):
        """Initialize with optional custom sources."""
        self.sources = sources or THREAT_SOURCES
        self.blocklists: dict[str, set[str]] = {}  # name -> set of IPs
        self.networks: dict[str, list[ipaddress.IPv4Network]] = {}  # name -> list of CIDRs
        self.source_config: dict[str, ThreatSource] = {s.name: s for s in self.sources}
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    def _parse_ip(self, line: str, fmt: str) -> tuple[Optional[str], Optional[ipaddress.IPv4Network]]:
        """
        Parse an IP or CIDR from a line based on format.
        Returns (ip, network) - one will be set based on the input.
        """
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            return None, None

        try:
            if fmt == "cidr":
                # Handle CIDR notation: 1.2.3.0/24
                if '/' in line:
                    # Remove comments after the CIDR
                    cidr = line.split()[0].split(';')[0].strip()
                    network = ipaddress.IPv4Network(cidr, strict=False)
                    return None, network
                else:
                    # Single IP treated as /32
                    ip = line.split()[0].split(';')[0].strip()
                    if self._is_valid_ip(ip):
                        return ip, None

            elif fmt == "ip_port":
                # Handle IP:port format: 1.2.3.4:1080
                if ':' in line:
                    ip = line.split(':')[0]
                    if self._is_valid_ip(ip):
                        return ip, None

            elif fmt == "url":
                # Extract IP from URL: http://1.2.3.4/malware
                match = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    ip = match.group(1)
                    if self._is_valid_ip(ip):
                        return ip, None

            else:  # fmt == "ip"
                # Plain IP address
                ip = line.split()[0].split(';')[0].strip()
                # Handle IP:port in "ip" format too
                if ':' in ip:
                    ip = ip.split(':')[0]
                if self._is_valid_ip(ip):
                    return ip, None

        except (ValueError, IndexError):
            pass

        return None, None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    async def _fetch_source(self, source: ThreatSource) -> tuple[str, int, int, Optional[str]]:
        """
        Fetch and parse a single blocklist source.
        Returns (name, ip_count, network_count, error).
        """
        ips = set()
        networks = []

        try:
            async with self._session.get(
                source.url,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return source.name, 0, 0, f"HTTP {resp.status}"

                text = await resp.text()
                for line in text.split('\n'):
                    ip, network = self._parse_ip(line, source.format)
                    if ip:
                        ips.add(ip)
                    if network:
                        networks.append(network)

                self.blocklists[source.name] = ips
                self.networks[source.name] = networks
                return source.name, len(ips), len(networks), None

        except asyncio.TimeoutError:
            return source.name, 0, 0, "timeout"
        except Exception as e:
            return source.name, 0, 0, str(e)[:50]

    async def fetch_blocklists(self, parallel: bool = True) -> dict:
        """
        Fetch all blocklists.
        Returns stats about what was fetched.
        """
        if not self._session:
            raise RuntimeError("Must use as async context manager")

        stats = dict(
            sources_total=len(self.sources),
            sources_ok=0,
            sources_failed=0,
            total_ips=0,
            total_networks=0,
            details={},
        )

        if parallel:
            tasks = [self._fetch_source(s) for s in self.sources]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []
            for s in self.sources:
                results.append(await self._fetch_source(s))

        for result in results:
            if isinstance(result, Exception):
                stats["sources_failed"] += 1
                continue

            name, ip_count, net_count, error = result
            if error:
                stats["sources_failed"] += 1
                stats["details"][name] = dict(error=error)
            else:
                stats["sources_ok"] += 1
                stats["total_ips"] += ip_count
                stats["total_networks"] += net_count
                stats["details"][name] = dict(ips=ip_count, networks=net_count)

        return stats

    def check_ip(self, ip: str) -> ThreatResult:
        """
        Check an IP against all loaded blocklists.
        Returns a ThreatResult with score and sources.
        """
        result = ThreatResult(ip=ip)

        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            return result  # Invalid IP, return clean

        matched_sources = []
        max_severity = 0

        for source in self.sources:
            matched = False

            # Check direct IP match
            if source.name in self.blocklists:
                if ip in self.blocklists[source.name]:
                    matched = True

            # Check CIDR match
            if source.name in self.networks:
                for network in self.networks[source.name]:
                    if ip_obj in network:
                        matched = True
                        break

            if matched:
                matched_sources.append(source.name)
                max_severity = max(max_severity, source.severity)

        if matched_sources:
            result.flagged = True
            result.sources = matched_sources
            result.score = self._calculate_score(matched_sources, max_severity)
            result.level = self._score_to_level(result.score)
            result.details = dict(
                source_count=len(matched_sources),
                max_severity=max_severity,
            )

        return result

    def _calculate_score(self, sources: list[str], max_severity: int) -> int:
        """
        Calculate threat score based on sources and severity.

        Scoring logic:
        - Base score from max severity: low=2, medium=4, high=6
        - +1 for each additional source (max +4)
        - Total range: 0-10

        This makes:
        - 1 low-severity source = 2 (Low Risk)
        - 1 medium-severity source = 4 (Low Risk)
        - 1 high-severity source = 6 (Risk)
        - Multiple high-severity sources = 7-10 (Risk)
        """
        severity_base = {1: 2, 2: 4, 3: 6}
        base = severity_base.get(max_severity, 0)
        additional = min(len(sources) - 1, 4)  # Cap at +4
        return min(base + additional, 10)

    def _score_to_level(self, score: int) -> ThreatLevel:
        """
        Convert numeric score to threat level.

        0 = Clean (not in any blocklist)
        1-4 = Low Risk (low/medium severity, few sources)
        5-10 = Risk (high severity or multiple sources)
        """
        if score == 0:
            return ThreatLevel.CLEAN
        elif score < 5:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.RISK

    def check_many(self, ips: list[str]) -> dict[str, ThreatResult]:
        """Check multiple IPs, returns dict of IP -> ThreatResult."""
        return {ip: self.check_ip(ip) for ip in ips}

    def get_stats(self) -> dict:
        """Get statistics about loaded blocklists."""
        total_ips = sum(len(ips) for ips in self.blocklists.values())
        total_networks = sum(len(nets) for nets in self.networks.values())
        return dict(
            sources_loaded=len(self.blocklists) + len(self.networks),
            total_ips=total_ips,
            total_networks=total_networks,
            sources=list(self.blocklists.keys()),
        )


async def check_ip_threats(ip: str) -> ThreatResult:
    """
    Convenience function to check a single IP.
    Creates a new checker, fetches blocklists, and checks the IP.
    """
    async with ThreatChecker() as checker:
        await checker.fetch_blocklists()
        return checker.check_ip(ip)


async def check_ips_threats(ips: list[str]) -> dict[str, ThreatResult]:
    """
    Convenience function to check multiple IPs.
    Creates a new checker, fetches blocklists, and checks all IPs.
    """
    async with ThreatChecker() as checker:
        await checker.fetch_blocklists()
        return checker.check_many(ips)
