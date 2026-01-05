"""
GeoIP Module - Offline geolocation using MaxMind GeoLite2 databases.

Features:
- No rate limits (offline database)
- Fast lookups (~0.1ms per IP)
- ASN, City, and Country data
- Automatic database download and updates

Requires:
- geoip2 library: pip install geoip2
- MaxMind account for database download (free)

Database files:
- GeoLite2-ASN.mmdb
- GeoLite2-City.mmdb
- GeoLite2-Country.mmdb
"""

import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

import requests

logger = logging.getLogger(__name__)


@dataclass
class GeoIPResult:
    """Result of GeoIP lookup."""

    ip: str

    # Country
    country: Optional[str] = None
    country_code: Optional[str] = None

    # City
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None

    # Coordinates
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None

    # ASN
    asn: Optional[int] = None
    asn_org: Optional[str] = None

    # Metadata
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False
    accuracy_radius: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}

    @property
    def asn_str(self) -> str:
        """Format ASN as string (e.g., 'AS12345')."""
        return f"AS{self.asn}" if self.asn else ""

    @property
    def location_str(self) -> str:
        """Format location as string."""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country_code:
            parts.append(self.country_code)
        return ", ".join(parts) if parts else "Unknown"


class GeoIPDatabase:
    """
    Offline GeoIP database using MaxMind GeoLite2.

    Usage:
        db = GeoIPDatabase(db_path="/path/to/databases")
        result = db.lookup("8.8.8.8")
        print(f"{result.country_code}, {result.asn_str}")
    """

    # MaxMind download URLs (requires license key)
    DOWNLOAD_URLS = {
        'asn': 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key={key}&suffix=tar.gz',
        'city': 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz',
        'country': 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={key}&suffix=tar.gz',
    }

    # Default database directory
    DEFAULT_DB_PATH = Path.home() / '.geoip'

    def __init__(
        self,
        db_path: Optional[str] = None,
        license_key: Optional[str] = None,
        auto_download: bool = False
    ):
        """
        Initialize GeoIP database.

        Args:
            db_path: Path to database directory
            license_key: MaxMind license key (for auto-download)
            auto_download: Automatically download databases if missing
        """
        if not HAS_GEOIP2:
            raise ImportError("geoip2 library required: pip install geoip2")

        self.db_path = Path(db_path) if db_path else self.DEFAULT_DB_PATH
        self.license_key = license_key or os.environ.get('MAXMIND_LICENSE_KEY')
        self.auto_download = auto_download

        self._asn_reader = None
        self._city_reader = None
        self._country_reader = None

        # Ensure directory exists
        self.db_path.mkdir(parents=True, exist_ok=True)

        # Load databases
        self._load_databases()

    def _load_databases(self):
        """Load available database files."""
        asn_path = self._find_db('GeoLite2-ASN.mmdb')
        city_path = self._find_db('GeoLite2-City.mmdb')
        country_path = self._find_db('GeoLite2-Country.mmdb')

        if asn_path:
            try:
                self._asn_reader = geoip2.database.Reader(str(asn_path))
                logger.info(f"Loaded ASN database: {asn_path}")
            except Exception as e:
                logger.warning(f"Failed to load ASN database: {e}")

        if city_path:
            try:
                self._city_reader = geoip2.database.Reader(str(city_path))
                logger.info(f"Loaded City database: {city_path}")
            except Exception as e:
                logger.warning(f"Failed to load City database: {e}")

        if country_path:
            try:
                self._country_reader = geoip2.database.Reader(str(country_path))
                logger.info(f"Loaded Country database: {country_path}")
            except Exception as e:
                logger.warning(f"Failed to load Country database: {e}")

        if not any([self._asn_reader, self._city_reader, self._country_reader]):
            if self.auto_download and self.license_key:
                self.download_databases()
            else:
                logger.warning(
                    "No GeoIP databases found. Download from MaxMind or use "
                    "GeoIPDatabase(license_key='...', auto_download=True)"
                )

    def _find_db(self, filename: str) -> Optional[Path]:
        """Find database file in various locations."""
        # Check db_path
        path = self.db_path / filename
        if path.exists():
            return path

        # Check subdirectories (MaxMind extracts to versioned folders)
        for subdir in self.db_path.iterdir():
            if subdir.is_dir():
                path = subdir / filename
                if path.exists():
                    return path

        return None

    def download_databases(self, editions: list = None):
        """
        Download GeoLite2 databases from MaxMind.

        Args:
            editions: List of editions to download ('asn', 'city', 'country')
        """
        if not self.license_key:
            raise ValueError("MaxMind license key required for download")

        editions = editions or ['asn', 'city', 'country']

        for edition in editions:
            if edition not in self.DOWNLOAD_URLS:
                continue

            url = self.DOWNLOAD_URLS[edition].format(key=self.license_key)
            logger.info(f"Downloading {edition} database...")

            try:
                response = requests.get(url, stream=True, timeout=60)
                response.raise_for_status()

                # Extract tar.gz
                with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
                    for chunk in response.iter_content(chunk_size=8192):
                        tmp.write(chunk)
                    tmp_path = tmp.name

                with tarfile.open(tmp_path, 'r:gz') as tar:
                    tar.extractall(self.db_path)

                os.unlink(tmp_path)
                logger.info(f"Downloaded {edition} database")

            except Exception as e:
                logger.error(f"Failed to download {edition}: {e}")

        # Reload databases
        self._load_databases()

    def lookup(self, ip: str) -> GeoIPResult:
        """
        Look up IP address in all available databases.

        Args:
            ip: IP address to look up

        Returns:
            GeoIPResult with all available data
        """
        result = GeoIPResult(ip=ip)

        # ASN lookup
        if self._asn_reader:
            try:
                asn = self._asn_reader.asn(ip)
                result.asn = asn.autonomous_system_number
                result.asn_org = asn.autonomous_system_organization
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"ASN lookup failed for {ip}: {e}")

        # City lookup (includes country data)
        if self._city_reader:
            try:
                city = self._city_reader.city(ip)
                result.country = city.country.name
                result.country_code = city.country.iso_code
                result.city = city.city.name
                result.region = city.subdivisions.most_specific.name if city.subdivisions else None
                result.postal_code = city.postal.code
                result.latitude = city.location.latitude
                result.longitude = city.location.longitude
                result.timezone = city.location.time_zone
                result.accuracy_radius = city.location.accuracy_radius
                result.is_anonymous_proxy = city.traits.is_anonymous_proxy
                result.is_satellite_provider = city.traits.is_satellite_provider
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"City lookup failed for {ip}: {e}")

        # Country lookup (fallback if city not available)
        elif self._country_reader:
            try:
                country = self._country_reader.country(ip)
                result.country = country.country.name
                result.country_code = country.country.iso_code
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"Country lookup failed for {ip}: {e}")

        return result

    def lookup_batch(self, ips: list) -> Dict[str, GeoIPResult]:
        """
        Look up multiple IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IP -> GeoIPResult
        """
        return {ip: self.lookup(ip) for ip in ips}

    @property
    def is_available(self) -> bool:
        """Check if any database is loaded."""
        return any([self._asn_reader, self._city_reader, self._country_reader])

    def close(self):
        """Close database readers."""
        if self._asn_reader:
            self._asn_reader.close()
        if self._city_reader:
            self._city_reader.close()
        if self._country_reader:
            self._country_reader.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# Fallback to online API if geoip2 not available
class OnlineGeoIP:
    """
    Fallback online GeoIP using free APIs.
    Use when MaxMind databases are not available.
    """

    PROVIDERS = [
        ('ip-api.com', 'http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as'),
        ('ipwho.is', 'https://ipwho.is/{ip}'),
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._cache: Dict[str, GeoIPResult] = {}

    def lookup(self, ip: str) -> GeoIPResult:
        """Look up IP using online API."""
        if ip in self._cache:
            return self._cache[ip]

        result = GeoIPResult(ip=ip)

        for provider_name, url_template in self.PROVIDERS:
            try:
                url = url_template.format(ip=ip)
                response = requests.get(url, timeout=self.timeout)

                if response.status_code != 200:
                    continue

                data = response.json()
                result = self._parse_response(ip, provider_name, data)

                if result.country:
                    self._cache[ip] = result
                    return result

            except Exception as e:
                logger.debug(f"{provider_name} failed for {ip}: {e}")
                continue

        return result

    def _parse_response(self, ip: str, provider: str, data: dict) -> GeoIPResult:
        """Parse response from different providers."""
        result = GeoIPResult(ip=ip)

        if provider == 'ip-api.com':
            if data.get('status') != 'success':
                return result

            result.country = data.get('country')
            result.country_code = data.get('countryCode')
            result.region = data.get('regionName')
            result.city = data.get('city')
            result.postal_code = data.get('zip')
            result.latitude = data.get('lat')
            result.longitude = data.get('lon')
            result.timezone = data.get('timezone')
            result.asn_org = data.get('isp')

            # Parse ASN from "AS12345 Name" format
            as_str = data.get('as', '')
            if as_str.startswith('AS'):
                try:
                    result.asn = int(as_str.split()[0][2:])
                except (ValueError, IndexError):
                    pass

        elif provider == 'ipwho.is':
            if not data.get('success'):
                return result

            result.country = data.get('country')
            result.country_code = data.get('country_code')
            result.region = data.get('region')
            result.city = data.get('city')
            result.postal_code = data.get('postal')
            result.latitude = data.get('latitude')
            result.longitude = data.get('longitude')
            result.timezone = data.get('timezone', {}).get('id')

            conn = data.get('connection', {})
            result.asn = conn.get('asn')
            result.asn_org = conn.get('org')

        return result


def get_geoip(db_path: Optional[str] = None) -> 'GeoIPDatabase | OnlineGeoIP':
    """
    Get the best available GeoIP provider.

    Returns offline database if available, otherwise online API.
    """
    if HAS_GEOIP2:
        try:
            db = GeoIPDatabase(db_path=db_path)
            if db.is_available:
                return db
        except Exception:
            pass

    return OnlineGeoIP()
