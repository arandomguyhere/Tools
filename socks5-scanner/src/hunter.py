"""
Proxy Hunter - GitHub repository discovery for proxy lists.

Inspired by arandomguyhere/Proxy-Hound.
Searches GitHub for fresh proxy sources and learns which ones work best.
"""

import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import requests

from .utils import Color, extract_proxies_from_text, get_user_agent, validate_ip


@dataclass
class RepositoryInfo:
    """Information about a discovered proxy repository."""
    owner: str
    name: str
    url: str
    raw_url: Optional[str] = None
    stars: int = 0
    forks: int = 0
    updated_at: Optional[str] = None
    scent_score: float = 0.0  # How "proxy-like" the repo smells
    hunt_score: float = 0.0   # Historical success rate


@dataclass
class HuntResult:
    """Result of a hunting expedition."""
    repository: RepositoryInfo
    proxies_found: int = 0
    proxies_valid: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ScentAnalyzer:
    """Analyzes repositories to detect proxy list characteristics."""

    # Keywords that indicate a proxy repository (with weights)
    SCENT_KEYWORDS = {
        # Strong indicators
        'socks5': 15, 'socks4': 12, 'proxy': 10, 'proxies': 10,
        'proxy-list': 15, 'proxylist': 15, 'free-proxy': 15,
        # Medium indicators
        'fresh': 8, 'working': 8, 'verified': 10, 'checked': 8,
        'live': 8, 'valid': 8, 'daily': 5, 'hourly': 8,
        # Weak indicators
        'http': 3, 'https': 3, 'anonymous': 5, 'elite': 5,
    }

    # File patterns that contain proxies
    PROXY_FILE_PATTERNS = [
        r'socks5\.txt', r'socks4\.txt', r'proxy\.txt', r'proxies\.txt',
        r'http\.txt', r'https\.txt', r'.*proxy.*\.txt', r'.*socks.*\.txt',
    ]

    def analyze_repository(self, repo_data: dict) -> float:
        """
        Analyze a repository and return a scent score (0-100).

        Higher scores indicate stronger proxy list characteristics.
        """
        score = 0.0

        # Analyze name and description
        name = repo_data.get('name', '').lower()
        description = (repo_data.get('description') or '').lower()
        full_name = repo_data.get('full_name', '').lower()

        text = f"{name} {description} {full_name}"

        for keyword, weight in self.SCENT_KEYWORDS.items():
            if keyword in text:
                score += weight

        # Bonus for recent updates
        updated_at = repo_data.get('updated_at', '')
        if updated_at:
            try:
                update_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                days_ago = (datetime.now(update_date.tzinfo) - update_date).days

                if days_ago < 1:
                    score += 20  # Updated today
                elif days_ago < 7:
                    score += 15  # Updated this week
                elif days_ago < 30:
                    score += 10  # Updated this month
            except Exception:
                pass

        # Community trust indicators
        stars = repo_data.get('stargazers_count', 0)
        forks = repo_data.get('forks_count', 0)

        if stars > 100:
            score += 10
        elif stars > 50:
            score += 7
        elif stars > 10:
            score += 5

        if forks > 50:
            score += 5
        elif forks > 10:
            score += 3

        return min(score, 100.0)  # Cap at 100


class HuntDatabase:
    """SQLite database for tracking hunting history and results."""

    def __init__(self, db_path: str = "proxy_hunt.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id INTEGER PRIMARY KEY,
                    owner TEXT NOT NULL,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    raw_url TEXT,
                    stars INTEGER DEFAULT 0,
                    scent_score REAL DEFAULT 0,
                    hunt_score REAL DEFAULT 50,
                    total_hunts INTEGER DEFAULT 0,
                    successful_hunts INTEGER DEFAULT 0,
                    last_hunt TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(owner, name)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_results (
                    id INTEGER PRIMARY KEY,
                    repo_id INTEGER,
                    proxies_found INTEGER,
                    proxies_valid INTEGER,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (repo_id) REFERENCES repositories(id)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hunt_score
                ON repositories(hunt_score DESC)
            """)

    def upsert_repository(self, repo: RepositoryInfo):
        """Insert or update a repository."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO repositories (owner, name, url, raw_url, stars, scent_score)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner, name) DO UPDATE SET
                    url = excluded.url,
                    raw_url = excluded.raw_url,
                    stars = excluded.stars,
                    scent_score = excluded.scent_score
            """, (repo.owner, repo.name, repo.url, repo.raw_url, repo.stars, repo.scent_score))

    def record_hunt(self, repo: RepositoryInfo, proxies_found: int, proxies_valid: int):
        """Record a hunt result and update scores."""
        with sqlite3.connect(self.db_path) as conn:
            # Get repo id
            cursor = conn.execute(
                "SELECT id, total_hunts, successful_hunts FROM repositories WHERE owner=? AND name=?",
                (repo.owner, repo.name)
            )
            row = cursor.fetchone()

            if row:
                repo_id, total, successful = row

                # Update hunt statistics
                total += 1
                if proxies_valid > 0:
                    successful += 1

                # Calculate new hunt score (weighted average)
                hunt_score = (successful / total) * 100 if total > 0 else 50

                conn.execute("""
                    UPDATE repositories SET
                        total_hunts = ?,
                        successful_hunts = ?,
                        hunt_score = ?,
                        last_hunt = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (total, successful, hunt_score, repo_id))

                # Record hunt result
                conn.execute("""
                    INSERT INTO hunt_results (repo_id, proxies_found, proxies_valid)
                    VALUES (?, ?, ?)
                """, (repo_id, proxies_found, proxies_valid))

    def get_best_repositories(self, limit: int = 20) -> List[RepositoryInfo]:
        """Get repositories with highest hunt scores."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT owner, name, url, raw_url, stars, scent_score, hunt_score
                FROM repositories
                ORDER BY hunt_score DESC, scent_score DESC
                LIMIT ?
            """, (limit,))

            repos = []
            for row in cursor.fetchall():
                repos.append(RepositoryInfo(
                    owner=row[0], name=row[1], url=row[2], raw_url=row[3],
                    stars=row[4], scent_score=row[5], hunt_score=row[6]
                ))
            return repos

    def get_stats(self) -> dict:
        """Get hunting statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total_repos,
                    AVG(hunt_score) as avg_score,
                    SUM(total_hunts) as total_hunts,
                    SUM(successful_hunts) as successful_hunts
                FROM repositories
            """)
            row = cursor.fetchone()

            return {
                'total_repos': row[0] or 0,
                'avg_score': row[1] or 0,
                'total_hunts': row[2] or 0,
                'successful_hunts': row[3] or 0,
            }


class ProxyHunter:
    """
    Hunts for SOCKS5 proxies by discovering GitHub repositories.

    Learns which sources work best over time.
    """

    # GitHub search queries for finding proxy repositories
    HUNT_QUERIES = [
        'socks5 proxy list',
        'free socks5 proxies',
        'proxy list fresh',
        'socks proxy verified',
        'working proxy list',
    ]

    # Backup sources (known good repositories)
    # Format: (owner, repo, path)
    BACKUP_SOURCES = [
        # === ORIGINAL SOURCES ===
        ("TheSpeedX", "SOCKS-List", "socks5.txt"),
        ("monosans", "proxy-list", "proxies/socks5.txt"),
        ("hookzof", "socks5_list", "proxy.txt"),
        ("jetkai", "proxy-list", "online-proxies/txt/proxies-socks5.txt"),
        ("ShiftyTR", "Proxy-List", "socks5.txt"),
        ("ALIILAPRO", "Proxy", "socks5.txt"),
        ("prxchk", "proxy-list", "socks5.txt"),
        ("roosterkid", "openproxylist", "SOCKS5_RAW.txt"),

        # === HIGH-QUALITY UPDATED SOURCES ===
        ("proxifly", "free-proxy-list", "proxies/protocols/socks5/data.txt"),
        ("ErcinDedeoglu", "proxies", "proxies/socks5.txt"),
        ("vakhov", "fresh-proxy-list", "socks5.txt"),
        ("mmpx12", "proxy-list", "socks5.txt"),
        ("officialputuid", "KangProxy", "socks5/socks5.txt"),
        ("MuRongPIG", "Proxy-Master", "socks5.txt"),
        ("Anonym0usWork1221", "Free-Proxies", "proxy_files/socks5_proxies.txt"),
        ("zevtyardt", "proxy-list", "socks5.txt"),
        ("sunny9577", "proxy-scraper", "generated/socks5_proxies.txt"),
        ("fyvri", "fresh-proxy-list", "socks5.txt"),

        # === VERY ACTIVE (updates every few minutes) ===
        ("dpangestuw", "Free-Proxy", "socks5.txt"),
        ("Skillter", "ProxyGather", "proxies/working-proxies-socks5.txt"),
        ("databay-labs", "free-proxy-list", "socks5.txt"),
        ("BreakingTechFr", "Proxy_Free", "proxies/socks5.txt"),
        ("Vadim287", "free-proxy", "socks5.txt"),
        ("yemixzy", "free-proxy-list", "socks5.txt"),
        ("claude89757", "free_https_proxies", "socks5.txt"),

        # === ACTIVE DAILY UPDATES ===
        ("gitrecon1455", "fresh-proxy-list", "socks5.txt"),
        ("Vann-Dev", "proxy-list", "proxies/socks5.txt"),
        ("ArrayIterator", "proxy-lists", "proxies/socks5.txt"),
        ("Noctiro", "getproxy", "file/socks5.txt"),
        ("tuanminpay", "live-proxy", "socks5.txt"),
        ("zloi-user", "hideip.me", "socks5.txt"),
        ("HyperBeats", "proxy-list", "socks5.txt"),
        ("baklazhan1337", "proxier", "socks5.txt"),

        # === RELIABLE SOURCES ===
        ("stormsia", "proxy-list", "socks5.txt"),
        ("ebrasha", "abdal-proxy-hub", "socks5.txt"),
        ("handeveloper1", "Proxy", "socks5.txt"),
        ("vmheaven", "VMHeaven-Free-Proxy-Updated", "socks5.txt"),
        ("iplocate", "free-proxy-list", "socks5.txt"),
        ("gfpcom", "free-proxy-list", "socks5.txt"),
        ("sanat1ro", "Mass-Proxy-Parser-Checker", "socks5.txt"),
        ("kranoley", "Proxy-Scraper-Parser-And-Checker", "socks5.txt"),

        # === ADDITIONAL REPOSITORIES ===
        ("rdavydov", "proxy-list", "socks5.txt"),
        ("clarketm", "proxy-list", "socks5.txt"),
        ("fate0", "proxylist", "socks5.txt"),
        ("a2u", "free-proxy-list", "socks5.txt"),
        ("rx443", "proxy-list", "socks5.txt"),
        ("hendrikbgr", "Free-Proxy-Repo", "socks5.txt"),
        ("saschazesiger", "Free-Proxies", "socks5.txt"),
        ("UptimerBot", "proxy-list", "socks5.txt"),
        ("mertguvencli", "http-proxy-list", "socks5.txt"),
        ("almroot", "proxylist", "socks5.txt"),

        # === MORE ACTIVE SOURCES ===
        ("human1ty", "proxy-list", "socks5.txt"),
        ("BlackSnowDot", "proxylist-update-every-minute", "socks5.txt"),
        ("proxy4parsing", "proxy-list", "socks5.txt"),
        ("zenjahid", "FreeProxy4u", "socks5.txt"),
        ("SevenworksDev", "proxy-list", "socks5.txt"),
        ("im-razvan", "proxy-list", "socks5.txt"),
        ("mzyui", "proxy-list", "socks5.txt"),
        ("casals-ar", "proxy-list", "socks5.txt"),
        ("ObcbO", "getproxy", "file/socks5.txt"),

        # === BONUS SOURCES ===
        ("UserR3X", "proxy-list", "socks5.txt"),
        ("Flavoured", "proxylist", "socks5.txt"),
        ("B4RC0DE-TM", "proxy-list", "socks5.txt"),
        ("TheSpeedX", "PROXY-List", "socks5.txt"),
        ("aslfrancisco", "proxy-list", "socks5.txt"),
    ]

    # GitHub search queries for dynamic discovery
    GITHUB_SEARCH_QUERIES = [
        "socks5 proxy list",
        "free proxy socks5",
        "proxy list updated",
        "socks5 proxies fresh",
        "free socks5",
        "proxy scraper socks5",
        "working proxy list",
        "proxy list daily",
        "socks proxy free",
        "anonymous proxy list",
    ]

    # Common file paths to check in discovered repos
    COMMON_PROXY_PATHS = [
        "socks5.txt", "proxy.txt", "proxies.txt",
        "socks5/socks5.txt", "proxies/socks5.txt",
        "data/socks5.txt", "list/socks5.txt",
        "proxy_files/socks5_proxies.txt",
        "proxies/protocols/socks5/data.txt",
        "online-proxies/txt/proxies-socks5.txt",
        "SOCKS5_RAW.txt", "socks5_proxies.txt",
        "working-proxies-socks5.txt",
        "generated/socks5_proxies.txt",
        "file/socks5.txt",
        "xResults/socks5.txt",
    ]

    def __init__(self, db_path: str = "proxy_hunt.db", github_token: Optional[str] = None):
        self.db = HuntDatabase(db_path)
        self.analyzer = ScentAnalyzer()
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': get_user_agent(),
            'Accept': 'application/vnd.github.v3+json',
        })
        if self.github_token:
            self.session.headers['Authorization'] = f'token {self.github_token}'

    def search_github(self, query: str, max_results: int = 10) -> List[RepositoryInfo]:
        """Search GitHub for proxy repositories."""
        repos = []

        try:
            # Add date filter for freshness
            date_filter = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d')
            full_query = f"{query} pushed:>{date_filter}"

            url = f"https://api.github.com/search/repositories?q={quote(full_query)}&sort=updated&per_page={max_results}"

            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                for item in data.get('items', []):
                    scent = self.analyzer.analyze_repository(item)

                    if scent >= 20:  # Minimum threshold
                        repo = RepositoryInfo(
                            owner=item['owner']['login'],
                            name=item['name'],
                            url=item['html_url'],
                            stars=item.get('stargazers_count', 0),
                            forks=item.get('forks_count', 0),
                            updated_at=item.get('updated_at'),
                            scent_score=scent,
                        )
                        repos.append(repo)
                        self.db.upsert_repository(repo)

            elif response.status_code == 403:
                print(f"{Color.yellow('Warning:')} GitHub API rate limited")

        except Exception as e:
            print(f"{Color.red('Error:')} GitHub search failed: {e}")

        return repos

    def discover_raw_url(self, repo: RepositoryInfo) -> Optional[str]:
        """Find the raw URL for a proxy file in a repository."""
        try:
            for path in self.COMMON_PROXY_PATHS:
                # Try main branch first
                raw_url = f"https://raw.githubusercontent.com/{repo.owner}/{repo.name}/main/{path}"
                response = self.session.head(raw_url, timeout=5)

                if response.status_code == 200:
                    return raw_url

                # Try master branch
                raw_url = f"https://raw.githubusercontent.com/{repo.owner}/{repo.name}/master/{path}"
                response = self.session.head(raw_url, timeout=5)

                if response.status_code == 200:
                    return raw_url

        except Exception:
            pass

        return None

    def search_github_live(self, max_results_per_query: int = 100) -> List[RepositoryInfo]:
        """
        Poll GitHub search API for recently updated proxy repositories.

        This enables dynamic discovery of new sources for scaling to 1M+ proxies.
        Polls: https://github.com/search?q=free+proxy&type=repositories&s=updated&o=desc
        """
        all_repos = []
        seen_repos = set()

        for query in self.GITHUB_SEARCH_QUERIES:
            try:
                # Add date filter for freshness (last 30 days)
                date_filter = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
                full_query = f"{query} pushed:>{date_filter}"

                url = "https://api.github.com/search/repositories"
                params = {
                    "q": full_query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": min(max_results_per_query, 100)
                }

                response = self.session.get(url, params=params, timeout=15)

                if response.status_code == 200:
                    data = response.json()

                    for item in data.get('items', []):
                        repo_key = f"{item['owner']['login']}/{item['name']}"

                        if repo_key in seen_repos:
                            continue
                        seen_repos.add(repo_key)

                        scent = self.analyzer.analyze_repository(item)

                        if scent >= 15:  # Lower threshold to catch more sources
                            repo = RepositoryInfo(
                                owner=item['owner']['login'],
                                name=item['name'],
                                url=item['html_url'],
                                stars=item.get('stargazers_count', 0),
                                forks=item.get('forks_count', 0),
                                updated_at=item.get('updated_at'),
                                scent_score=scent,
                            )
                            all_repos.append(repo)
                            self.db.upsert_repository(repo)

                elif response.status_code == 403:
                    print(f"{Color.yellow('Warning:')} GitHub API rate limited, waiting...")
                    time.sleep(60)  # Wait a minute if rate limited

                time.sleep(2)  # Rate limit protection between queries

            except Exception as e:
                print(f"{Color.red('Error:')} GitHub live search failed for '{query}': {e}")

        # Sort by scent score
        all_repos.sort(key=lambda r: r.scent_score, reverse=True)
        return all_repos

    def mega_hunt(self, show_progress: bool = True) -> Tuple[List[str], List[HuntResult]]:
        """
        High-performance hunting mode for 1M+ proxy discovery.

        Combines:
        1. All 60+ backup sources
        2. Dynamic GitHub search discovery
        3. Historical best performers
        """
        all_proxies: Set[str] = set()
        results: List[HuntResult] = []

        if show_progress:
            print(f"\n{Color.cyan('MEGA HUNT')} - High-performance proxy discovery")
            print(f"Backup sources: {len(self.BACKUP_SOURCES)}")

        # Phase 1: Fetch from all backup sources (parallel-friendly)
        if show_progress:
            print(f"\n{Color.bold('Phase 1:')} Fetching from {len(self.BACKUP_SOURCES)} backup sources...")

        for i, (owner, name, path) in enumerate(self.BACKUP_SOURCES):
            raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/main/{path}"
            proxies = self.fetch_proxies(raw_url)

            if not proxies:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/master/{path}"
                proxies = self.fetch_proxies(raw_url)

            if proxies:
                if show_progress:
                    print(f"  [{i+1}/{len(self.BACKUP_SOURCES)}] {Color.green('✓')} {owner}/{name}: {len(proxies):,}")
                all_proxies.update(proxies)

                repo = RepositoryInfo(
                    owner=owner, name=name,
                    url=f"https://github.com/{owner}/{name}",
                    raw_url=raw_url
                )
                self.db.upsert_repository(repo)
                self.db.record_hunt(repo, len(proxies), len(proxies))
                results.append(HuntResult(repo, len(proxies), len(proxies)))
            elif show_progress:
                print(f"  [{i+1}/{len(self.BACKUP_SOURCES)}] {Color.red('✗')} {owner}/{name}: no proxies")

        if show_progress:
            print(f"\n  Subtotal: {Color.green(f'{len(all_proxies):,}')} unique proxies")

        # Phase 2: Dynamic GitHub discovery
        if show_progress:
            print(f"\n{Color.bold('Phase 2:')} Dynamic GitHub search discovery...")

        discovered = self.search_github_live(max_results_per_query=100)
        if show_progress:
            print(f"  Discovered {len(discovered)} potential repositories")

        for repo in discovered[:50]:  # Check top 50 by scent score
            raw_url = self.discover_raw_url(repo)
            if raw_url:
                proxies = self.fetch_proxies(raw_url)
                if proxies:
                    if show_progress:
                        print(f"  {Color.green('✓')} {repo.owner}/{repo.name}: {len(proxies):,} (scent: {repo.scent_score:.0f})")
                    all_proxies.update(proxies)
                    repo.raw_url = raw_url
                    self.db.record_hunt(repo, len(proxies), 0)
                    results.append(HuntResult(repo, len(proxies), 0))

        # Phase 3: Historical best performers
        if show_progress:
            print(f"\n{Color.bold('Phase 3:')} Checking historical top performers...")

        best_repos = self.db.get_best_repositories(limit=30)
        for repo in best_repos:
            if repo.raw_url:
                repo_key = f"{repo.owner}/{repo.name}"
                if not any(repo_key == f"{r.repository.owner}/{r.repository.name}" for r in results):
                    proxies = self.fetch_proxies(repo.raw_url)
                    if proxies:
                        if show_progress:
                            print(f"  {Color.green('✓')} {repo.owner}/{repo.name}: {len(proxies):,} (score: {repo.hunt_score:.0f})")
                        all_proxies.update(proxies)

        proxy_list = list(all_proxies)

        if show_progress:
            print(f"\n{Color.bold('='*50)}")
            print(f"{Color.bold('MEGA HUNT COMPLETE')}")
            print(f"Total unique proxies: {Color.green(f'{len(proxy_list):,}')}")
            print(f"Sources checked: {len(results)}")
            stats = self.db.get_stats()
            print(f"Tracked repositories: {stats['total_repos']}")
            print(f"{Color.bold('='*50)}")

        return proxy_list, results

    def fetch_proxies(self, url: str) -> List[str]:
        """Fetch proxy list from a URL."""
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return extract_proxies_from_text(response.text)
        except Exception:
            pass
        return []

    def hunt(self, max_sources: int = 20, show_progress: bool = True) -> Tuple[List[str], List[HuntResult]]:
        """
        Hunt for SOCKS5 proxies across GitHub.

        Returns (proxies, hunt_results)
        """
        all_proxies: Set[str] = set()
        results: List[HuntResult] = []

        if show_progress:
            print(f"\n{Color.cyan('Hunting')} for proxy sources on GitHub...")

        # 1. Use known good sources first
        if show_progress:
            print(f"\n{Color.bold('Phase 1:')} Checking backup sources...")

        for owner, name, path in self.BACKUP_SOURCES:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/main/{path}"
            proxies = self.fetch_proxies(raw_url)

            if not proxies:
                # Try master branch
                raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/master/{path}"
                proxies = self.fetch_proxies(raw_url)

            if proxies:
                if show_progress:
                    print(f"  {Color.green('✓')} {owner}/{name}: {len(proxies)} proxies")
                all_proxies.update(proxies)

                repo = RepositoryInfo(owner=owner, name=name, url=f"https://github.com/{owner}/{name}", raw_url=raw_url)
                self.db.upsert_repository(repo)
                self.db.record_hunt(repo, len(proxies), len(proxies))  # Assume valid for backup
                results.append(HuntResult(repo, len(proxies), len(proxies)))

        # 2. Search GitHub for new sources
        if show_progress:
            print(f"\n{Color.bold('Phase 2:')} Searching GitHub for new sources...")

        discovered_repos = []
        for query in self.HUNT_QUERIES[:3]:  # Limit queries to avoid rate limiting
            repos = self.search_github(query, max_results=5)
            discovered_repos.extend(repos)
            time.sleep(1)  # Rate limit protection

        # Deduplicate
        seen = set()
        unique_repos = []
        for repo in discovered_repos:
            key = f"{repo.owner}/{repo.name}"
            if key not in seen:
                seen.add(key)
                unique_repos.append(repo)

        if show_progress:
            print(f"  Found {len(unique_repos)} potential repositories")

        # 3. Fetch from discovered repos
        for repo in unique_repos[:max_sources]:
            raw_url = self.discover_raw_url(repo)

            if raw_url:
                proxies = self.fetch_proxies(raw_url)

                if proxies:
                    if show_progress:
                        print(f"  {Color.green('✓')} {repo.owner}/{repo.name}: {len(proxies)} proxies (score: {repo.scent_score:.0f})")
                    all_proxies.update(proxies)

                    repo.raw_url = raw_url
                    self.db.record_hunt(repo, len(proxies), 0)  # Will update valid count after validation
                    results.append(HuntResult(repo, len(proxies), 0))

        # 4. Check best historical sources
        if show_progress:
            print(f"\n{Color.bold('Phase 3:')} Checking top-rated sources...")

        best_repos = self.db.get_best_repositories(limit=10)
        for repo in best_repos:
            if repo.raw_url and repo.raw_url not in [r.repository.raw_url for r in results]:
                proxies = self.fetch_proxies(repo.raw_url)

                if proxies:
                    if show_progress:
                        print(f"  {Color.green('✓')} {repo.owner}/{repo.name}: {len(proxies)} (hunt score: {repo.hunt_score:.0f})")
                    all_proxies.update(proxies)

        proxy_list = list(all_proxies)

        if show_progress:
            print(f"\n{Color.bold('Total unique proxies:')} {Color.green(str(len(proxy_list)))}")
            stats = self.db.get_stats()
            print(f"Tracked repositories: {stats['total_repos']}, Avg score: {stats['avg_score']:.1f}")

        return proxy_list, results

    def update_hunt_results(self, results: List[HuntResult], valid_proxies: Set[str]):
        """Update hunt results with validation data."""
        for result in results:
            # Count how many of this source's proxies were valid
            # This is approximate since we don't track per-source
            valid_count = min(result.proxies_found, len(valid_proxies) // max(len(results), 1))
            self.db.record_hunt(result.repository, result.proxies_found, valid_count)
