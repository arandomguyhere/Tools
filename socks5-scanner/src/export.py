"""
Export and integration module for SOCKS5 proxy scanner.

Provides:
- JSON export (full structured data)
- CSV export (tabular format)
- Plain text export (simple proxy list)
- Pipeline integration hooks
- Feed/callback interfaces
"""

import csv
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable, TextIO

from .core import ProxyResult, ScanResults, ErrorCategory


# =============================================================================
# Export Formats
# =============================================================================

class Exporter(ABC):
    """Base class for result exporters."""

    @abstractmethod
    def export(self, results: ScanResults, output: TextIO):
        """Export results to a file-like object."""
        pass

    def export_to_file(self, results: ScanResults, filepath: str) -> bool:
        """Export results to a file."""
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'w', encoding='utf-8') as f:
                self.export(results, f)
            return True
        except Exception:
            return False

    def export_to_string(self, results: ScanResults) -> str:
        """Export results to a string."""
        import io
        buffer = io.StringIO()
        self.export(results, buffer)
        return buffer.getvalue()


class JSONExporter(Exporter):
    """Export results as JSON."""

    def __init__(self, indent: int = 2, include_failed: bool = True):
        self.indent = indent
        self.include_failed = include_failed

    def export(self, results: ScanResults, output: TextIO):
        data = results.to_dict()

        if not self.include_failed:
            data['results'] = [
                r for r in data['results']
                if r.get('socks5_valid') or r.get('tunnel_works')
            ]

        json.dump(data, output, indent=self.indent, ensure_ascii=False)


class CSVExporter(Exporter):
    """Export results as CSV."""

    COLUMNS = [
        'proxy', 'host', 'port', 'reachable', 'socks5_valid', 'tunnel_works',
        'http_works', 'latency_ms', 'error', 'error_category', 'error_stage',
        'external_ip', 'auth_required', 'anonymity', 'country', 'city', 'asn'
    ]

    def __init__(self, include_failed: bool = True, columns: List[str] = None):
        self.include_failed = include_failed
        self.columns = columns or self.COLUMNS

    def export(self, results: ScanResults, output: TextIO):
        writer = csv.DictWriter(output, fieldnames=self.columns, extrasaction='ignore')
        writer.writeheader()

        for result in results.results:
            if not self.include_failed and not result.is_working:
                continue

            row = result.to_dict()

            # Flatten geo data if present
            if 'geo' in row:
                geo = row.pop('geo')
                row.update({
                    'country': geo.get('country_code', ''),
                    'city': geo.get('city', ''),
                    'asn': geo.get('asn', ''),
                })

            # Flatten timing if present
            if 'timing' in row:
                row.pop('timing')

            writer.writerow(row)


class PlainTextExporter(Exporter):
    """Export as simple proxy list (one per line)."""

    def __init__(self, working_only: bool = True, include_protocol: bool = False):
        self.working_only = working_only
        self.include_protocol = include_protocol

    def export(self, results: ScanResults, output: TextIO):
        for result in results.results:
            if self.working_only and not result.is_working:
                continue

            if self.include_protocol:
                output.write(f"socks5://{result.proxy}\n")
            else:
                output.write(f"{result.proxy}\n")


class DetailedTextExporter(Exporter):
    """Export with full details in human-readable format."""

    def __init__(self, include_failed: bool = False):
        self.include_failed = include_failed

    def export(self, results: ScanResults, output: TextIO):
        # Header
        output.write("# SOCKS5 Proxy Scan Results\n")
        output.write(f"# Generated: {datetime.now().isoformat()}\n")
        output.write(f"# Total: {results.total} | Working: {results.working} | Failed: {results.failed}\n")
        output.write("#" + "=" * 80 + "\n\n")

        # Format string
        fmt = "{proxy:<22} | {status:<6} | {latency:<8} | {error}\n"

        output.write(fmt.format(
            proxy="PROXY", status="STATUS", latency="LATENCY", error="ERROR/INFO"
        ))
        output.write("-" * 80 + "\n")

        for result in results.results:
            if not self.include_failed and not result.is_working:
                continue

            status = "OK" if result.is_working else "FAIL"
            latency = f"{result.latency_ms:.0f}ms" if result.latency_ms else "-"
            error = result.error or ""

            if result.is_working and result.external_ip:
                error = f"IP: {result.external_ip}"

            output.write(fmt.format(
                proxy=result.proxy,
                status=status,
                latency=latency,
                error=error[:40]
            ))


# =============================================================================
# Batch Export
# =============================================================================

def export_results(
    results: ScanResults,
    output_dir: str = "./results",
    prefix: str = None,
    formats: List[str] = None
) -> Dict[str, str]:
    """
    Export results in multiple formats.

    Args:
        results: Scan results to export
        output_dir: Output directory
        prefix: Filename prefix (default: timestamp)
        formats: List of formats ['json', 'csv', 'txt', 'detailed']

    Returns:
        Dict mapping format -> filepath
    """
    formats = formats or ['json', 'txt']
    prefix = prefix or datetime.now().strftime("%Y%m%d_%H%M%S")

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    exporters = {
        'json': (JSONExporter(), '.json'),
        'csv': (CSVExporter(), '.csv'),
        'txt': (PlainTextExporter(), '.txt'),
        'detailed': (DetailedTextExporter(include_failed=True), '_detailed.txt'),
    }

    saved = {}

    for fmt in formats:
        if fmt not in exporters:
            continue

        exporter, ext = exporters[fmt]
        filepath = os.path.join(output_dir, f"{prefix}_proxies{ext}")

        if exporter.export_to_file(results, filepath):
            saved[fmt] = filepath

    return saved


# =============================================================================
# Integration Hooks
# =============================================================================

class ResultHook(ABC):
    """Base class for result processing hooks."""

    @abstractmethod
    def on_result(self, result: ProxyResult):
        """Called for each scan result."""
        pass

    def on_batch_complete(self, results: ScanResults):
        """Called when a batch scan completes."""
        pass

    def on_error(self, error: Exception):
        """Called on errors."""
        pass


class CallbackHook(ResultHook):
    """Hook that calls a user-provided function."""

    def __init__(
        self,
        on_result: Callable[[ProxyResult], None] = None,
        on_complete: Callable[[ScanResults], None] = None,
        on_error: Callable[[Exception], None] = None
    ):
        self._on_result = on_result
        self._on_complete = on_complete
        self._on_error = on_error

    def on_result(self, result: ProxyResult):
        if self._on_result:
            self._on_result(result)

    def on_batch_complete(self, results: ScanResults):
        if self._on_complete:
            self._on_complete(results)

    def on_error(self, error: Exception):
        if self._on_error:
            self._on_error(error)


class FilterHook(ResultHook):
    """Hook that filters results based on criteria."""

    def __init__(
        self,
        working_only: bool = True,
        min_latency: Optional[float] = None,
        max_latency: Optional[float] = None,
        exclude_errors: List[ErrorCategory] = None,
        callback: Callable[[ProxyResult], None] = None
    ):
        self.working_only = working_only
        self.min_latency = min_latency
        self.max_latency = max_latency
        self.exclude_errors = exclude_errors or []
        self.callback = callback
        self.filtered_results: List[ProxyResult] = []

    def on_result(self, result: ProxyResult):
        # Apply filters
        if self.working_only and not result.is_working:
            return

        if result.latency_ms:
            if self.min_latency and result.latency_ms < self.min_latency:
                return
            if self.max_latency and result.latency_ms > self.max_latency:
                return

        if result.error_category in self.exclude_errors:
            return

        # Passed all filters
        self.filtered_results.append(result)

        if self.callback:
            self.callback(result)


class StreamingHook(ResultHook):
    """Hook that streams results to a file as they complete."""

    def __init__(self, filepath: str, working_only: bool = True):
        self.filepath = filepath
        self.working_only = working_only
        self._file = None

    def start(self):
        """Open the output file."""
        Path(self.filepath).parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.filepath, 'w', encoding='utf-8')

    def on_result(self, result: ProxyResult):
        if not self._file:
            self.start()

        if self.working_only and not result.is_working:
            return

        self._file.write(f"{result.proxy}\n")
        self._file.flush()

    def on_batch_complete(self, results: ScanResults):
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        if self._file:
            self._file.close()


class WebhookHook(ResultHook):
    """Hook that sends results to a webhook URL."""

    def __init__(
        self,
        url: str,
        batch_size: int = 10,
        working_only: bool = True
    ):
        self.url = url
        self.batch_size = batch_size
        self.working_only = working_only
        self._buffer: List[Dict] = []

    def on_result(self, result: ProxyResult):
        if self.working_only and not result.is_working:
            return

        self._buffer.append(result.to_dict())

        if len(self._buffer) >= self.batch_size:
            self._flush()

    def on_batch_complete(self, results: ScanResults):
        if self._buffer:
            self._flush()

    def _flush(self):
        if not self._buffer:
            return

        try:
            import requests
            requests.post(
                self.url,
                json={'proxies': self._buffer},
                timeout=10
            )
        except Exception:
            pass

        self._buffer = []


# =============================================================================
# Pipeline Integration
# =============================================================================

class ProxyPipeline:
    """
    Pipeline for processing proxy scan results.

    Allows chaining multiple hooks for complex workflows.

    Usage:
        pipeline = ProxyPipeline()
        pipeline.add_hook(FilterHook(working_only=True, max_latency=1000))
        pipeline.add_hook(StreamingHook("output.txt"))

        for result in scanner.scan_stream(proxies):
            pipeline.process(result)

        pipeline.finalize(results)
    """

    def __init__(self):
        self.hooks: List[ResultHook] = []

    def add_hook(self, hook: ResultHook) -> 'ProxyPipeline':
        """Add a hook to the pipeline."""
        self.hooks.append(hook)
        return self

    def process(self, result: ProxyResult):
        """Process a single result through all hooks."""
        for hook in self.hooks:
            try:
                hook.on_result(result)
            except Exception as e:
                hook.on_error(e)

    def finalize(self, results: ScanResults):
        """Finalize the pipeline with complete results."""
        for hook in self.hooks:
            try:
                hook.on_batch_complete(results)
            except Exception as e:
                hook.on_error(e)


# =============================================================================
# Feed Interface
# =============================================================================

class ProxyFeed:
    """
    Interface for consuming proxies from external sources.

    Subclass this to create custom feeds (APIs, databases, etc.)
    """

    def __init__(self):
        self.proxies: List[str] = []

    def fetch(self) -> List[str]:
        """Fetch proxies from the source."""
        raise NotImplementedError

    def __iter__(self):
        return iter(self.fetch())


class FileFeed(ProxyFeed):
    """Feed that reads proxies from a file."""

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath

    def fetch(self) -> List[str]:
        proxies = []
        try:
            with open(self.filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except Exception:
            pass
        return proxies


class URLFeed(ProxyFeed):
    """Feed that fetches proxies from a URL."""

    def __init__(self, url: str, timeout: int = 10):
        super().__init__()
        self.url = url
        self.timeout = timeout

    def fetch(self) -> List[str]:
        import requests
        import re

        try:
            response = requests.get(self.url, timeout=self.timeout)
            if response.status_code == 200:
                # Extract IP:port patterns
                pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b'
                matches = re.findall(pattern, response.text)
                return [f"{ip}:{port}" for ip, port in matches]
        except Exception:
            pass
        return []


class MultiFeed(ProxyFeed):
    """Feed that combines multiple sources."""

    def __init__(self, feeds: List[ProxyFeed]):
        super().__init__()
        self.feeds = feeds

    def fetch(self) -> List[str]:
        all_proxies = []
        for feed in self.feeds:
            try:
                all_proxies.extend(feed.fetch())
            except Exception:
                pass
        # Deduplicate
        return list(set(all_proxies))
