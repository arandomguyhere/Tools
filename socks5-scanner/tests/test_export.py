"""
Tests for export.py - Export formats and integration hooks.
"""

import pytest
import json
from src.export import (
    JSONExporter, CSVExporter, PlainTextExporter, DetailedTextExporter,
    ProxyPipeline, FilterHook, CallbackHook,
    FileFeed, URLFeed, MultiFeed,
    export_results
)
from src.core import ProxyResult, ScanResults, ErrorCategory


class TestJSONExporter:
    """Tests for JSON export."""

    def test_export_empty(self):
        results = ScanResults()
        exporter = JSONExporter()
        output = exporter.export_to_string(results)

        data = json.loads(output)
        assert data["stats"]["total"] == 0
        assert data["results"] == []

    def test_export_with_results(self):
        results = ScanResults()
        results.add(ProxyResult(
            proxy="1.2.3.4:1080",
            socks5_valid=True,
            tunnel_works=True,
            latency_ms=100
        ))

        exporter = JSONExporter()
        output = exporter.export_to_string(results)

        data = json.loads(output)
        assert data["stats"]["total"] == 1
        assert data["stats"]["working"] == 1
        assert len(data["results"]) == 1
        assert data["results"][0]["proxy"] == "1.2.3.4:1080"

    def test_exclude_failed(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        results.add(ProxyResult(proxy="2.2.2.2:1080", error="failed"))

        exporter = JSONExporter(include_failed=False)
        output = exporter.export_to_string(results)

        data = json.loads(output)
        assert len(data["results"]) == 1


class TestCSVExporter:
    """Tests for CSV export."""

    def test_export_headers(self):
        results = ScanResults()
        exporter = CSVExporter()
        output = exporter.export_to_string(results)

        lines = output.strip().split("\n")
        assert "proxy" in lines[0]
        assert "reachable" in lines[0]

    def test_export_with_data(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.2.3.4:1080", reachable=True))

        exporter = CSVExporter()
        output = exporter.export_to_string(results)

        lines = output.strip().split("\n")
        assert len(lines) == 2  # Header + 1 row
        assert "1.2.3.4:1080" in lines[1]


class TestPlainTextExporter:
    """Tests for plain text export."""

    def test_export_working_only(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        results.add(ProxyResult(proxy="2.2.2.2:1080", socks5_valid=False))

        exporter = PlainTextExporter(working_only=True)
        output = exporter.export_to_string(results)

        lines = output.strip().split("\n")
        assert len(lines) == 1
        assert lines[0] == "1.1.1.1:1080"

    def test_export_all(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))
        results.add(ProxyResult(proxy="2.2.2.2:1080", socks5_valid=False))

        exporter = PlainTextExporter(working_only=False)
        output = exporter.export_to_string(results)

        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_with_protocol(self):
        results = ScanResults()
        results.add(ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True))

        exporter = PlainTextExporter(include_protocol=True)
        output = exporter.export_to_string(results)

        assert output.strip() == "socks5://1.1.1.1:1080"


class TestProxyPipeline:
    """Tests for pipeline hooks."""

    def test_empty_pipeline(self):
        pipeline = ProxyPipeline()
        result = ProxyResult(proxy="1.2.3.4:1080")
        pipeline.process(result)  # Should not raise

    def test_callback_hook(self):
        collected = []

        def on_result(r):
            collected.append(r.proxy)

        pipeline = ProxyPipeline()
        pipeline.add_hook(CallbackHook(on_result=on_result))

        pipeline.process(ProxyResult(proxy="1.1.1.1:1080"))
        pipeline.process(ProxyResult(proxy="2.2.2.2:1080"))

        assert len(collected) == 2
        assert "1.1.1.1:1080" in collected

    def test_filter_hook(self):
        hook = FilterHook(working_only=True, max_latency=500)

        # Should pass
        r1 = ProxyResult(proxy="1.1.1.1:1080", socks5_valid=True, tunnel_works=True, latency_ms=100)
        hook.on_result(r1)

        # Should be filtered (not working)
        r2 = ProxyResult(proxy="2.2.2.2:1080", socks5_valid=False)
        hook.on_result(r2)

        # Should be filtered (too slow)
        r3 = ProxyResult(proxy="3.3.3.3:1080", socks5_valid=True, tunnel_works=True, latency_ms=1000)
        hook.on_result(r3)

        assert len(hook.filtered_results) == 1
        assert hook.filtered_results[0].proxy == "1.1.1.1:1080"


class TestFeeds:
    """Tests for feed interfaces."""

    def test_file_feed_nonexistent(self):
        feed = FileFeed("/nonexistent/file.txt")
        proxies = feed.fetch()
        assert proxies == []

    def test_multi_feed(self):
        # Create mock feeds
        class MockFeed:
            def __init__(self, proxies):
                self._proxies = proxies
            def fetch(self):
                return self._proxies

        feed = MultiFeed([
            MockFeed(["1.1.1.1:1080", "2.2.2.2:1080"]),
            MockFeed(["3.3.3.3:1080", "1.1.1.1:1080"]),  # Duplicate
        ])

        proxies = feed.fetch()
        assert len(proxies) == 3  # Deduplicated
