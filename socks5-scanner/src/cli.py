#!/usr/bin/env python3
"""
Unified CLI for SOCKS5 Proxy Scanner.

Supports both sync and async modes with full configurability.

Usage:
    # Scan from file (sync mode)
    python -m src.cli scan proxies.txt

    # Scan from file (async mode - faster)
    python -m src.cli scan proxies.txt --async

    # Scan from URL sources
    python -m src.cli fetch --sources default

    # Scan single proxy
    python -m src.cli test 1.2.3.4:1080
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import List, Optional

from .core import ScanConfig, ProxyResult, ScanResults
from .logger import setup_logger, ProgressReporter, get_logger
from .export import export_results, PlainTextExporter, JSONExporter


def main():
    parser = argparse.ArgumentParser(
        prog='socks5-scanner',
        description='High-performance SOCKS5 proxy scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan proxies.txt                    Scan proxies from file (sync)
  %(prog)s scan proxies.txt --async -c 200     Scan async with 200 concurrent
  %(prog)s scan proxies.txt -o results/        Export to directory
  %(prog)s test 1.2.3.4:1080                   Test single proxy
  %(prog)s fetch --sources default             Fetch from default sources
        '''
    )

    # Global options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Minimal output (errors only)')
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # === SCAN command ===
    scan_parser = subparsers.add_parser('scan', help='Scan proxies from file/stdin')
    scan_parser.add_argument('input', nargs='?', default='-',
                            help='Input file (- for stdin)')
    scan_parser.add_argument('-o', '--output', default='./results',
                            help='Output directory')
    scan_parser.add_argument('-f', '--format', nargs='+',
                            choices=['json', 'csv', 'txt', 'detailed'],
                            default=['json', 'txt'],
                            help='Output formats')
    scan_parser.add_argument('--async', dest='use_async', action='store_true',
                            help='Use async scanner (faster)')
    scan_parser.add_argument('-c', '--concurrency', type=int, default=50,
                            help='Concurrent connections (default: 50)')
    scan_parser.add_argument('--timeout', type=float, default=5.0,
                            help='Connection timeout in seconds')
    scan_parser.add_argument('--http-timeout', type=float, default=10.0,
                            help='HTTP test timeout in seconds')
    scan_parser.add_argument('--retries', type=int, default=1,
                            help='Retry count for failed connections')
    scan_parser.add_argument('--test-url', default='http://httpbin.org/ip',
                            help='URL for HTTP connectivity test')
    scan_parser.add_argument('--no-http', action='store_true',
                            help='Skip HTTP test (faster, less accurate)')
    scan_parser.add_argument('--working-only', action='store_true',
                            help='Only output working proxies')

    # === TEST command ===
    test_parser = subparsers.add_parser('test', help='Test a single proxy')
    test_parser.add_argument('proxy', help='Proxy address (ip:port)')
    test_parser.add_argument('--timeout', type=float, default=5.0,
                            help='Connection timeout')
    test_parser.add_argument('--verbose', '-v', action='store_true',
                            help='Show detailed timing')

    # === FETCH command ===
    fetch_parser = subparsers.add_parser('fetch', help='Fetch and scan from sources')
    fetch_parser.add_argument('--sources', default='default',
                             help='Source set: default, extended, or URL')
    fetch_parser.add_argument('-o', '--output', default='./results',
                             help='Output directory')
    fetch_parser.add_argument('--async', dest='use_async', action='store_true',
                             help='Use async scanner')
    fetch_parser.add_argument('-c', '--concurrency', type=int, default=100,
                             help='Concurrent connections')

    # === VERSION command ===
    subparsers.add_parser('version', help='Show version info')

    args = parser.parse_args()

    # Setup logging
    if args.quiet:
        import logging
        log_level = logging.WARNING
    elif args.debug:
        import logging
        log_level = logging.DEBUG
    elif args.verbose:
        import logging
        log_level = logging.INFO
    else:
        import logging
        log_level = logging.INFO

    logger = setup_logger(level=log_level, compact=not args.verbose)

    # Route to command handler
    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'test':
        return cmd_test(args)
    elif args.command == 'fetch':
        return cmd_fetch(args)
    elif args.command == 'version':
        return cmd_version()
    else:
        parser.print_help()
        return 1


def cmd_scan(args) -> int:
    """Handle scan command."""
    logger = get_logger()

    # Read proxies
    proxies = read_proxies(args.input)
    if not proxies:
        logger.error("No proxies to scan")
        return 1

    logger.info(f"Loaded {len(proxies)} proxies")

    # Build config
    config = ScanConfig(
        connect_timeout=args.timeout,
        read_timeout=args.timeout,
        write_timeout=args.timeout,
        http_timeout=args.http_timeout,
        max_retries=args.retries,
        max_concurrent=args.concurrency,
        test_url=args.test_url,
    )

    # Run scan
    start_time = time.time()

    if args.use_async:
        results = run_async_scan(proxies, config, args.concurrency)
    else:
        results = run_sync_scan(proxies, config)

    elapsed = time.time() - start_time

    # Print summary
    print_summary(results, elapsed)

    # Export results
    if args.output:
        saved = export_results(
            results,
            output_dir=args.output,
            formats=args.format
        )
        for fmt, path in saved.items():
            logger.info(f"Saved {fmt}: {path}")

    # JSON output mode
    if hasattr(args, 'json') and args.json:
        import json
        print(json.dumps(results.to_dict(), indent=2))

    return 0 if results.working > 0 else 1


def cmd_test(args) -> int:
    """Handle test command."""
    from .sync_scanner import SyncScanner

    config = ScanConfig(
        connect_timeout=args.timeout,
        read_timeout=args.timeout,
    )

    print(f"Testing {args.proxy}...")

    with SyncScanner(config) as scanner:
        result = scanner.scan_one(args.proxy)

    # Display result
    if result.is_working:
        print(f"\n✓ Proxy is WORKING")
    else:
        print(f"\n✗ Proxy FAILED")

    print(f"\n  Reachable:    {'Yes' if result.reachable else 'No'}")
    print(f"  SOCKS5 Valid: {'Yes' if result.socks5_valid else 'No'}")
    print(f"  Tunnel Works: {'Yes' if result.tunnel_works else 'No'}")
    print(f"  HTTP Works:   {'Yes' if result.http_works else 'No'}")

    if result.latency_ms:
        print(f"  Latency:      {result.latency_ms:.0f}ms")

    if result.external_ip:
        print(f"  External IP:  {result.external_ip}")

    if result.error:
        print(f"  Error:        {result.error}")
        print(f"  Category:     {result.error_category.name}")
        print(f"  Stage:        {result.error_stage}")

    if args.verbose and result.timing:
        print(f"\n  Timing breakdown:")
        if result.timing.connect_ms:
            print(f"    Connect:    {result.timing.connect_ms:.0f}ms")
        if result.timing.handshake_ms:
            print(f"    Handshake:  {result.timing.handshake_ms:.0f}ms")
        if result.timing.tunnel_ms:
            print(f"    Tunnel:     {result.timing.tunnel_ms:.0f}ms")
        if result.timing.http_ms:
            print(f"    HTTP:       {result.timing.http_ms:.0f}ms")

    return 0 if result.is_working else 1


def cmd_fetch(args) -> int:
    """Handle fetch command."""
    from .scanner import ProxyScanner

    logger = get_logger()
    logger.info(f"Fetching proxies from {args.sources} sources...")

    # Fetch proxies
    scanner = ProxyScanner()
    proxies = scanner.fetch_all_sources()

    if not proxies:
        logger.error("No proxies fetched")
        return 1

    logger.info(f"Fetched {len(proxies)} proxies")

    # Build config
    config = ScanConfig(max_concurrent=args.concurrency)

    # Run scan
    start_time = time.time()

    if args.use_async:
        results = run_async_scan(list(proxies), config, args.concurrency)
    else:
        results = run_sync_scan(list(proxies), config)

    elapsed = time.time() - start_time

    print_summary(results, elapsed)

    # Export
    if args.output:
        saved = export_results(results, output_dir=args.output)
        for fmt, path in saved.items():
            logger.info(f"Saved {fmt}: {path}")

    return 0


def cmd_version() -> int:
    """Show version info."""
    print("SOCKS5 Proxy Scanner v2.0.0")
    print("High-performance proxy scanning utility")
    print()
    print("Features:")
    print("  - Sync and async scanning modes")
    print("  - Structured error categorization")
    print("  - Configurable timeouts and retries")
    print("  - JSON/CSV/TXT export")
    print("  - Pipeline integration hooks")
    return 0


# =============================================================================
# Helper Functions
# =============================================================================

def read_proxies(source: str) -> List[str]:
    """Read proxies from file or stdin."""
    proxies = []

    if source == '-':
        # Read from stdin
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                proxies.append(line)
    else:
        # Read from file
        path = Path(source)
        if not path.exists():
            return []

        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)

    return proxies


def run_sync_scan(proxies: List[str], config: ScanConfig) -> ScanResults:
    """Run synchronous scan with progress."""
    from .sync_scanner import SyncScanner

    results = ScanResults(config=config)

    with ProgressReporter(len(proxies), "Scanning (sync)") as progress:
        def on_result(result: ProxyResult):
            results.add(result)
            progress.update(result)

        with SyncScanner(config) as scanner:
            scan_results = scanner.scan_many(
                proxies,
                callback=on_result,
                max_workers=config.max_concurrent
            )

    return scan_results


def run_async_scan(proxies: List[str], config: ScanConfig, concurrency: int) -> ScanResults:
    """Run asynchronous scan."""
    from .async_scanner_v2 import AsyncScanner, install_uvloop

    # Try to use uvloop for better performance
    install_uvloop()

    async def do_scan():
        completed = 0
        total = len(proxies)

        async def progress_cb(done: int, total: int):
            nonlocal completed
            completed = done
            pct = (done / total) * 100 if total > 0 else 100
            print(f"\rScanning (async) │ {done}/{total} ({pct:.0f}%)", end='', flush=True)

        async with AsyncScanner(config) as scanner:
            results = await scanner.scan_many(
                proxies,
                concurrency=concurrency,
                progress_callback=progress_cb
            )

        print()  # New line after progress
        return results

    return asyncio.run(do_scan())


def print_summary(results: ScanResults, elapsed: float):
    """Print scan summary."""
    rate = results.total / elapsed if elapsed > 0 else 0

    print()
    print("=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    print(f"  Total scanned:  {results.total}")
    print(f"  Reachable:      {results.reachable}")
    print(f"  SOCKS5 valid:   {results.valid}")
    print(f"  Fully working:  {results.working}")
    print(f"  Failed:         {results.failed}")
    print(f"  Duration:       {elapsed:.1f}s")
    print(f"  Rate:           {rate:.1f} proxies/sec")
    print("=" * 50)

    # Show error breakdown if verbose
    if results.failed > 0:
        from .core import ErrorCategory
        print("\nError breakdown:")
        error_counts = {}
        for r in results.results:
            if r.error_category != ErrorCategory.NONE:
                cat = r.error_category.name
                error_counts[cat] = error_counts.get(cat, 0) + 1

        for cat, count in sorted(error_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"  {cat}: {count}")


if __name__ == '__main__':
    sys.exit(main())
