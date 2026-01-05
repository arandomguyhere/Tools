#!/usr/bin/env python3
"""
SOCKS5 Proxy Scanner - Main CLI Entry Point

A multi-threaded tool for discovering and validating SOCKS5 proxies
from various free sources.

Usage:
    python -m src.main [options]
    python src/main.py [options]

Examples:
    # Scan free sources with default settings
    python -m src.main

    # Scan with custom thread count
    python -m src.main --threads 50

    # Test proxies from a file
    python -m src.main --mode file --proxy-file proxies.txt

    # Scan and save to custom directory
    python -m src.main --output ./my_results
"""

import argparse
import os
import sys
import warnings
from pathlib import Path

import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import Socks5Scanner
from src.validator import ProxyValidator
from src.utils import Color, print_banner

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file."""
    default_paths = [
        'config/config.yaml',
        'config/config.yml',
        os.path.join(Path.home(), '.config/socks5-scanner/config.yaml'),
    ]

    if config_path:
        paths_to_try = [config_path]
    else:
        paths_to_try = default_paths

    for path in paths_to_try:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
                    print(f"Loaded config from: {path}")
                    return config
            except Exception as e:
                print(f"Warning: Failed to load {path}: {e}")

    # Return default config
    return {
        'scanner': {
            'timeout': 15,
            'sources': None,  # Use default sources
        },
        'validator': {
            'timeout': 5,
            'test_urls': [
                'http://httpbin.org/ip',
                'http://icanhazip.com',
            ],
        },
        'output': {
            'directory': './results',
        },
    }


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SOCKS5 Proxy Scanner - Discover and validate SOCKS5 proxies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Scan free sources with defaults
  %(prog)s -t 50                    Scan with 50 threads
  %(prog)s --async -c 200           Async mode with 200 concurrent
  %(prog)s --geo                    Include geolocation lookup
  %(prog)s -m file -f proxies.txt   Test proxies from file
  %(prog)s -o ./my_results          Save to custom directory
        """
    )

    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file (YAML)'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=['free', 'file', 'hunt', 'both'],
        default='free',
        help='Scan mode: free (static sources), file (local), hunt (GitHub discovery), both'
    )

    parser.add_argument(
        '-f', '--proxy-file',
        help='Proxy list file (required for file/both modes)'
    )

    parser.add_argument(
        '--hunt',
        action='store_true',
        help='Enable GitHub repository hunting (discovers new sources)'
    )

    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=20,
        help='Number of validation threads (default: 20)'
    )

    parser.add_argument(
        '--async',
        dest='async_mode',
        action='store_true',
        help='Use async mode for faster scanning (requires aiohttp)'
    )

    parser.add_argument(
        '--concurrency',
        type=int,
        default=100,
        help='Concurrency level for async mode (default: 100)'
    )

    parser.add_argument(
        '--geo',
        action='store_true',
        help='Enable geolocation lookup for proxies'
    )

    parser.add_argument(
        '-o', '--output',
        default='./results',
        help='Output directory for results (default: ./results)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Validation timeout in seconds (default: 5)'
    )

    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='Only collect proxies, skip validation'
    )

    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner output'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - minimal output'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Print banner
    if not args.no_banner and not args.quiet:
        print_banner()

    # Load configuration
    config = load_config(args.config)

    # Override config with command line args
    if args.timeout:
        config.setdefault('validator', {})['timeout'] = args.timeout

    # Validate arguments
    if args.mode in ['file', 'both'] and not args.proxy_file:
        print(f"{Color.red('Error:')} --proxy-file is required for mode '{args.mode}'")
        sys.exit(1)

    if args.proxy_file and not os.path.exists(args.proxy_file):
        print(f"{Color.red('Error:')} Proxy file not found: {args.proxy_file}")
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Determine if hunting is enabled
    use_hunter = args.hunt or args.mode == 'hunt'

    # Print settings
    if not args.quiet:
        mode_display = args.mode
        if use_hunter and args.mode != 'hunt':
            mode_display += " + hunt"
        if args.async_mode:
            mode_display += " (async)"
        print(f"Mode: {mode_display}")
        if args.async_mode:
            print(f"Concurrency: {args.concurrency}")
        else:
            print(f"Threads: {args.threads}")
        print(f"Output: {args.output}")
        if args.geo:
            print("Geolocation: enabled")
        if use_hunter:
            print("GitHub hunting: enabled")
        if args.proxy_file:
            print(f"Proxy file: {args.proxy_file}")

    try:
        # Async mode
        if args.async_mode:
            try:
                from src.async_scanner import AsyncSocks5Scanner
                import asyncio
            except ImportError as e:
                print(f"{Color.red('Error:')} Async mode requires aiohttp: pip install aiohttp")
                sys.exit(1)

            scanner_config = config.get('scanner', {})
            scanner_config['validator'] = config.get('validator', {})
            scanner = AsyncSocks5Scanner(scanner_config)

            results = asyncio.run(scanner.run_scan(
                concurrency=args.concurrency,
                output_dir=args.output,
                validate=not args.no_validate,
                geo_lookup=args.geo
            ))

        # Sync mode (default)
        else:
            scanner_config = config.get('scanner', {})
            scanner_config['validator'] = config.get('validator', {})
            scanner = Socks5Scanner(scanner_config)

            results = scanner.run_full_scan(
                max_workers=args.threads,
                mode=args.mode,
                output_dir=args.output,
                validate=not args.no_validate,
                proxy_file=args.proxy_file,
                use_hunter=use_hunter
            )

        # Exit with appropriate code
        if results.get('stats', {}).get('working', 0) > 0:
            sys.exit(0)
        elif results.get('stats', {}).get('valid', 0) > 0:
            sys.exit(0)
        elif results.get('proxies'):
            sys.exit(0)
        else:
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{Color.yellow('Scan interrupted by user')}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Color.red('Error:')} {e}")
        if os.getenv('DEBUG'):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
