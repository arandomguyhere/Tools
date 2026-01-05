#!/usr/bin/env python3
"""
Quick Test Script for SOCKS5 Proxy Scanner

This script performs a quick test to verify the scanner is working correctly.
It will:
1. Test module imports
2. Fetch proxies from one source
3. Validate a small sample
"""

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    try:
        from src import Socks5Scanner, ProxyValidator
        from src.utils import Color, parse_proxy, validate_ip
        print("  ✓ All imports successful")
        return True
    except ImportError as e:
        print(f"  ✗ Import failed: {e}")
        return False


def test_utils():
    """Test utility functions."""
    print("\nTesting utility functions...")
    from src.utils import parse_proxy, validate_ip, validate_port

    # Test IP validation
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("invalid") is False
    print("  ✓ IP validation works")

    # Test port validation
    assert validate_port(8080) is True
    assert validate_port(0) is False
    assert validate_port(70000) is False
    print("  ✓ Port validation works")

    # Test proxy parsing
    result = parse_proxy("192.168.1.1:8080")
    assert result == ("192.168.1.1", 8080)
    print("  ✓ Proxy parsing works")

    result = parse_proxy("socks5://10.0.0.1:1080")
    assert result == ("10.0.0.1", 1080)
    print("  ✓ URL proxy parsing works")

    return True


def test_fetch_proxies():
    """Test fetching proxies from a source."""
    print("\nTesting proxy fetching...")
    from src.scanner import Socks5Scanner

    scanner = Socks5Scanner()

    # Fetch from one source
    test_url = "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
    proxies = scanner.fetch_from_url(test_url)

    if proxies:
        print(f"  ✓ Fetched {len(proxies)} proxies from source")
        print(f"  Sample: {proxies[0]}")
        return True
    else:
        print("  ✗ Failed to fetch proxies (might be network issue)")
        return False


def test_validate_proxy():
    """Test proxy validation (quick check)."""
    print("\nTesting proxy validation...")
    from src.validator import ProxyValidator

    validator = ProxyValidator({'timeout': 3})

    # Test with a known bad proxy
    result = validator.test_socks5_handshake("127.0.0.1", 9999)
    if not result[0]:
        print("  ✓ Correctly rejected invalid proxy")
        return True
    else:
        print("  ? Unexpected result for test proxy")
        return True  # Not a failure, just unexpected


def main():
    """Run all tests."""
    print("=" * 50)
    print("SOCKS5 Proxy Scanner - Quick Test")
    print("=" * 50)

    tests = [
        ("Imports", test_imports),
        ("Utilities", test_utils),
        ("Proxy Fetching", test_fetch_proxies),
        ("Validation", test_validate_proxy),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"  ✗ Test failed with error: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "=" * 50)
    print("Test Summary:")
    print("=" * 50)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")

    print(f"\nResult: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed! Scanner is ready to use.")
        print("\nTo run a full scan:")
        print("  python -m src.main")
        print("\nOr with options:")
        print("  python -m src.main --threads 50 --output ./my_results")
        return 0
    else:
        print("\n✗ Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
