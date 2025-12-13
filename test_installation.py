#!/usr/bin/env python3
"""
Test script to verify PCAP Analyzer installation
"""

import sys
import subprocess


def test_python_version():
    """Check Python version"""
    print("Testing Python version...", end=" ")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (Need 3.7+)")
        return False


def test_pyqt6():
    """Check if PyQt6 is installed"""
    print("Testing PyQt6...", end=" ")
    try:
        import PyQt6.QtWidgets
        import PyQt6.QtCore
        print(f"✓ PyQt6 installed")
        return True
    except ImportError:
        print("✗ PyQt6 not found (run: pip install PyQt6)")
        return False


def test_tshark():
    """Check if tshark is available"""
    print("Testing tshark...", end=" ")
    try:
        result = subprocess.run(
            ['tshark', '--version'],
            capture_output=True,
            text=True,
            check=True
        )
        version_line = result.stdout.split('\n')[0]
        print(f"✓ {version_line}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ tshark not found (install Wireshark/tshark)")
        return False


def test_imports():
    """Test if all modules can be imported"""
    print("Testing module imports...", end=" ")
    try:
        from core.tshark_wrapper import TsharkWrapper
        from core.report_generator import ReportGenerator
        from analyzers.tcp_analyzer import TCPAnalyzer
        from analyzers.dns_analyzer import DNSAnalyzer
        from analyzers.http_analyzer import HTTPAnalyzer
        from analyzers.network_analyzer import NetworkAnalyzer
        print("✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("PCAP Analyzer Installation Test")
    print("=" * 60)
    print()

    tests = [
        test_python_version,
        test_pyqt6,
        test_tshark,
        test_imports
    ]

    results = [test() for test in tests]

    print()
    print("=" * 60)
    if all(results):
        print("✓ All tests passed! Installation is complete.")
        print("\nYou can now run:")
        print("  python main_gui.py      # Start GUI application")
        print("  python pcap_analyzer.py <file.pcap>  # CLI mode")
    else:
        print("✗ Some tests failed. Please fix the issues above.")
        print("\nInstallation steps:")
        print("  1. pip install -r requirements.txt")
        print("  2. Install tshark: sudo apt-get install tshark")
    print("=" * 60)

    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main())
