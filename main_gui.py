#!/usr/bin/env python3
"""
PCAP Analyzer GUI - Main Entry Point
Automated network traffic analysis tool with PyQt6 interface
"""

import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from gui.main_window import MainWindow
from gui.app_icon import get_app_icon, save_icon_file


def main():
    """Main entry point for GUI application"""
    app = QApplication(sys.argv)
    app.setApplicationName("PCAP Analyzer")
    app.setOrganizationName("Network Tools")

    # Get and set application icon
    icon = get_app_icon()
    app.setWindowIcon(icon)

    # Save icon to file for better desktop integration
    try:
        icon_path = save_icon_file()
        print(f"Icon saved to: {icon_path}")
    except Exception as e:
        print(f"Could not save icon file: {e}")

    # On Linux, set additional properties for taskbar icon
    if sys.platform.startswith('linux'):
        app.setDesktopFileName("pcap-analyzer.desktop")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
