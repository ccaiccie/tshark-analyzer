"""Packet viewer widget for drilling down into packet details"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QMessageBox,
    QHeaderView, QGroupBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from typing import List, Dict, Any
import subprocess
from pathlib import Path


class PacketViewer(QWidget):
    """Widget for displaying packet details"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pcap_file = None
        self.tshark = None
        self.current_filter = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)

        # Header
        header_layout = QHBoxLayout()

        self.title_label = QLabel("Packet Details")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        header_layout.addWidget(self.title_label)

        header_layout.addStretch()

        # Open in Wireshark button
        self.wireshark_btn = QPushButton("Open in Wireshark")
        self.wireshark_btn.setEnabled(False)
        self.wireshark_btn.clicked.connect(self.open_in_wireshark)
        self.wireshark_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        header_layout.addWidget(self.wireshark_btn)

        layout.addLayout(header_layout)

        # Info label
        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        layout.addWidget(self.info_label)

        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(9)
        self.packet_table.setHorizontalHeaderLabels([
            "Frame #", "Time", "Source IP", "Src Port",
            "Destination IP", "Dst Port", "Protocol", "Length", "Info"
        ])

        # Set column widths
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)

        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d0d0d0;
            }
            QTableWidget::item:selected {
                background-color: #E3F2FD;
                color: black;
            }
        """)

        layout.addWidget(self.packet_table)

    def set_pcap_file(self, pcap_file: str, tshark):
        """Set the PCAP file and tshark wrapper"""
        self.pcap_file = pcap_file
        self.tshark = tshark

    def display_packets(self, filter_string: str, category: str, description: str):
        """Display packets matching the filter"""
        if not self.tshark:
            return

        self.current_filter = filter_string
        self.title_label.setText(f"Packet Details: {category}")
        self.info_label.setText(f"{description}\nFilter: {filter_string}\n\nLoading packets...")

        try:
            # First check if any packets match the filter
            frame_count = self.tshark.count_packets(filter_string)

            if frame_count == 0:
                self.info_label.setText(
                    f"{description}\n"
                    f"Filter: {filter_string}\n\n"
                    f"No packets match this filter in the capture.\n"
                    f"This could mean the packets were not captured or the filter needs adjustment."
                )
                self.packet_table.setRowCount(0)
                self.wireshark_btn.setEnabled(False)
                return

            # Get packet details
            packets = self.tshark.get_packet_details(filter_string, limit=1000)

            # Clear table
            self.packet_table.setRowCount(0)

            if not packets:
                self.info_label.setText(
                    f"{description}\n"
                    f"Filter: {filter_string}\n\n"
                    f"Found {frame_count} matching packets, but unable to extract details.\n"
                    f"Try opening in Wireshark for full packet inspection."
                )
                self.wireshark_btn.setEnabled(True)
                return

            # Populate table
            self.packet_table.setRowCount(len(packets))

            for row, packet in enumerate(packets):
                # Frame number
                item = QTableWidgetItem(str(packet['frame_number']))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.packet_table.setItem(row, 0, item)

                # Timestamp
                item = QTableWidgetItem(packet['timestamp'])
                self.packet_table.setItem(row, 1, item)

                # Source IP
                item = QTableWidgetItem(packet['src_ip'])
                self.packet_table.setItem(row, 2, item)

                # Source port
                item = QTableWidgetItem(packet['src_port'])
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.packet_table.setItem(row, 3, item)

                # Destination IP
                item = QTableWidgetItem(packet['dst_ip'])
                self.packet_table.setItem(row, 4, item)

                # Destination port
                item = QTableWidgetItem(packet['dst_port'])
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.packet_table.setItem(row, 5, item)

                # Protocol
                item = QTableWidgetItem(packet['protocols'])
                self.packet_table.setItem(row, 6, item)

                # Length
                item = QTableWidgetItem(packet['length'])
                item.setTextAlignment(Qt.AlignmentFlag.AlignRight)
                self.packet_table.setItem(row, 7, item)

                # Info
                item = QTableWidgetItem(packet['info'])
                self.packet_table.setItem(row, 8, item)

            count_text = f"Showing {len(packets)} packets"
            if len(packets) >= 1000:
                count_text += " (limited to first 1000)"

            self.info_label.setText(f"{description}\nFilter: {filter_string}\n{count_text}")
            self.wireshark_btn.setEnabled(True)

        except Exception as e:
            self.info_label.setText(f"Error loading packets: {str(e)}")
            self.wireshark_btn.setEnabled(False)

    def open_in_wireshark(self):
        """Open the current PCAP in Wireshark with the filter applied"""
        if not self.pcap_file or not self.current_filter:
            return

        try:
            # Try to open Wireshark with the display filter
            subprocess.Popen([
                'wireshark',
                self.pcap_file,
                '-Y', self.current_filter
            ])
        except FileNotFoundError:
            QMessageBox.warning(
                self,
                "Wireshark Not Found",
                "Wireshark is not installed or not in PATH.\n\n"
                "To install Wireshark:\n"
                "Ubuntu/Debian: sudo apt-get install wireshark\n"
                "macOS: brew install wireshark\n"
                "Windows: Download from https://www.wireshark.org"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Wireshark:\n\n{str(e)}"
            )

    def clear(self):
        """Clear the packet viewer"""
        self.packet_table.setRowCount(0)
        self.info_label.setText("")
        self.title_label.setText("Packet Details")
        self.current_filter = None
        self.wireshark_btn.setEnabled(False)
