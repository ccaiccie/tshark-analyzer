"""Packet detail dialog for viewing individual packet information"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTextEdit, QPushButton,
    QHBoxLayout, QLabel, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont


class PacketDetailWorker(QThread):
    """Worker thread for fetching packet details"""
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, tshark, frame_number):
        super().__init__()
        self.tshark = tshark
        self.frame_number = frame_number

    def run(self):
        try:
            # Get verbose packet details using tshark -V
            import subprocess
            result = subprocess.run(
                ['tshark', '-r', self.tshark.pcap_file, '-Y', f'frame.number=={self.frame_number}', '-V'],
                capture_output=True,
                text=True,
                check=True
            )
            self.finished.emit(result.stdout)
        except Exception as e:
            self.error.emit(str(e))


class PacketDetailDialog(QDialog):
    """Dialog to show detailed information about a single packet"""

    def __init__(self, tshark, frame_number, parent=None):
        super().__init__(parent)
        self.tshark = tshark
        self.frame_number = frame_number
        self.worker = None
        self.init_ui()
        self.load_packet_details()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"Packet Details - Frame {self.frame_number}")
        self.setGeometry(200, 200, 900, 700)

        layout = QVBoxLayout(self)

        # Header
        header_label = QLabel(f"Frame Number: {self.frame_number}")
        header_font = QFont()
        header_font.setPointSize(12)
        header_font.setBold(True)
        header_label.setFont(header_font)
        layout.addWidget(header_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        layout.addWidget(self.progress_bar)

        # Text area for packet details
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Courier", 9))
        self.detail_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.detail_text)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def load_packet_details(self):
        """Load packet details in background thread"""
        self.detail_text.setText("Loading packet details...")
        self.progress_bar.setVisible(True)

        self.worker = PacketDetailWorker(self.tshark, self.frame_number)
        self.worker.finished.connect(self.on_details_loaded)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_details_loaded(self, details: str):
        """Handle loaded packet details"""
        self.progress_bar.setVisible(False)
        self.detail_text.setText(details)

    def on_error(self, error_msg: str):
        """Handle error loading details"""
        self.progress_bar.setVisible(False)
        self.detail_text.setText(f"Error loading packet details:\n\n{error_msg}")
