"""Main window for PCAP Analyzer GUI"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QProgressBar,
    QGroupBox, QSplitter, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from pathlib import Path
from typing import Dict, Any
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcap_analyzer import PcapAnalyzer
from gui.packet_viewer import PacketViewer
from gui.app_icon import get_app_icon


class AnalysisWorker(QThread):
    """Worker thread for running analysis"""
    finished = pyqtSignal(dict, object)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, pcap_file: str):
        super().__init__()
        self.pcap_file = pcap_file

    def run(self):
        try:
            self.progress.emit("Initializing analyzer...")
            analyzer = PcapAnalyzer(self.pcap_file)

            self.progress.emit("Running analysis...")
            results = analyzer.analyze()

            self.progress.emit("Analysis complete!")
            self.finished.emit(results, analyzer)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.current_results = None
        self.current_analyzer = None
        self.worker = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("PCAP Analyzer - Network Traffic Analysis Tool")
        self.setWindowIcon(get_app_icon())
        self.setGeometry(100, 100, 1200, 800)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Title
        title_label = QLabel("PCAP Analyzer")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Automated Network Traffic Analysis using TShark")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: #666; margin-bottom: 20px;")
        main_layout.addWidget(subtitle_label)

        # File selection group
        file_group = QGroupBox("PCAP File Selection")
        file_layout = QHBoxLayout()

        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("padding: 5px; background-color: #f0f0f0; border-radius: 3px;")
        file_layout.addWidget(self.file_label, 1)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 8px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        file_layout.addWidget(self.analyze_btn)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)

        # Progress label
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        self.progress_label.setStyleSheet("color: #666; font-style: italic;")
        main_layout.addWidget(self.progress_label)

        # Results area with tabs
        self.tabs = QTabWidget()

        # Overview tab
        self.overview_tree = QTreeWidget()
        self.overview_tree.setHeaderLabels(["Category", "Issue", "Count"])
        self.overview_tree.setColumnWidth(0, 150)
        self.overview_tree.setColumnWidth(1, 500)
        self.overview_tree.itemClicked.connect(self.on_issue_clicked)
        self.tabs.addTab(self.overview_tree, "Overview")

        # Packet Details tab
        self.packet_viewer = PacketViewer()
        self.tabs.addTab(self.packet_viewer, "Packet Details")

        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Courier", 10))
        self.tabs.addTab(self.stats_text, "Statistics")

        # Details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Courier", 10))
        self.tabs.addTab(self.details_text, "Detailed Report")

        main_layout.addWidget(self.tabs)

        # Export buttons
        export_layout = QHBoxLayout()
        export_layout.addStretch()

        self.export_text_btn = QPushButton("Export as Text")
        self.export_text_btn.setEnabled(False)
        self.export_text_btn.clicked.connect(lambda: self.export_report('text'))
        export_layout.addWidget(self.export_text_btn)

        self.export_html_btn = QPushButton("Export as HTML")
        self.export_html_btn.setEnabled(False)
        self.export_html_btn.clicked.connect(lambda: self.export_report('html'))
        export_layout.addWidget(self.export_html_btn)

        self.export_json_btn = QPushButton("Export as JSON")
        self.export_json_btn.setEnabled(False)
        self.export_json_btn.clicked.connect(lambda: self.export_report('json'))
        export_layout.addWidget(self.export_json_btn)

        main_layout.addLayout(export_layout)

        # Status bar
        self.statusBar().showMessage("Ready")

    def browse_file(self):
        """Open file dialog to select PCAP file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )

        if file_path:
            self.file_label.setText(file_path)
            self.analyze_btn.setEnabled(True)
            self.statusBar().showMessage(f"Selected: {Path(file_path).name}")

    def start_analysis(self):
        """Start the analysis in a background thread"""
        pcap_file = self.file_label.text()

        if not Path(pcap_file).exists():
            QMessageBox.critical(self, "Error", "Selected file does not exist!")
            return

        # Disable buttons
        self.analyze_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_label.setVisible(True)
        self.progress_label.setText("Starting analysis...")

        # Clear previous results
        self.overview_tree.clear()
        self.stats_text.clear()
        self.details_text.clear()

        # Start worker thread
        self.worker = AnalysisWorker(pcap_file)
        self.worker.finished.connect(self.on_analysis_complete)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.progress.connect(self.on_progress_update)
        self.worker.start()

    def on_progress_update(self, message: str):
        """Update progress label"""
        self.progress_label.setText(message)

    def on_analysis_complete(self, results: Dict[str, Any], analyzer):
        """Handle analysis completion"""
        self.current_results = results
        self.current_analyzer = analyzer

        # Set up packet viewer with tshark access
        pcap_file = self.file_label.text()
        self.packet_viewer.set_pcap_file(pcap_file, analyzer.tshark)

        # Hide progress
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)

        # Re-enable buttons
        self.analyze_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)
        self.export_text_btn.setEnabled(True)
        self.export_html_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)

        # Display results
        self.display_results(results)

        self.statusBar().showMessage("Analysis complete!")

    def on_analysis_error(self, error_msg: str):
        """Handle analysis error"""
        # Hide progress
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)

        # Re-enable buttons
        self.analyze_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)

        QMessageBox.critical(self, "Analysis Error", f"An error occurred:\n\n{error_msg}")
        self.statusBar().showMessage("Analysis failed")

    def display_results(self, results: Dict[str, Any]):
        """Display analysis results in the UI"""
        # Overview tree
        self.overview_tree.clear()

        # Add critical issues
        critical = results.get('critical', [])
        if critical:
            critical_root = QTreeWidgetItem(self.overview_tree, ["CRITICAL ISSUES", "", str(len(critical))])
            critical_root.setForeground(0, QColor("#f44336"))
            critical_root.setFont(0, QFont("", -1, QFont.Weight.Bold))

            for issue in critical:
                item = QTreeWidgetItem(critical_root, [
                    issue['category'],
                    issue['description'],
                    str(issue.get('count', 1))
                ])
                item.setForeground(0, QColor("#f44336"))
                # Store issue data for drill-down
                item.setData(0, Qt.ItemDataRole.UserRole, issue)

        # Add warnings
        warnings = results.get('warnings', [])
        if warnings:
            warning_root = QTreeWidgetItem(self.overview_tree, ["WARNINGS", "", str(len(warnings))])
            warning_root.setForeground(0, QColor("#ff9800"))
            warning_root.setFont(0, QFont("", -1, QFont.Weight.Bold))

            for issue in warnings:
                item = QTreeWidgetItem(warning_root, [
                    issue['category'],
                    issue['description'],
                    str(issue.get('count', 1))
                ])
                item.setForeground(0, QColor("#ff9800"))
                # Store issue data for drill-down
                item.setData(0, Qt.ItemDataRole.UserRole, issue)

        # Add info
        info = results.get('info', [])
        if info:
            info_root = QTreeWidgetItem(self.overview_tree, ["INFORMATION", "", str(len(info))])
            info_root.setForeground(0, QColor("#2196F3"))
            info_root.setFont(0, QFont("", -1, QFont.Weight.Bold))

            for issue in info:
                item = QTreeWidgetItem(info_root, [
                    issue['category'],
                    issue['description'],
                    str(issue.get('count', 1))
                ])
                item.setForeground(0, QColor("#2196F3"))
                # Store issue data for drill-down
                item.setData(0, Qt.ItemDataRole.UserRole, issue)

        self.overview_tree.expandAll()

        # Statistics tab
        stats = results.get('statistics', {})
        stats_text = "PCAP File Statistics\n"
        stats_text += "=" * 60 + "\n\n"
        stats_text += f"Total Packets: {stats.get('total_packets', 'Unknown')}\n"
        stats_text += f"Duration: {stats.get('duration', 'Unknown')}\n"
        stats_text += f"Start Time: {stats.get('start_time', 'Unknown')}\n"
        stats_text += f"End Time: {stats.get('end_time', 'Unknown')}\n"
        stats_text += f"File Size: {stats.get('file_size', 'Unknown')}\n"
        self.stats_text.setText(stats_text)

        # Detailed report tab
        from core.report_generator import ReportGenerator
        generator = ReportGenerator(results)
        detailed_report = generator.generate_text_report()
        self.details_text.setText(detailed_report)

    def export_report(self, format: str):
        """Export report to file"""
        if not self.current_results:
            return

        extensions = {
            'text': 'txt',
            'html': 'html',
            'json': 'json'
        }

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            f"pcap_analysis_report.{extensions[format]}",
            f"{format.upper()} Files (*.{extensions[format]});;All Files (*)"
        )

        if file_path:
            try:
                from core.report_generator import ReportGenerator
                generator = ReportGenerator(self.current_results)

                if format == 'text':
                    report = generator.generate_text_report()
                elif format == 'html':
                    report = generator.generate_html_report()
                elif format == 'json':
                    report = generator.generate_json_report()

                with open(file_path, 'w') as f:
                    f.write(report)

                QMessageBox.information(self, "Success", f"Report saved to:\n{file_path}")
                self.statusBar().showMessage(f"Report exported to {Path(file_path).name}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n\n{str(e)}")

    def on_issue_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle clicking on an issue in the tree view"""
        # Get issue data stored in the item
        issue = item.data(0, Qt.ItemDataRole.UserRole)

        if not issue or not isinstance(issue, dict):
            # Clicked on a category header, not an issue
            return

        # Debug: Print issue details
        print(f"DEBUG: Clicked issue: {issue.get('category', 'Unknown')}")
        print(f"DEBUG: Issue details: {issue.get('details', {})}")

        # Check if there's a filter to use for drill-down
        filter_string = issue.get('details', {}).get('filter')

        print(f"DEBUG: Filter string: {filter_string}")

        if not filter_string:
            # No filter available for this issue
            self.packet_viewer.clear()
            self.tabs.setCurrentWidget(self.packet_viewer)

            # Show more detailed debug info
            details_info = issue.get('details', {})
            debug_msg = f"Issue: {issue.get('category', 'Unknown')}\n\n"
            debug_msg += f"Description: {issue.get('description', 'N/A')}\n\n"
            debug_msg += f"Details keys: {list(details_info.keys())}\n\n"
            debug_msg += f"Full details: {details_info}"

            QMessageBox.information(
                self,
                "No Packet Details",
                f"This issue does not have associated packet details available.\n\n"
                f"Debug Info:\n{debug_msg}"
            )
            return

        # Switch to packet details tab
        self.tabs.setCurrentWidget(self.packet_viewer)

        # Display packets matching the filter
        self.packet_viewer.display_packets(
            filter_string,
            issue['category'],
            issue['description']
        )

        self.statusBar().showMessage(f"Showing packets for: {issue['category']}")
