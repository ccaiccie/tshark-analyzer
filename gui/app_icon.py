"""Application icon generator for PCAP Analyzer"""

from PyQt6.QtGui import QPixmap, QPainter, QColor, QPen, QBrush, QIcon
from PyQt6.QtCore import Qt, QRect
import os


def create_app_icon(size=64):
    """Create application icon programmatically"""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Background circle (gradient blue)
    gradient_rect = QRect(0, 0, size, size)
    painter.setBrush(QColor(33, 150, 243))  # Material blue
    painter.setPen(QPen(QColor(25, 118, 210), 2))  # Darker blue border
    painter.drawEllipse(2, 2, size-4, size-4)

    # Draw network nodes (white circles)
    node_color = QColor(255, 255, 255, 230)
    painter.setBrush(QBrush(node_color))
    painter.setPen(QPen(node_color, 1))

    center = size // 2
    radius = size // 5

    # Center node
    painter.drawEllipse(center - 4, center - 4, 8, 8)

    # Surrounding nodes (like a network topology)
    import math
    for i in range(6):
        angle = (i * 60) * math.pi / 180
        x = center + int(radius * math.cos(angle))
        y = center + int(radius * math.sin(angle))

        # Draw connection line
        painter.setPen(QPen(QColor(255, 255, 255, 180), 2))
        painter.drawLine(center, center, x, y)

        # Draw node
        painter.setBrush(QBrush(node_color))
        painter.setPen(QPen(node_color, 1))
        painter.drawEllipse(x - 3, y - 3, 6, 6)

    # Draw "packet" indicator (small colored square in corner)
    packet_color = QColor(76, 175, 80)  # Green
    painter.setBrush(QBrush(packet_color))
    painter.setPen(QPen(packet_color, 1))
    painter.drawRect(size - 16, size - 16, 10, 10)

    painter.end()

    return pixmap


def get_app_icon():
    """Get the application icon with multiple sizes for better display"""
    icon = QIcon()

    # Add multiple sizes for different contexts (taskbar, window, etc.)
    for size in [16, 24, 32, 48, 64, 128, 256]:
        pixmap = create_app_icon(size)
        icon.addPixmap(pixmap)

    return icon


def save_icon_file():
    """Save icon to file for desktop integration"""
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'pcap_analyzer_icon.png')
    pixmap = create_app_icon(256)
    pixmap.save(icon_path, 'PNG')
    return icon_path
