"""Report generator for PCAP analysis results"""

import json
from typing import Dict, Any
from datetime import datetime


class ReportGenerator:
    """Generates reports from analysis results"""

    def __init__(self, results: Dict[str, Any]):
        self.results = results

    def generate_text_report(self) -> str:
        """Generate text-based report"""
        lines = []
        lines.append("=" * 70)
        lines.append("PCAP ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"File: {self.results['file']}")

        stats = self.results.get('statistics', {})
        lines.append(f"Packets: {stats.get('total_packets', 'Unknown')}")
        lines.append(f"Duration: {stats.get('duration', 'Unknown')}")
        lines.append(f"Start Time: {stats.get('start_time', 'Unknown')}")
        lines.append("")

        # Critical issues
        critical = self.results.get('critical', [])
        if critical:
            lines.append("CRITICAL ISSUES (%d)" % len(critical))
            lines.append("-" * 70)
            for issue in critical:
                lines.append(f"  [{issue['category']}] {issue['description']}")
                if issue.get('details', {}).get('impact'):
                    lines.append(f"    Impact: {issue['details']['impact']}")
            lines.append("")

        # Warnings
        warnings = self.results.get('warnings', [])
        if warnings:
            lines.append("WARNINGS (%d)" % len(warnings))
            lines.append("-" * 70)
            for issue in warnings:
                lines.append(f"  [{issue['category']}] {issue['description']}")
                if issue.get('details', {}).get('impact'):
                    lines.append(f"    Impact: {issue['details']['impact']}")
            lines.append("")

        # Informational
        info = self.results.get('info', [])
        if info:
            lines.append("INFORMATIONAL (%d)" % len(info))
            lines.append("-" * 70)
            for issue in info:
                lines.append(f"  [{issue['category']}] {issue['description']}")
            lines.append("")

        lines.append("=" * 70)
        lines.append(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)

        return "\n".join(lines)

    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'results': self.results
        }
        return json.dumps(report, indent=2)

    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .stats {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .issue {{
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .critical {{
            background-color: #ffebee;
            border-left-color: #f44336;
        }}
        .warning {{
            background-color: #fff3e0;
            border-left-color: #ff9800;
        }}
        .info {{
            background-color: #e3f2fd;
            border-left-color: #2196F3;
        }}
        .issue-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .issue-description {{
            color: #666;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .badge-critical {{ background-color: #f44336; }}
        .badge-warning {{ background-color: #ff9800; }}
        .badge-info {{ background-color: #2196F3; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCAP Analysis Report</h1>
        <div class="stats">
            <p><strong>File:</strong> {self.results['file']}</p>
            <p><strong>Total Packets:</strong> {self.results.get('statistics', {}).get('total_packets', 'Unknown')}</p>
            <p><strong>Duration:</strong> {self.results.get('statistics', {}).get('duration', 'Unknown')}</p>
            <p><strong>Start Time:</strong> {self.results.get('statistics', {}).get('start_time', 'Unknown')}</p>
        </div>
"""

        # Critical issues
        critical = self.results.get('critical', [])
        if critical:
            html += f"""
        <h2><span class="badge badge-critical">CRITICAL</span> Critical Issues ({len(critical)})</h2>
"""
            for issue in critical:
                html += f"""
        <div class="issue critical">
            <div class="issue-title">{issue['category']}</div>
            <div class="issue-description">{issue['description']}</div>
"""
                if issue.get('details', {}).get('impact'):
                    html += f"            <div style='margin-top: 5px; font-size: 14px;'>Impact: {issue['details']['impact']}</div>\n"
                html += "        </div>\n"

        # Warnings
        warnings = self.results.get('warnings', [])
        if warnings:
            html += f"""
        <h2><span class="badge badge-warning">WARNING</span> Warnings ({len(warnings)})</h2>
"""
            for issue in warnings:
                html += f"""
        <div class="issue warning">
            <div class="issue-title">{issue['category']}</div>
            <div class="issue-description">{issue['description']}</div>
"""
                if issue.get('details', {}).get('impact'):
                    html += f"            <div style='margin-top: 5px; font-size: 14px;'>Impact: {issue['details']['impact']}</div>\n"
                html += "        </div>\n"

        # Info
        info = self.results.get('info', [])
        if info:
            html += f"""
        <h2><span class="badge badge-info">INFO</span> Information ({len(info)})</h2>
"""
            for issue in info:
                html += f"""
        <div class="issue info">
            <div class="issue-title">{issue['category']}</div>
            <div class="issue-description">{issue['description']}</div>
        </div>
"""

        html += f"""
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #999;">
            Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""
        return html
