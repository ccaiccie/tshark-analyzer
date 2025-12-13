#!/usr/bin/env python3
"""
PCAP Analyzer - Automated packet capture analysis tool
Uses tshark as backend to detect network issues and anomalies
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Any
from analyzers.tcp_analyzer import TCPAnalyzer
from analyzers.dns_analyzer import DNSAnalyzer
from analyzers.http_analyzer import HTTPAnalyzer
from analyzers.network_analyzer import NetworkAnalyzer
from core.tshark_wrapper import TsharkWrapper
from core.report_generator import ReportGenerator


class PcapAnalyzer:
    """Main PCAP analyzer class"""

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.tshark = TsharkWrapper(pcap_file)
        self.results: Dict[str, Any] = {
            'file': pcap_file,
            'critical': [],
            'warnings': [],
            'info': [],
            'statistics': {}
        }

    def analyze(self) -> Dict[str, Any]:
        """Run all analyzers on the PCAP file"""
        print(f"Analyzing {self.pcap_file}...")

        # Get basic statistics
        print("  [*] Gathering basic statistics...")
        self.results['statistics'] = self.tshark.get_basic_stats()

        # Run analyzers
        analyzers = [
            TCPAnalyzer(self.tshark),
            DNSAnalyzer(self.tshark),
            HTTPAnalyzer(self.tshark),
            NetworkAnalyzer(self.tshark)
        ]

        for analyzer in analyzers:
            print(f"  [*] Running {analyzer.name}...")
            issues = analyzer.analyze()
            self._categorize_issues(issues)

        return self.results

    def _categorize_issues(self, issues: List[Dict[str, Any]]):
        """Categorize issues by severity"""
        for issue in issues:
            severity = issue.get('severity', 'info')
            if severity == 'critical':
                self.results['critical'].append(issue)
            elif severity == 'warning':
                self.results['warnings'].append(issue)
            else:
                self.results['info'].append(issue)

    def generate_report(self, format: str = 'text') -> str:
        """Generate analysis report"""
        generator = ReportGenerator(self.results)
        if format == 'text':
            return generator.generate_text_report()
        elif format == 'json':
            return generator.generate_json_report()
        elif format == 'html':
            return generator.generate_html_report()
        else:
            raise ValueError(f"Unknown format: {format}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze PCAP files for network issues using tshark'
    )
    parser.add_argument('pcap_file', help='Path to PCAP file to analyze')
    parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'html'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file (default: stdout)'
    )

    args = parser.parse_args()

    # Check if file exists
    if not Path(args.pcap_file).exists():
        print(f"Error: File not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    analyzer = PcapAnalyzer(args.pcap_file)
    analyzer.analyze()

    # Generate report
    report = analyzer.generate_report(format=args.format)

    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == '__main__':
    main()
