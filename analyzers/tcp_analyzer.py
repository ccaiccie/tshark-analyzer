"""TCP protocol analyzer - detects retransmissions, resets, and other TCP issues"""

from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class TCPAnalyzer(BaseAnalyzer):
    """Analyzes TCP traffic for common issues"""

    def analyze(self) -> List[Dict[str, Any]]:
        """Analyze TCP traffic"""
        issues = []

        # Check for retransmissions
        retrans_count = self.tshark.count_packets('tcp.analysis.retransmission')
        if retrans_count > 0:
            severity = 'critical' if retrans_count > 100 else 'warning'
            issues.append(self.create_issue(
                severity=severity,
                category='TCP Retransmissions',
                description=f'Detected {retrans_count} TCP retransmissions',
                count=retrans_count,
                details={
                    'filter': 'tcp.analysis.retransmission',
                    'impact': 'Indicates packet loss or network congestion'
                }
            ))

        # Check for duplicate ACKs
        dup_ack_count = self.tshark.count_packets('tcp.analysis.duplicate_ack')
        if dup_ack_count > 0:
            severity = 'warning' if dup_ack_count > 50 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='TCP Duplicate ACKs',
                description=f'Detected {dup_ack_count} duplicate ACKs',
                count=dup_ack_count,
                details={
                    'filter': 'tcp.analysis.duplicate_ack',
                    'impact': 'May indicate packet loss'
                }
            ))

        # Check for connection resets
        rst_count = self.tshark.count_packets('tcp.flags.reset==1')
        if rst_count > 0:
            severity = 'warning' if rst_count > 10 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='TCP Resets',
                description=f'Detected {rst_count} TCP connection resets',
                count=rst_count,
                details={
                    'filter': 'tcp.flags.reset==1',
                    'impact': 'Connections terminated abruptly'
                }
            ))

        # Check for zero window events
        zero_win_count = self.tshark.count_packets('tcp.analysis.zero_window')
        if zero_win_count > 0:
            issues.append(self.create_issue(
                severity='warning',
                category='TCP Zero Window',
                description=f'Detected {zero_win_count} zero window events',
                count=zero_win_count,
                details={
                    'filter': 'tcp.analysis.zero_window',
                    'impact': 'Receiver buffer full, flow control issue'
                }
            ))

        # Check for out-of-order packets
        ooo_count = self.tshark.count_packets('tcp.analysis.out_of_order')
        if ooo_count > 0:
            severity = 'warning' if ooo_count > 50 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='TCP Out-of-Order',
                description=f'Detected {ooo_count} out-of-order packets',
                count=ooo_count,
                details={
                    'filter': 'tcp.analysis.out_of_order',
                    'impact': 'Packets arriving in wrong order'
                }
            ))

        # Check for fast retransmissions
        fast_retrans_count = self.tshark.count_packets('tcp.analysis.fast_retransmission')
        if fast_retrans_count > 0:
            issues.append(self.create_issue(
                severity='info',
                category='TCP Fast Retransmission',
                description=f'Detected {fast_retrans_count} fast retransmissions',
                count=fast_retrans_count,
                details={
                    'filter': 'tcp.analysis.fast_retransmission',
                    'impact': 'TCP recovering from packet loss'
                }
            ))

        # Analyze RTT if available
        try:
            rtt_values = self.tshark.get_field_values(
                'tcp.analysis.ack_rtt',
                'tcp.analysis.ack_rtt'
            )
            if rtt_values:
                rtt_floats = [float(v) for v in rtt_values if v]
                if rtt_floats:
                    avg_rtt = sum(rtt_floats) / len(rtt_floats)
                    max_rtt = max(rtt_floats)

                    if avg_rtt > 0.2:  # 200ms
                        issues.append(self.create_issue(
                            severity='warning',
                            category='High Latency',
                            description=f'Average RTT is {avg_rtt*1000:.2f}ms (max: {max_rtt*1000:.2f}ms)',
                            count=len(rtt_floats),
                            details={
                                'filter': 'tcp.analysis.ack_rtt',
                                'avg_rtt_ms': round(avg_rtt * 1000, 2),
                                'max_rtt_ms': round(max_rtt * 1000, 2),
                                'impact': 'High network latency detected'
                            }
                        ))
        except:
            pass  # RTT analysis is optional

        return issues
